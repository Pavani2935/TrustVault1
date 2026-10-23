"""Authentication, server-side sessions and login throttling.

Sessions are rows in the database. The browser holds only a random 256-bit token; the
database holds its SHA-256. Every request re-reads the session AND the user row, so:
  * logging out, disabling a user, changing a password, or an admin's "sign out
    everywhere" ends existing sessions on the very next request;
  * a role change applies on the very next request;
  * nothing the server issued earlier (cookie, CSRF token) outlives that moment.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from werkzeug.security import check_password_hash, generate_password_hash

from . import clock
from .context import Ctx
from .errors import TooMany

# Used to equalise timing when the username does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password-" + secrets.token_hex(8),
                                     method=os.environ.get("TRUSTVAULT_PASSWORD_HASH", "scrypt"))


# scrypt in production. The test suite sets a cheaper method purely for speed.
HASH_METHOD = os.environ.get("TRUSTVAULT_PASSWORD_HASH", "scrypt")


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def throttle_state(ctx: Ctx, username: str) -> str | None:
    """Return a reason string if this login attempt must be refused before checking the
    password. Keyed on (username, ip) so one attacker cannot lock a user out from
    everywhere, plus a per-IP ceiling against password spraying."""
    s = ctx.settings
    since = clock.ago_iso(minutes=s.login_window_minutes)
    ip = ctx.ip or "unknown"
    last_ok = ctx.conn.scalar(
        "SELECT MAX(attempted_at) AS t FROM login_attempts WHERE username = ? AND ip = ? AND success = 1",
        (username, ip))
    window_start = max(since, last_ok) if last_ok else since
    pair_failures = ctx.conn.scalar(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE username = ? AND ip = ? AND success = 0 AND attempted_at > ?",
        (username, ip, window_start)) or 0
    if int(pair_failures) >= s.login_max_failures:
        return "too many failed attempts for this account from this address"
    ip_failures = ctx.conn.scalar(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND success = 0 AND attempted_at > ?",
        (ip, since)) or 0
    if int(ip_failures) >= s.login_ip_max_failures:
        return "too many failed attempts from this address"
    return None


def login(ctx: Ctx, username: str, password: str, user_agent: str = "") -> tuple[dict, str, str]:
    """Verify credentials. Returns (user, session_token, csrf_token). Raises TooMany or ValueError."""
    username = (username or "").strip().lower()[:64]
    password = password or ""
    blocked = throttle_state(ctx, username)
    if blocked:
        ctx.log("login", outcome="denied", actor_name_hint=username or "anonymous",
                details={"reason": "throttled: " + blocked})
        raise TooMany("Too many failed sign-in attempts. Wait a few minutes and try again.")

    user = ctx.conn.one("SELECT * FROM users WHERE username = ?", (username,))
    ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password[:256])
    reason = None
    if not user:
        reason = "unknown username"
    elif not ok:
        reason = "wrong password"
    elif not user["is_active"]:
        reason = "account disabled"

    with ctx.conn.transaction():
        ctx.conn.execute("INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (?,?,?,?)",
                         (username, ctx.ip or "unknown", clock.now_iso(), 0 if reason else 1))
        if reason:
            ctx.audit.record(ctx.conn, action="login", actor=None, outcome="denied", ip=ctx.ip,
                             actor_name_hint=username or "anonymous", details={"reason": reason})
        else:
            token, csrf = create_session(ctx, user, user_agent)
            ctx.audit.record(ctx.conn, action="login", actor=user, ip=ctx.ip)
    if reason:
        raise ValueError("Sign-in failed. Check your username and password.")
    return user, token, csrf


def create_session(ctx: Ctx, user: dict, user_agent: str = "") -> tuple[str, str]:
    """Issue a brand-new session (fresh token and CSRF token; never reuse a presented one)."""
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = clock.now_iso()
    ctx.conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at,"
        " absolute_expires_at, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
        (_token_hash(token), user["id"], csrf, now, now,
         clock.ahead_iso(hours=ctx.settings.session_absolute_hours), ctx.ip, (user_agent or "")[:200]))
    return token, csrf


def load_session(ctx: Ctx, token: str | None) -> tuple[dict, dict] | None:
    """Return (user, session) for a live session, or None. Expired/invalid sessions are deleted."""
    if not token or len(token) > 100:
        return None
    token_hash = _token_hash(token)
    row = ctx.conn.one("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
    if not row:
        return None
    user = ctx.conn.one("SELECT id, username, display_name, role, is_active, is_demo, password_changed_at"
                        " FROM users WHERE id = ?", (row["user_id"],))
    now = clock.now_iso()
    idle_cutoff = clock.ago_iso(minutes=ctx.settings.session_idle_minutes)
    end_reason = None
    if not user or not user["is_active"]:
        end_reason = "account disabled"
    elif row["absolute_expires_at"] <= now:
        end_reason = "absolute lifetime reached"
    elif row["last_seen_at"] < idle_cutoff:
        end_reason = "idle timeout"
    elif row["created_at"] < user["password_changed_at"]:
        end_reason = "password changed"
    if end_reason:
        ctx.conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    if row["last_seen_at"] < clock.ago_iso(seconds=30):  # avoid a write on every request
        ctx.conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (now, token_hash))
    return user, row


def logout(ctx: Ctx, token: str | None) -> None:
    if token:
        ctx.conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def csrf_valid(session: dict | None, submitted: str | None) -> bool:
    return bool(session and submitted and hmac.compare_digest(session["csrf_token"], submitted))


def end_all_sessions(conn, user_id: int, except_token: str | None = None) -> int:
    if except_token:
        keep = _token_hash(except_token)
        count = conn.scalar("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND token_hash <> ?", (user_id, keep))
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (user_id, keep))
    else:
        count = conn.scalar("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return int(count or 0)


def set_flash(conn, session: dict | None, kind: str, message: str) -> None:
    if session:
        import json
        existing = json.loads(session.get("flash") or "[]")
        existing.append([kind, message[:300]])
        payload = json.dumps(existing[-5:])
        session["flash"] = payload
        conn.execute("UPDATE sessions SET flash = ? WHERE token_hash = ?", (payload, session["token_hash"]))


def pop_flashes(conn, session: dict | None) -> list:
    if not session or not session.get("flash"):
        return []
    import json
    conn.execute("UPDATE sessions SET flash = NULL WHERE token_hash = ?", (session["token_hash"],))
    messages, session["flash"] = json.loads(session["flash"]), None
    return messages


def prune(conn) -> None:
    """Housekeeping: drop expired sessions and old login attempts."""
    conn.execute("DELETE FROM sessions WHERE absolute_expires_at <= ?", (clock.now_iso(),))
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (clock.ago_iso(days=2),))
