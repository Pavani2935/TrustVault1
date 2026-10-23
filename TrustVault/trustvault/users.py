"""Account administration and self-service.

Deliberately absent: administrator password reset and impersonation. Either would
let an administrator become a document owner and read their files, which would make
the "admins do not read documents" rule meaningless. Account recovery belongs to an
identity provider with MFA (see WRITEUP.md, "not built").
"""
from __future__ import annotations

from werkzeug.security import check_password_hash

from . import authz, clock
from .auth import create_session, end_all_sessions, hash_password
from .context import Ctx
from .errors import Forbidden, Invalid, NotFound
from .validation import ValidationError, check_password, clean_text, clean_username

ROLES = ("admin", "owner", "viewer")


def _require_admin(ctx: Ctx, action: str) -> None:
    if not authz.has_capability(ctx.user, "manage_users"):
        ctx.log(action, outcome="denied", details={"reason": "not an administrator"})
        raise Forbidden()


def list_users(ctx: Ctx) -> list[dict]:
    _require_admin(ctx, "list_users")
    return ctx.conn.all(
        "SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.is_demo, u.created_at,"
        " (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions,"
        " (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id AND d.deleted_at IS NULL) AS documents"
        " FROM users u ORDER BY u.username")


def create_user(ctx: Ctx, username: str, display_name: str, password: str, role: str) -> int:
    _require_admin(ctx, "create_user")
    try:
        username = clean_username(username)
        display_name = clean_text(display_name or username, "Display name", 80)
        check_password(password, username)
    except ValidationError as exc:
        raise Invalid(str(exc))
    if role not in ROLES:
        raise Invalid("Role must be admin, owner or viewer.")
    with ctx.conn.transaction():
        if ctx.conn.one("SELECT id FROM users WHERE username = ?", (username,)):
            raise Invalid("That username is taken.")
        now = clock.now_iso()
        user_id = ctx.conn.insert_returning_id(
            "INSERT INTO users (username, display_name, password_hash, role, is_active, is_demo, created_at,"
            " updated_at, password_changed_at) VALUES (?,?,?,?,1,0,?,?,?)",
            (username, display_name, hash_password(password), role, now, now, now))
        ctx.log("user_created", target=username, details={"role": role, "user_id": user_id})
    return user_id


def _target(ctx: Ctx, user_id: int) -> dict:
    target = ctx.conn.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not target:
        raise NotFound("No such user.")
    return target


def _guard_demo(ctx: Ctx, target: dict) -> None:
    if ctx.settings.demo_mode and target["is_demo"]:
        raise Invalid("Demo accounts are protected on the public demo so every reviewer can sign in. "
                      "Create a new account to try this.")


def set_active(ctx: Ctx, user_id: int, active: bool) -> None:
    _require_admin(ctx, "user_status")
    with ctx.conn.transaction():
        target = _target(ctx, user_id)
        if target["id"] == ctx.user["id"]:
            raise Invalid("You cannot disable your own account.")
        _guard_demo(ctx, target)
        ctx.conn.execute("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
                         (1 if active else 0, clock.now_iso(), user_id))
        ended = 0 if active else end_all_sessions(ctx.conn, user_id)
        ctx.log("user_enabled" if active else "user_disabled", target=target["username"],
                details={"sessions_ended": ended})


def set_role(ctx: Ctx, user_id: int, role: str) -> None:
    _require_admin(ctx, "user_role")
    if role not in ROLES:
        raise Invalid("Role must be admin, owner or viewer.")
    with ctx.conn.transaction():
        target = _target(ctx, user_id)
        if target["id"] == ctx.user["id"]:
            raise Invalid("You cannot change your own role.")
        _guard_demo(ctx, target)
        ctx.conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", (role, clock.now_iso(), user_id))
        ctx.log("user_role_changed", target=target["username"], details={"from": target["role"], "to": role})


def end_sessions(ctx: Ctx, user_id: int) -> int:
    _require_admin(ctx, "user_sessions_ended")
    with ctx.conn.transaction():
        target = _target(ctx, user_id)
        ended = end_all_sessions(ctx.conn, user_id)
        ctx.log("user_sessions_ended", target=target["username"], details={"sessions_ended": ended})
    return ended


def change_own_password(ctx: Ctx, current: str, new: str, user_agent: str = "") -> tuple[str, str]:
    """Change the caller's password, end every existing session (including this one) and
    issue a fresh session for this browser. Returns (token, csrf)."""
    with ctx.conn.transaction():
        me = ctx.conn.one("SELECT * FROM users WHERE id = ?", (ctx.user["id"],))
        _guard_demo(ctx, me)
        if not check_password_hash(me["password_hash"], current or ""):
            ctx.log("password_change", outcome="denied", details={"reason": "current password wrong"})
            failed = True
        else:
            failed = False
    if failed:
        raise Invalid("Current password is incorrect.")
    try:
        check_password(new, me["username"])
    except ValidationError as exc:
        raise Invalid(str(exc))
    with ctx.conn.transaction():
        now = clock.now_iso()
        ctx.conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?",
                         (hash_password(new), now, now, me["id"]))
        ended = end_all_sessions(ctx.conn, me["id"])
        token, csrf = create_session(ctx, me, user_agent)
        ctx.log("password_change", details={"sessions_ended": ended})
    return token, csrf


def my_sessions(ctx: Ctx) -> list[dict]:
    return ctx.conn.all("SELECT token_hash, created_at, last_seen_at, ip, user_agent FROM sessions"
                        " WHERE user_id = ? ORDER BY last_seen_at DESC", (ctx.user["id"],))
