"""Administrator oversight: activity, permission changes and things worth noticing.
Administrators see metadata and the audit trail, never document contents."""
from __future__ import annotations

import csv
import io
import json

from . import authz, clock
from .context import Ctx
from .db import like_pattern
from .errors import Forbidden, Invalid
from .validation import ValidationError, parse_date

PERMISSION_ACTIONS = ("grant", "grant_changed", "revoke", "access_suggested", "suggestion_dismissed",
                      "user_created", "user_disabled", "user_enabled", "user_role_changed", "user_sessions_ended")
ALLOWED_OUTCOMES = ("success", "denied", "error")


def _require(ctx: Ctx, capability: str, action: str) -> None:
    if not authz.has_capability(ctx.user, capability):
        ctx.log(action, outcome="denied", details={"reason": f"missing capability {capability}"})
        raise Forbidden()


def query_audit(ctx: Ctx, actor: str = "", action: str = "", outcome: str = "", document_id: str = "",
                date_from: str = "", date_to: str = "", limit: int = 300, before_seq: int | None = None,
                log: bool = True) -> list[dict]:
    _require(ctx, "read_audit", "read_audit")
    sql = "SELECT * FROM audit_events WHERE 1 = 1"
    params: list = []
    if actor.strip():
        sql += " AND LOWER(actor_username) LIKE ? ESCAPE '!'"
        params.append(like_pattern(actor.strip()[:64]))
    if action.strip():
        if action == "permissions":
            sql += " AND action IN (" + ",".join("?" * len(PERMISSION_ACTIONS)) + ")"
            params += list(PERMISSION_ACTIONS)
        else:
            sql += " AND action = ?"
            params.append(action.strip()[:40])
    if outcome in ALLOWED_OUTCOMES:
        sql += " AND outcome = ?"
        params.append(outcome)
    if document_id.strip():
        sql += " AND document_id = ?"
        params.append(document_id.strip()[:80])
    try:
        start, end = parse_date(date_from, "From date"), parse_date(date_to, "To date")
    except ValidationError as exc:
        raise Invalid(str(exc))
    if start:
        sql += " AND event_time >= ?"
        params.append(start.isoformat() + "T00:00:00.000000Z")
    if end:
        sql += " AND event_time <= ?"
        params.append(end.isoformat() + "T23:59:59.999999Z")
    if before_seq:
        sql += " AND seq < ?"
        params.append(int(before_seq))
    sql += " ORDER BY seq DESC LIMIT ?"
    params.append(max(1, min(int(limit), 5000)))
    rows = ctx.conn.all(sql, params)
    if log:
        ctx.log("read_audit", details={"filters": {"actor": actor, "action": action, "outcome": outcome,
                                                   "document_id": document_id, "from": date_from, "to": date_to},
                                       "rows": len(rows)})
    return rows


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text  # spreadsheet formula injection


def export_csv(ctx: Ctx, **filters) -> str:
    rows = query_audit(ctx, limit=5000, log=False, **filters)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    columns = ["seq", "event_time", "actor_username", "actor_role", "ip", "action", "outcome", "document_id",
               "target", "details", "prev_hash", "event_hash", "key_id"]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_safe(row[c]) for c in columns])
    ctx.log("export_audit", details={"rows": len(rows), "filters": filters})
    return buffer.getvalue()


def verify(ctx: Ctx) -> dict:
    _require(ctx, "read_audit", "verify_audit")
    result = ctx.audit.verify_chain(ctx.conn)
    ctx.log("verify_audit", outcome="success" if result["ok"] else "error", details=result)
    return result


def dashboard(ctx: Ctx) -> dict:
    _require(ctx, "read_audit", "view_dashboard")
    day = clock.ago_iso(hours=24)
    hour = clock.ago_iso(hours=1)
    conn = ctx.conn
    stats = {
        "users": conn.scalar("SELECT COUNT(*) AS n FROM users WHERE is_active = 1"),
        "documents": conn.scalar("SELECT COUNT(*) AS n FROM documents WHERE deleted_at IS NULL"),
        "grants": conn.scalar("SELECT COUNT(*) AS n FROM grants g JOIN documents d ON d.id = g.document_id"
                              " WHERE d.deleted_at IS NULL"),
        "events_24h": conn.scalar("SELECT COUNT(*) AS n FROM audit_events WHERE event_time > ?", (day,)),
        "denied_24h": conn.scalar("SELECT COUNT(*) AS n FROM audit_events WHERE outcome = 'denied' AND event_time > ?", (day,)),
        "downloads_24h": conn.scalar("SELECT COUNT(*) AS n FROM audit_events WHERE action = 'download' AND outcome = 'success'"
                                     " AND event_time > ?", (day,)),
        "active_sessions": conn.scalar("SELECT COUNT(*) AS n FROM sessions"),
    }
    alerts = []
    for row in conn.all("SELECT actor_username, COUNT(*) AS n FROM audit_events WHERE action = 'access_denied'"
                        " AND event_time > ? GROUP BY actor_username HAVING COUNT(*) >= 3 ORDER BY n DESC", (day,)):
        alerts.append({"level": "high", "title": f"{row['actor_username']} was refused {row['n']} document requests in 24h",
                       "hint": "Possible probing of document ids (IDOR attempts).",
                       "filter": {"actor": row["actor_username"], "outcome": "denied"}})
    for row in conn.all("SELECT actor_username, COUNT(DISTINCT document_id) AS n FROM audit_events WHERE action = 'download'"
                        " AND outcome = 'success' AND event_time > ? GROUP BY actor_username HAVING COUNT(DISTINCT document_id) >= 5"
                        " ORDER BY n DESC", (hour,)):
        alerts.append({"level": "high", "title": f"{row['actor_username']} downloaded {row['n']} different documents in 1h",
                       "hint": "Bulk download: check whether this is expected.",
                       "filter": {"actor": row["actor_username"], "action": "download"}})
    for row in conn.all("SELECT actor_username, ip, COUNT(*) AS n FROM audit_events WHERE action = 'login' AND outcome = 'denied'"
                        " AND event_time > ? GROUP BY actor_username, ip HAVING COUNT(*) >= 3 ORDER BY n DESC", (day,)):
        alerts.append({"level": "medium", "title": f"{row['n']} failed sign-ins for '{row['actor_username']}' from {row['ip'] or 'unknown'}",
                       "hint": "Password guessing; throttling applies after repeated failures.",
                       "filter": {"actor": row["actor_username"], "action": "login"}})
    for row in conn.all("SELECT actor_username, COUNT(*) AS n FROM audit_events WHERE action IN ('csrf_rejected', 'origin_rejected')"
                        " AND event_time > ? GROUP BY actor_username ORDER BY n DESC", (day,)):
        alerts.append({"level": "medium", "title": f"{row['n']} cross-site request(s) blocked for {row['actor_username']}",
                       "hint": "A page on another site tried to act as this user.",
                       "filter": {"actor": row["actor_username"], "action": "csrf_rejected"}})
    for row in conn.all("SELECT actor_username, document_id, target, details, event_time FROM audit_events"
                        " WHERE action IN ('grant', 'grant_changed') AND event_time > ? ORDER BY seq DESC LIMIT 20", (day,)):
        details = json.loads(row["details"] or "{}")
        if details.get("permission") == "edit":
            alerts.append({"level": "low", "title": f"{row['actor_username']} gave EDIT access to {row['target']}",
                           "hint": "Edit lets the grantee replace the file with a new version.",
                           "filter": {"document_id": row["document_id"]}})
    if conn.scalar("SELECT COUNT(*) AS n FROM audit_events WHERE action = 'integrity_failure' AND event_time > ?", (day,)):
        alerts.insert(0, {"level": "high", "title": "Encrypted file failed integrity check",
                          "hint": "Stored ciphertext was altered or the key changed.",
                          "filter": {"action": "integrity_failure"}})
    recent_permissions = query_audit(ctx, action="permissions", limit=15, log=False)
    ctx.log("view_dashboard")
    return {"stats": stats, "alerts": alerts, "permission_changes": recent_permissions}


def inventory(ctx: Ctx) -> list[dict]:
    """Metadata-only document inventory for oversight. No content, no download links."""
    _require(ctx, "view_inventory", "view_inventory")
    rows = ctx.conn.all(
        "SELECT d.id, d.title, d.category, d.created_at, d.deleted_at, d.purged_at, d.current_version,"
        " u.username AS owner,"
        " (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id) AS grants,"
        " (SELECT MAX(event_time) FROM audit_events a WHERE a.document_id = d.id AND a.action = 'download'"
        "   AND a.outcome = 'success') AS last_download,"
        " (SELECT COUNT(*) FROM audit_events a WHERE a.document_id = d.id AND a.outcome = 'denied') AS denied"
        " FROM documents d JOIN users u ON u.id = d.owner_id ORDER BY d.created_at DESC LIMIT 500")
    ctx.log("view_inventory", details={"rows": len(rows)})
    return rows
