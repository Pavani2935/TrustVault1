"""Document service. All document operations for the web UI and the JSON API go
through these functions; none of them touches a document without `_authorize`."""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from functools import wraps

from . import authz, clock
from .context import Ctx
from .crypto import IntegrityError
from .db import like_pattern
from .errors import Forbidden, Invalid, NotFound, TooMany
from .validation import ValidationError, clean_text, grant_expiry, is_doc_id, parse_date, validate_upload


class _Denied(Exception):
    def __init__(self, doc_id: str, action: str, reason: str):
        super().__init__(reason)
        self.doc_id, self.action, self.reason = doc_id, action, reason


def _authorize(ctx: Ctx, doc_id: str, action: str) -> tuple[dict, str]:
    """The single authorisation gate for document access. Must run inside the same
    transaction as the work it protects so the decision and the change see the same state."""
    doc = ctx.conn.one("SELECT * FROM documents WHERE id = ?", (doc_id,)) if is_doc_id(doc_id) else None
    allowed, permission = authz.is_allowed(ctx.conn, ctx.user, doc, action)
    if not allowed:
        if doc is None:
            reason = "unknown document id"
        elif doc.get("deleted_at"):
            reason = "document is deleted" if permission is None else "action not valid for a deleted document"
        elif permission is None:
            reason = "no grant"
        else:
            reason = f"holds '{permission}', action needs '{authz.LIVE_ACTIONS.get(action)}'"
        raise _Denied(doc_id, action, reason)
    return doc, permission


def document_operation(fn):
    """Turn an authorisation refusal into: (1) a durable 'denied' audit event written in its
    own transaction, after the protected work was rolled back, and (2) a 404 that looks
    exactly like a document that does not exist."""
    @wraps(fn)
    def wrapper(ctx: Ctx, doc_id: str, *args, **kwargs):
        try:
            return fn(ctx, doc_id, *args, **kwargs)
        except _Denied as denied:
            ctx.log("access_denied", outcome="denied", document_id=(denied.doc_id or "")[:80] or None,
                    details={"attempted": denied.action, "reason": denied.reason})
            raise NotFound() from None
    return wrapper


def _invalid(exc: ValidationError) -> Invalid:
    return Invalid(str(exc))


# --------------------------------------------------------------------------- reads --
LIST_SQL = """
SELECT d.id, d.title, d.category, d.owner_id, d.current_version, d.created_at, d.updated_at,
       d.deleted_at, d.purged_at,
       o.username AS owner_username, o.display_name AS owner_name,
       v.original_name, v.size_bytes, v.content_type,
       g.permission AS grant_permission, g.expires_at AS grant_expires_at
FROM documents d
JOIN users o ON o.id = d.owner_id
JOIN document_versions v ON v.document_id = d.id AND v.version_no = d.current_version
LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = ?
WHERE d.deleted_at IS NULL AND d.purged_at IS NULL
  AND (d.owner_id = ? OR (g.id IS NOT NULL AND (g.expires_at IS NULL OR g.expires_at > ?)))
"""


def search(ctx: Ctx, q: str = "", owner: str = "", category: str = "", date_from: str = "",
           date_to: str = "", scope: str = "all", limit: int = 200) -> list[dict]:
    """Documents the caller may view, filtered. Scoped in SQL *and* re-checked per row
    against the policy, so a mistake in this query cannot widen access."""
    user = ctx.user
    if not user:
        return []
    params: list = [user["id"], user["id"], clock.now_iso()]
    sql = LIST_SQL
    try:
        if q.strip():
            pattern = like_pattern(q.strip()[:100])
            sql += " AND (LOWER(d.title) LIKE ? ESCAPE '!' OR LOWER(v.original_name) LIKE ? ESCAPE '!')"
            params += [pattern, pattern]
        if owner.strip():
            pattern = like_pattern(owner.strip()[:64])
            sql += " AND (LOWER(o.username) LIKE ? ESCAPE '!' OR LOWER(o.display_name) LIKE ? ESCAPE '!')"
            params += [pattern, pattern]
        if category.strip():
            sql += " AND d.category = ?"
            params.append(category.strip()[:60])
        start = parse_date(date_from, "From date")
        end = parse_date(date_to, "To date")
    except ValidationError as exc:
        raise _invalid(exc)
    if start:
        sql += " AND d.created_at >= ?"
        params.append(start.isoformat() + "T00:00:00.000000Z")
    if end:
        sql += " AND d.created_at < ?"
        params.append((end + timedelta(days=1)).isoformat() + "T00:00:00.000000Z")
    if scope == "mine":
        sql += " AND d.owner_id = ?"
        params.append(user["id"])
    elif scope == "shared":
        sql += " AND d.owner_id <> ?"
        params.append(user["id"])
    sql += " ORDER BY d.created_at DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))

    results = []
    for row in ctx.conn.all(sql, params):
        allowed, permission = authz.is_allowed(ctx.conn, user, row, "view")
        if allowed:  # defence in depth: the policy, not the query, has the last word
            row["my_permission"] = permission
            results.append(row)
    return results


def categories(ctx: Ctx) -> list[str]:
    """Categories of documents the caller can see. Never global: category names leak."""
    return sorted({row["category"] for row in search(ctx, limit=500)}, key=str.lower)


@document_operation
def get_document(ctx: Ctx, doc_id: str, audit_view: bool = True) -> dict:
    with ctx.conn.transaction():
        doc, permission = _authorize(ctx, doc_id, "view")
        if audit_view:
            ctx.log("view", document_id=doc_id)
    return _describe(ctx, doc, permission)


def _describe(ctx: Ctx, doc: dict, permission: str) -> dict:
    owner = ctx.conn.one("SELECT username, display_name FROM users WHERE id = ?", (doc["owner_id"],))
    versions = ctx.conn.all(
        "SELECT v.version_no, v.original_name, v.content_type, v.size_bytes, v.sha256, v.created_at,"
        " u.username AS uploaded_by FROM document_versions v JOIN users u ON u.id = v.uploaded_by"
        " WHERE v.document_id = ? ORDER BY v.version_no DESC", (doc["id"],))
    current = next((v for v in versions if v["version_no"] == doc["current_version"]), None)
    return {
        "id": doc["id"], "title": doc["title"], "category": doc["category"],
        "owner": owner["username"], "owner_name": owner["display_name"],
        "created_at": doc["created_at"], "updated_at": doc["updated_at"],
        "deleted_at": doc.get("deleted_at"), "current_version": doc["current_version"],
        "my_permission": permission, "current": current, "versions": versions,
        "can_edit": authz.LEVEL[permission] >= authz.LEVEL["edit"],
        "can_manage": permission == "owner",
    }


@document_operation
def get_content(ctx: Ctx, doc_id: str, version_no: int | None = None) -> tuple[dict, bytes]:
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "download")
        number = doc["current_version"] if version_no is None else version_no
        version = ctx.conn.one("SELECT * FROM document_versions WHERE document_id = ? AND version_no = ?",
                               (doc_id, number))
        if version is None or version["ciphertext"] is None:
            raise NotFound()
        ctx.log("download", document_id=doc_id,
                details={"version": number, "sha256": version["sha256"], "bytes": version["size_bytes"]})
    try:
        data = ctx.vault.decrypt(version["wrapped_key"], version["ciphertext"], doc_id, version["id"],
                                 version["sha256"], version["key_id"])
    except IntegrityError as exc:
        ctx.log("integrity_failure", outcome="error", document_id=doc_id,
                details={"version": number, "reason": str(exc)})
        raise
    return version, data


@document_operation
def access_log(ctx: Ctx, doc_id: str, limit: int = 200) -> list[dict]:
    """Who touched this document, including refused attempts. Owner only."""
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "view_access_log")
        ctx.log("view_access_log", document_id=doc_id)
    return ctx.conn.all(
        "SELECT seq, event_time, actor_username, actor_role, action, outcome, target, details, ip"
        " FROM audit_events WHERE document_id = ? ORDER BY seq DESC LIMIT ?", (doc_id, limit))


@document_operation
def document_summary(ctx: Ctx, doc_id: str) -> dict:
    """Title and state for the owner's access-history page (works for trashed documents too)."""
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "view_access_log")
    return {"id": doc["id"], "title": doc["title"], "deleted_at": doc.get("deleted_at")}


# -------------------------------------------------------------------------- writes --
def _check_quota(ctx: Ctx, incoming: int) -> None:
    used = ctx.conn.scalar("SELECT COALESCE(SUM(size_bytes), 0) AS used FROM document_versions"
                           " WHERE uploaded_by = ? AND ciphertext IS NOT NULL", (ctx.user["id"],)) or 0
    if int(used) + incoming > ctx.settings.user_quota_mb * 1024 * 1024:
        raise Invalid(f"Storage quota of {ctx.settings.user_quota_mb} MB reached. Delete or purge documents first.")
    recent = ctx.conn.scalar("SELECT COUNT(*) AS n FROM document_versions WHERE uploaded_by = ? AND created_at > ?",
                             (ctx.user["id"], clock.ago_iso(hours=1))) or 0
    if int(recent) >= ctx.settings.uploads_per_hour:
        raise TooMany("Upload rate limit reached. Try again later.")


def _store_version(ctx: Ctx, doc_id: str, version_no: int, filename: str, content_type: str, data: bytes) -> dict:
    version_id = secrets.token_urlsafe(16)
    digest = hashlib.sha256(data).hexdigest()
    wrapped, ciphertext = ctx.vault.encrypt(data, doc_id, version_id, digest)
    ctx.conn.execute(
        "INSERT INTO document_versions (id, document_id, version_no, original_name, content_type, size_bytes,"
        " sha256, key_id, wrapped_key, ciphertext, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (version_id, doc_id, version_no, filename, content_type, len(data), digest, ctx.vault.key_id,
         wrapped, ciphertext, ctx.user["id"], clock.now_iso()))
    return {"version_no": version_no, "sha256": digest, "bytes": len(data), "filename": filename,
            "content_type": content_type}


def create_document(ctx: Ctx, title: str, category: str, filename: str, data: bytes) -> str:
    if not authz.has_capability(ctx.user, "upload"):
        ctx.log("upload", outcome="denied", details={"reason": f"role '{ctx.user['role'] if ctx.user else None}' cannot upload"})
        raise Forbidden("Your role cannot upload documents.")
    try:
        title = clean_text(title, "Title", 160)
        category = clean_text(category, "Category", 60)
        filename, content_type = validate_upload(filename, data, ctx.settings.max_upload_mb * 1024 * 1024)
    except ValidationError as exc:
        ctx.log("upload", outcome="denied", details={"reason": str(exc), "filename": (filename or "")[:120],
                                                     "bytes": len(data)})
        raise _invalid(exc)
    doc_id = secrets.token_urlsafe(16)
    with ctx.conn.transaction():
        _check_quota(ctx, len(data))
        now = clock.now_iso()
        ctx.conn.execute(
            "INSERT INTO documents (id, title, category, owner_id, current_version, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?)", (doc_id, title, category, ctx.user["id"], 1, now, now))
        info = _store_version(ctx, doc_id, 1, filename, content_type, data)
        ctx.log("upload", document_id=doc_id, details={"title": title, "category": category, **info})
    return doc_id


@document_operation
def add_version(ctx: Ctx, doc_id: str, filename: str, data: bytes) -> int:
    try:
        filename, content_type = validate_upload(filename, data, ctx.settings.max_upload_mb * 1024 * 1024)
    except ValidationError as exc:
        with ctx.conn.transaction():
            _authorize(ctx, doc_id, "upload_version")  # do not reveal validation result to outsiders
            ctx.log("upload_version", outcome="denied", document_id=doc_id, details={"reason": str(exc)})
        raise _invalid(exc)
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "upload_version")
        _check_quota(ctx, len(data))
        number = doc["current_version"] + 1
        info = _store_version(ctx, doc_id, number, filename, content_type, data)
        ctx.conn.execute("UPDATE documents SET current_version = ?, updated_at = ? WHERE id = ?",
                         (number, clock.now_iso(), doc_id))
        ctx.log("upload_version", document_id=doc_id, details=info)
    return number


@document_operation
def update_metadata(ctx: Ctx, doc_id: str, title: str, category: str) -> None:
    try:
        title = clean_text(title, "Title", 160)
        category = clean_text(category, "Category", 60)
    except ValidationError as exc:
        with ctx.conn.transaction():
            _authorize(ctx, doc_id, "edit_metadata")
        raise _invalid(exc)
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "edit_metadata")
        ctx.conn.execute("UPDATE documents SET title = ?, category = ?, updated_at = ? WHERE id = ?",
                         (title, category, clock.now_iso(), doc_id))
        ctx.log("edit_metadata", document_id=doc_id, details={
            "before": {"title": doc["title"], "category": doc["category"]},
            "after": {"title": title, "category": category}})


@document_operation
def delete_document(ctx: Ctx, doc_id: str) -> None:
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "delete")
        ctx.conn.execute("UPDATE documents SET deleted_at = ?, deleted_by = ?, updated_at = ? WHERE id = ?",
                         (clock.now_iso(), ctx.user["id"], clock.now_iso(), doc_id))
        active = ctx.conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (doc_id,))
        ctx.log("delete", document_id=doc_id, details={"mode": "trash", "grants_suspended": int(active or 0)})


@document_operation
def restore_document(ctx: Ctx, doc_id: str) -> None:
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "restore")
        ctx.conn.execute("UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = ? WHERE id = ?",
                         (clock.now_iso(), doc_id))
        grants = ctx.conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (doc_id,))
        ctx.log("restore", document_id=doc_id, details={"grants_reinstated": int(grants or 0)})


@document_operation
def purge_document(ctx: Ctx, doc_id: str) -> None:
    """Irreversible: destroys ciphertext and wrapped keys and removes grants. Metadata
    stub and the full audit history are kept as evidence."""
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "purge")
        ctx.conn.execute("UPDATE document_versions SET ciphertext = NULL, wrapped_key = NULL WHERE document_id = ?",
                         (doc_id,))
        removed = ctx.conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (doc_id,))
        ctx.conn.execute("DELETE FROM grants WHERE document_id = ?", (doc_id,))
        ctx.conn.execute("UPDATE documents SET purged_at = ?, updated_at = ? WHERE id = ?",
                         (clock.now_iso(), clock.now_iso(), doc_id))
        ctx.log("purge", document_id=doc_id, details={"grants_removed": int(removed or 0)})


def trash(ctx: Ctx) -> list[dict]:
    return ctx.conn.all(
        "SELECT d.id, d.title, d.category, d.deleted_at, v.original_name, v.size_bytes FROM documents d"
        " JOIN document_versions v ON v.document_id = d.id AND v.version_no = d.current_version"
        " WHERE d.owner_id = ? AND d.deleted_at IS NOT NULL AND d.purged_at IS NULL ORDER BY d.deleted_at DESC",
        (ctx.user["id"],))


# -------------------------------------------------------------------------- grants --
@document_operation
def list_grants(ctx: Ctx, doc_id: str) -> list[dict]:
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "manage_grants")
    rows = ctx.conn.all(
        "SELECT g.permission, g.created_at, g.expires_at, u.username, u.display_name, u.role, u.is_active,"
        " gb.username AS granted_by FROM grants g JOIN users u ON u.id = g.user_id"
        " JOIN users gb ON gb.id = g.granted_by WHERE g.document_id = ? ORDER BY u.username", (doc_id,))
    now = clock.now_iso()
    for row in rows:
        row["expired"] = bool(row["expires_at"] and row["expires_at"] <= now)
    return rows


@document_operation
def set_grant(ctx: Ctx, doc_id: str, username: str, permission: str, expires_on: str | None = None,
              source: str = "manual", suggestion: dict | None = None) -> None:
    """Grant or change access for a named person. Only the owner can call this, and only
    a human request reaches it: suggestions are shown, never applied automatically."""
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "manage_grants")
        if permission not in ("read", "edit"):
            raise Invalid("Permission must be 'read' or 'edit'.")
        if source not in ("manual", "suggestion"):
            source = "manual"
        try:
            expires_at = grant_expiry(expires_on)
        except ValidationError as exc:
            raise _invalid(exc)
        target = ctx.conn.one("SELECT id, username, is_active FROM users WHERE username = ?",
                              ((username or "").strip().lower(),))
        if not target or not target["is_active"]:
            raise Invalid("Choose an active user.")
        if target["id"] == doc["owner_id"]:
            raise Invalid("The owner already has full access.")
        existing = ctx.conn.one("SELECT permission, expires_at FROM grants WHERE document_id = ? AND user_id = ?",
                                (doc_id, target["id"]))
        if existing:
            ctx.conn.execute("UPDATE grants SET permission = ?, expires_at = ?, granted_by = ?, created_at = ?"
                             " WHERE document_id = ? AND user_id = ?",
                             (permission, expires_at, ctx.user["id"], clock.now_iso(), doc_id, target["id"]))
        else:
            ctx.conn.execute("INSERT INTO grants (document_id, user_id, permission, granted_by, created_at, expires_at)"
                             " VALUES (?,?,?,?,?,?)",
                             (doc_id, target["id"], permission, ctx.user["id"], clock.now_iso(), expires_at))
        details = {"permission": permission, "expires_at": expires_at, "source": source,
                   "previous": existing["permission"] if existing else None}
        if suggestion:
            details["suggestion"] = suggestion
        ctx.log("grant_changed" if existing else "grant", document_id=doc_id, target=target["username"],
                details=details)


@document_operation
def revoke_grant(ctx: Ctx, doc_id: str, username: str) -> None:
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "manage_grants")
        target = ctx.conn.one("SELECT id, username FROM users WHERE username = ?", ((username or "").strip().lower(),))
        existing = ctx.conn.one("SELECT permission FROM grants WHERE document_id = ? AND user_id = ?",
                                (doc_id, target["id"])) if target else None
        if not existing:
            raise Invalid("That person has no grant on this document.")
        ctx.conn.execute("DELETE FROM grants WHERE document_id = ? AND user_id = ?", (doc_id, target["id"]))
        ctx.log("revoke", document_id=doc_id, target=target["username"], details={"previous": existing["permission"]})


@document_operation
def grantable_users(ctx: Ctx, doc_id: str) -> list[dict]:
    """Active people the owner can pick from. The user directory is visible only to
    someone who is managing a document they own."""
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "manage_grants")
    return ctx.conn.all(
        "SELECT u.username, u.display_name, u.role FROM users u WHERE u.is_active = 1"
        " AND u.id <> (SELECT owner_id FROM documents WHERE id = ?)"
        " AND u.id NOT IN (SELECT user_id FROM grants WHERE document_id = ?) ORDER BY u.username",
        (doc_id, doc_id))
