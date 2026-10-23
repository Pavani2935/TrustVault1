"""THE authorisation policy. Every document operation, from every route (HTML or JSON),
is decided here, on the server, against the database state at the moment of the request.

Permission model (per document):
    owner  - the user who uploaded it. Full control, including grants and deletion.
    edit   - explicit grant: read + change metadata + upload a new version.
    read   - explicit grant: view metadata, download any version.
    (none) - everyone else. That explicitly includes administrators: the admin role
             manages accounts and reads the audit trail; it does not read documents.

Grants are per document and per named user (no folders, no groups, no inheritance,
no public links). A grant may carry an expiry. Nothing is cached: revoking a grant,
deleting a document or disabling an account takes effect on the next request.
"""
from __future__ import annotations

from . import clock

LEVEL = {None: 0, "read": 1, "edit": 2, "owner": 3}

# action -> minimum level required on a *live* (not deleted) document
LIVE_ACTIONS = {
    "view": "read",
    "download": "read",
    "edit_metadata": "edit",
    "upload_version": "edit",
    "delete": "owner",
    "manage_grants": "owner",
    "view_access_log": "owner",
    "suggest_access": "owner",
}
# actions that are only meaningful on a document in the owner's trash
TRASH_ACTIONS = {"restore": "owner", "purge": "owner", "view_access_log": "owner"}  # evidence outlives deletion


def effective_permission(conn, user: dict | None, doc: dict | None) -> str | None:
    """Return 'owner', 'edit', 'read' or None for this user on this document right now."""
    if not user or not doc or not user.get("is_active"):
        return None
    if doc.get("purged_at"):
        return None
    if doc["owner_id"] == user["id"]:
        return "owner"
    if doc.get("deleted_at"):
        return None  # grants do not survive deletion; only the owner can see the trash
    grant = conn.one(
        "SELECT permission, expires_at FROM grants WHERE document_id = ? AND user_id = ?",
        (doc["id"], user["id"]),
    )
    if not grant:
        return None
    if grant["expires_at"] and grant["expires_at"] <= clock.now_iso():
        return None
    return grant["permission"]


def is_allowed(conn, user: dict | None, doc: dict | None, action: str) -> tuple[bool, str | None]:
    """Decide whether `user` may perform `action` on `doc`. Returns (allowed, permission)."""
    if doc is None:
        return False, None
    permission = effective_permission(conn, user, doc)
    if doc.get("deleted_at"):
        required = TRASH_ACTIONS.get(action)
    else:
        required = LIVE_ACTIONS.get(action)
    if required is None:  # unknown action, or live action on trashed doc: deny by default
        return False, permission
    return LEVEL[permission] >= LEVEL[required], permission


# ---- role-level capabilities (not document access) -------------------------------
ROLE_CAPABILITIES = {
    "admin": {"manage_users", "read_audit", "view_inventory"},
    "owner": {"upload"},
    "viewer": set(),
}


def has_capability(user: dict | None, capability: str) -> bool:
    return bool(user and user.get("is_active") and capability in ROLE_CAPABILITIES.get(user["role"], set()))
