"""JSON API (v1). Same session cookie as the UI; state-changing calls must send the
X-CSRF-Token header returned by /auth/login or /me. Uses exactly the same service
functions as the UI, so there is one authorisation path, not two."""
from __future__ import annotations

import io
import json
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request, send_file

from . import auth, reports, suggestions, users
from . import documents as docsvc
from .errors import Invalid, Unauthenticated
from .validation import ALLOWED_EXTENSIONS
from .web import audit_anonymous_document_attempt

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def authenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.ctx.user:
            audit_anonymous_document_attempt(kwargs)
            raise Unauthenticated()
        return fn(*args, **kwargs)
    return wrapper


def body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def public_user(user: dict) -> dict:
    return {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}


def _events(rows: list[dict]) -> list[dict]:
    for row in rows:
        try:
            row["details"] = json.loads(row.get("details") or "{}")
        except ValueError:
            pass
    return rows


# ------------------------------------------------------------------ auth ----------
@bp.post("/auth/login")
def login():
    data = body()
    try:
        user, token, csrf = auth.login(g.ctx, str(data.get("username", "")), str(data.get("password", "")),
                                       request.headers.get("User-Agent", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc), "status": 401}), 401
    old = request.cookies.get(current_app.extensions["trustvault"]["cookie"])
    if old:
        auth.logout(g.ctx, old)
    g.cookie_to_set = token
    return jsonify({"user": public_user(user), "csrf_token": csrf})


@bp.post("/auth/logout")
@authenticated
def logout():
    g.ctx.log("logout")
    auth.logout(g.ctx, request.cookies.get(current_app.extensions["trustvault"]["cookie"]))
    g.clear_cookie = True
    return jsonify({"ok": True})


@bp.get("/me")
@authenticated
def me():
    return jsonify({"user": public_user(g.ctx.user), "csrf_token": g.session["csrf_token"]})


# ------------------------------------------------------------- documents ----------
@bp.get("/documents")
@authenticated
def list_documents():
    a = request.args
    rows = docsvc.search(g.ctx, q=a.get("q", ""), owner=a.get("owner", ""), category=a.get("category", ""),
                         date_from=a.get("from", ""), date_to=a.get("to", ""), scope=a.get("scope", "all"))
    keys = ("id", "title", "category", "owner_username", "created_at", "updated_at", "current_version",
            "original_name", "size_bytes", "my_permission", "grant_expires_at")
    return jsonify({"documents": [{k: r.get(k) for k in keys} for r in rows]})


@bp.post("/documents")
@authenticated
def create_document():
    file = request.files.get("file")
    doc_id = docsvc.create_document(g.ctx, request.form.get("title", ""), request.form.get("category", ""),
                                    file.filename if file else "", file.read() if file else b"")
    return jsonify({"id": doc_id}), 201


@bp.get("/documents/<doc_id>")
@authenticated
def get_document(doc_id):
    return jsonify(docsvc.get_document(g.ctx, doc_id))


@bp.get("/documents/<doc_id>/content")
@authenticated
def content(doc_id):
    raw = request.args.get("version", "")
    version_no = int(raw) if raw.isdigit() and len(raw) < 6 else None
    version, data = docsvc.get_content(g.ctx, doc_id, version_no)
    response = send_file(io.BytesIO(data), mimetype=version["content_type"], as_attachment=True,
                         download_name=version["original_name"], conditional=False, etag=False, max_age=0)
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@bp.patch("/documents/<doc_id>")
@authenticated
def patch_document(doc_id):
    data = body()
    current = docsvc.get_document(g.ctx, doc_id, audit_view=False)
    docsvc.update_metadata(g.ctx, doc_id, str(data.get("title", current["title"])),
                           str(data.get("category", current["category"])))
    return jsonify(docsvc.get_document(g.ctx, doc_id, audit_view=False))


@bp.post("/documents/<doc_id>/versions")
@authenticated
def add_version(doc_id):
    file = request.files.get("file")
    number = docsvc.add_version(g.ctx, doc_id, file.filename if file else "", file.read() if file else b"")
    return jsonify({"version": number}), 201


@bp.delete("/documents/<doc_id>")
@authenticated
def delete_document(doc_id):
    docsvc.delete_document(g.ctx, doc_id)
    return jsonify({"ok": True, "state": "trash"})


@bp.post("/documents/<doc_id>/restore")
@authenticated
def restore_document(doc_id):
    docsvc.restore_document(g.ctx, doc_id)
    return jsonify({"ok": True})


@bp.post("/documents/<doc_id>/purge")
@authenticated
def purge_document(doc_id):
    docsvc.purge_document(g.ctx, doc_id)
    return jsonify({"ok": True})


@bp.get("/trash")
@authenticated
def trash():
    return jsonify({"documents": docsvc.trash(g.ctx)})


@bp.get("/documents/<doc_id>/grants")
@authenticated
def grants(doc_id):
    return jsonify({"grants": docsvc.list_grants(g.ctx, doc_id)})


@bp.put("/documents/<doc_id>/grants/<username>")
@authenticated
def put_grant(doc_id, username):
    data = body()
    docsvc.set_grant(g.ctx, doc_id, username, str(data.get("permission", "")), data.get("expires_on") or None)
    return jsonify({"grants": docsvc.list_grants(g.ctx, doc_id)})


@bp.delete("/documents/<doc_id>/grants/<username>")
@authenticated
def delete_grant(doc_id, username):
    docsvc.revoke_grant(g.ctx, doc_id, username)
    return jsonify({"grants": docsvc.list_grants(g.ctx, doc_id)})


@bp.get("/documents/<doc_id>/activity")
@authenticated
def activity(doc_id):
    return jsonify({"events": _events(docsvc.access_log(g.ctx, doc_id))})


@bp.get("/documents/<doc_id>/suggestions")
@authenticated
def get_suggestions(doc_id):
    return jsonify({"suggestions": suggestions.suggest(g.ctx, doc_id),
                    "note": "Suggestions are never applied automatically. PUT a grant to accept one."})


@bp.get("/meta")
def meta():
    return jsonify({"allowed_extensions": ALLOWED_EXTENSIONS, "max_upload_mb": g.ctx.settings.max_upload_mb})


# ----------------------------------------------------------------- admin ----------
@bp.get("/admin/dashboard")
@authenticated
def admin_dashboard():
    data = reports.dashboard(g.ctx)
    data["permission_changes"] = _events(data["permission_changes"])
    return jsonify(data)


@bp.get("/admin/audit")
@authenticated
def admin_audit():
    a = request.args
    before = a.get("before_seq", "")
    rows = reports.query_audit(g.ctx, actor=a.get("actor", ""), action=a.get("action", ""),
                               outcome=a.get("outcome", ""), document_id=a.get("document_id", ""),
                               date_from=a.get("from", ""), date_to=a.get("to", ""),
                               limit=int(a.get("limit", "200")) if a.get("limit", "200").isdigit() else 200,
                               before_seq=int(before) if before.isdigit() else None)
    return jsonify({"events": _events(rows)})


@bp.post("/admin/audit/verify")
@authenticated
def admin_verify():
    return jsonify(reports.verify(g.ctx))


@bp.get("/admin/documents")
@authenticated
def admin_inventory():
    return jsonify({"documents": reports.inventory(g.ctx)})


@bp.get("/admin/users")
@authenticated
def admin_users():
    return jsonify({"users": users.list_users(g.ctx)})


@bp.post("/admin/users")
@authenticated
def admin_create_user():
    data = body()
    user_id = users.create_user(g.ctx, str(data.get("username", "")), str(data.get("display_name", "")),
                                str(data.get("password", "")), str(data.get("role", "")))
    return jsonify({"id": user_id}), 201


@bp.patch("/admin/users/<int:user_id>")
@authenticated
def admin_update_user(user_id):
    data = body()
    if "is_active" in data:
        if not isinstance(data["is_active"], bool):  # "false" is truthy; demand a real JSON boolean
            raise Invalid("is_active must be true or false.")
        users.set_active(g.ctx, user_id, data["is_active"])
    if "role" in data:
        users.set_role(g.ctx, user_id, str(data["role"]))
    return jsonify({"users": users.list_users(g.ctx)})


@bp.post("/admin/users/<int:user_id>/sessions/end")
@authenticated
def admin_end_sessions(user_id):
    return jsonify({"sessions_ended": users.end_sessions(g.ctx, user_id)})
