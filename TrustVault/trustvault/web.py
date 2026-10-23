"""Server-rendered UI. Every handler is a thin shell over the service layer, which is
where authorisation happens. Hiding a button here is cosmetic; the service decides."""
from __future__ import annotations

from functools import wraps
from urllib.parse import urlparse

import io

from flask import Blueprint, current_app, g, redirect, render_template, request, send_file, url_for

from . import auth, suggestions, users
from . import documents as docsvc
from .errors import Forbidden, Invalid, TooMany, Unauthenticated
from .validation import ALLOWED_EXTENSIONS

bp = Blueprint("web", __name__)


def ext():
    return current_app.extensions["trustvault"]


def flash(kind: str, message: str) -> None:
    auth.set_flash(g.ctx.conn, g.session, kind, message)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.ctx.user:
            audit_anonymous_document_attempt(kwargs)
            target = request.full_path if request.method == "GET" else "/"
            return redirect(url_for("web.login", next=target.rstrip("?")))
        return fn(*args, **kwargs)
    return wrapper


def audit_anonymous_document_attempt(kwargs: dict) -> None:
    """Refused attempts by people who are not signed in are evidence too."""
    if "doc_id" in kwargs:
        g.ctx.log("access_denied", outcome="denied", document_id=str(kwargs["doc_id"])[:80],
                  details={"attempted": request.endpoint, "reason": "not signed in"})


def _safe_next(value: str | None) -> str:
    """Only allow local paths (blocks open redirects like //evil.com or https://evil.com)."""
    if (not value or not value.startswith("/") or value.startswith("//") or "\\" in value
            or any(ch.isspace() or ord(ch) < 32 for ch in value)):  # browsers strip tabs: "/\t/evil" -> "//evil"
        return url_for("web.documents")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return url_for("web.documents")
    return value


def render(template: str, **context):
    flashes = auth.pop_flashes(g.ctx.conn, g.session) if g.session else []
    return render_template(template, flashes=flashes, **context)


# ------------------------------------------------------------------- auth ---------
@bp.route("/")
def index():
    return redirect(url_for("web.documents") if g.ctx.user else url_for("web.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    error, status = None, 200
    if request.method == "POST":
        try:
            user, token, _csrf = auth.login(g.ctx, request.form.get("username", ""), request.form.get("password", ""),
                                            request.headers.get("User-Agent", ""))
        except TooMany as exc:
            error, status = exc.message, 429
        except ValueError as exc:
            error, status = str(exc), 401
        else:
            old = request.cookies.get(ext()["cookie"])
            if old:
                auth.logout(g.ctx, old)  # never carry a pre-login session forward (fixation)
            g.cookie_to_set = token
            return redirect(_safe_next(request.args.get("next")))
    if g.ctx.user and request.method == "GET":
        return redirect(url_for("web.documents"))
    return render_template("login.html", error=error, flashes=[]), status


@bp.post("/logout")
def logout():
    if g.ctx.user:
        g.ctx.log("logout")
        auth.logout(g.ctx, request.cookies.get(ext()["cookie"]))
    g.clear_cookie = True
    return redirect(url_for("web.login"))


# -------------------------------------------------------------- documents ---------
@bp.get("/documents")
@login_required
def documents():
    filters = {k: request.args.get(k, "") for k in ("q", "owner", "category", "from", "to", "scope")}
    error = None
    try:
        rows = docsvc.search(g.ctx, q=filters["q"], owner=filters["owner"], category=filters["category"],
                                date_from=filters["from"], date_to=filters["to"], scope=filters["scope"] or "all")
    except Invalid as exc:
        rows, error = [], exc.message
    return render("documents.html", docs=rows, filters=filters, categories=docsvc.categories(g.ctx), error=error)


@bp.route("/documents/new", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        data = file.read() if file else b""
        try:
            doc_id = docsvc.create_document(g.ctx, request.form.get("title", ""), request.form.get("category", ""),
                                               file.filename if file else "", data)
        except (Invalid, TooMany) as exc:
            return render("upload.html", error=exc.message, form=request.form, allowed=ALLOWED_EXTENSIONS), exc.status
        flash("success", "Document encrypted and stored. Only you can see it until you grant access.")
        return redirect(url_for("web.document", doc_id=doc_id))
    if g.ctx.user["role"] != "owner":
        g.ctx.log("upload", outcome="denied", details={"reason": "role cannot upload (form requested)"})
        raise Forbidden("Only document owners can upload.")
    return render("upload.html", error=None, form={}, allowed=ALLOWED_EXTENSIONS)


@bp.get("/documents/<doc_id>")
@login_required
def document(doc_id):
    doc = docsvc.get_document(g.ctx, doc_id)
    grants, people = [], []
    if doc["can_manage"]:
        grants = docsvc.list_grants(g.ctx, doc_id)
        people = docsvc.grantable_users(g.ctx, doc_id)
    return render("document.html", doc=doc, grants=grants, people=people, allowed=ALLOWED_EXTENSIONS)


@bp.get("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    version_arg = request.args.get("v")
    version_no = int(version_arg) if version_arg and version_arg.isdigit() and len(version_arg) < 6 else None
    version, data = docsvc.get_content(g.ctx, doc_id, version_no)
    response = send_file(io.BytesIO(data), mimetype=version["content_type"], as_attachment=True,
                         download_name=version["original_name"], conditional=False, etag=False, max_age=0)
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@bp.post("/documents/<doc_id>/metadata")
@login_required
def edit_metadata(doc_id):
    try:
        docsvc.update_metadata(g.ctx, doc_id, request.form.get("title", ""), request.form.get("category", ""))
        flash("success", "Details updated.")
    except Invalid as exc:
        flash("error", exc.message)
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/versions")
@login_required
def new_version(doc_id):
    file = request.files.get("file")
    try:
        number = docsvc.add_version(g.ctx, doc_id, file.filename if file else "", file.read() if file else b"")
        flash("success", f"Version {number} uploaded.")
    except (Invalid, TooMany) as exc:
        flash("error", exc.message)
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/delete")
@login_required
def delete(doc_id):
    docsvc.delete_document(g.ctx, doc_id)
    flash("success", "Moved to trash. Everyone you shared it with lost access immediately.")
    return redirect(url_for("web.documents"))


@bp.post("/documents/<doc_id>/restore")
@login_required
def restore(doc_id):
    docsvc.restore_document(g.ctx, doc_id)
    flash("success", "Restored. Previous grants are active again.")
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/purge")
@login_required
def purge(doc_id):
    docsvc.purge_document(g.ctx, doc_id)
    flash("success", "File contents permanently destroyed. The audit history is kept.")
    return redirect(url_for("web.trash"))


@bp.get("/trash")
@login_required
def trash():
    return render("trash.html", docs=docsvc.trash(g.ctx))


# ----------------------------------------------------------------- sharing --------
@bp.post("/documents/<doc_id>/grants")
@login_required
def grant(doc_id):
    source = request.form.get("source", "manual")
    suggestion = None
    if source == "suggestion":
        suggestion = suggestions.suggestion_payload(request.form.get("username", ""), request.form.get("reason", ""))
    try:
        docsvc.set_grant(g.ctx, doc_id, request.form.get("username", ""), request.form.get("permission", ""),
                            request.form.get("expires_on") or None, source=source, suggestion=suggestion)
        flash("success", f"Access granted to {request.form.get('username', '')}.")
    except Invalid as exc:
        flash("error", exc.message)
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.post("/documents/<doc_id>/grants/<username>/revoke")
@login_required
def revoke(doc_id, username):
    try:
        docsvc.revoke_grant(g.ctx, doc_id, username)
        flash("success", f"Access revoked for {username}. Their next request is refused.")
    except Invalid as exc:
        flash("error", exc.message)
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.get("/documents/<doc_id>/suggestions")
@login_required
def suggest(doc_id):
    doc = docsvc.get_document(g.ctx, doc_id, audit_view=False)
    return render("suggestions.html", doc=doc, suggestions=suggestions.suggest(g.ctx, doc_id))


@bp.post("/documents/<doc_id>/suggestions/dismiss")
@login_required
def dismiss_suggestion(doc_id):
    suggestions.dismiss(g.ctx, doc_id, request.form.get("username", ""))
    flash("info", "Suggestion dismissed. Nothing was changed.")
    return redirect(url_for("web.document", doc_id=doc_id))


@bp.get("/documents/<doc_id>/activity")
@login_required
def activity(doc_id):
    events = docsvc.access_log(g.ctx, doc_id)
    doc = docsvc.document_summary(g.ctx, doc_id)
    return render("activity.html", doc=doc, events=events)


# ----------------------------------------------------------------- account --------
@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    error = None
    if request.method == "POST":
        try:
            token, _ = users.change_own_password(g.ctx, request.form.get("current", ""), request.form.get("new", ""),
                                                 request.headers.get("User-Agent", ""))
            g.cookie_to_set = token
            return redirect(url_for("web.documents"))
        except Invalid as exc:
            error = exc.message
    return render("account.html", sessions=users.my_sessions(g.ctx), error=error,
                  current_hash=g.session["token_hash"])


@bp.post("/account/sessions/end-others")
@login_required
def end_other_sessions():
    ended = auth.end_all_sessions(g.ctx.conn, g.ctx.user["id"], except_token=request.cookies.get(ext()["cookie"]))
    g.ctx.log("sessions_ended_by_user", details={"sessions_ended": ended})
    flash("success", f"Signed out {ended} other session(s).")
    return redirect(url_for("web.account"))


@bp.app_errorhandler(Unauthenticated)
def unauthenticated(exc):
    if request.path.startswith("/api/"):
        return ext()["error_response"](401, exc.message)
    return redirect(url_for("web.login"))

