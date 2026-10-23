"""Administrator screens: oversight of activity and permission changes, user lifecycle.
Every handler calls a service that checks the admin capability itself."""
from __future__ import annotations

from flask import Blueprint, Response, g, redirect, request, url_for

from . import reports, users
from .errors import Invalid
from .web import flash, login_required, render

bp = Blueprint("admin", __name__, url_prefix="/admin")

AUDIT_FILTERS = ("actor", "action", "outcome", "document_id", "from", "to")


def _filters() -> dict:
    raw = {k: request.args.get(k, "") for k in AUDIT_FILTERS}
    return {"actor": raw["actor"], "action": raw["action"], "outcome": raw["outcome"],
            "document_id": raw["document_id"], "date_from": raw["from"], "date_to": raw["to"]}


@bp.get("/")
@login_required
def dashboard():
    return render("admin/dashboard.html", data=reports.dashboard(g.ctx), client_ip=request.remote_addr,
                  forwarded_for=(request.headers.get("X-Forwarded-For") or "")[:200],
                  proxy_hops=g.ctx.settings.trust_proxy_hops)


@bp.get("/audit")
@login_required
def audit():
    error = None
    try:
        rows = reports.query_audit(g.ctx, **_filters())
    except Invalid as exc:
        rows, error = [], exc.message
    raw = {k: request.args.get(k, "") for k in AUDIT_FILTERS}
    return render("admin/audit.html", rows=rows, filters=raw, error=error, verification=None)


@bp.post("/audit/verify")
@login_required
def verify():
    result = reports.verify(g.ctx)
    rows = reports.query_audit(g.ctx, limit=100, log=False)
    return render("admin/audit.html", rows=rows, filters={k: "" for k in AUDIT_FILTERS}, error=None,
                  verification=result)


@bp.get("/audit/export.csv")
@login_required
def export():
    body = reports.export_csv(g.ctx, **_filters())
    return Response(body, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=trustvault-audit.csv"})


@bp.get("/documents")
@login_required
def inventory():
    return render("admin/inventory.html", rows=reports.inventory(g.ctx))


@bp.route("/users", methods=["GET", "POST"])
@login_required
def users_page():
    error = None
    if request.method == "POST":
        try:
            users.create_user(g.ctx, request.form.get("username", ""), request.form.get("display_name", ""),
                              request.form.get("password", ""), request.form.get("role", ""))
            flash("success", "Account created.")
            return redirect(url_for("admin.users_page"))
        except Invalid as exc:
            error = exc.message
    return render("admin/users.html", users=users.list_users(g.ctx), error=error, form=request.form)


def _user_id(value: str) -> int:
    # Malformed ids become -1 (no such user); the service checks the admin role first.
    return int(value) if value.isdigit() and len(value) <= 12 else -1


@bp.post("/users/<user_id>/status")
@login_required
def user_status(user_id):
    try:
        users.set_active(g.ctx, _user_id(user_id), request.form.get("active") == "1")
        flash("success", "Account status updated. Sessions of a disabled account end immediately.")
    except Invalid as exc:
        flash("error", exc.message)
    return redirect(url_for("admin.users_page"))


@bp.post("/users/<user_id>/role")
@login_required
def user_role(user_id):
    try:
        users.set_role(g.ctx, _user_id(user_id), request.form.get("role", ""))
        flash("success", "Role updated. It applies to the user's next request.")
    except Invalid as exc:
        flash("error", exc.message)
    return redirect(url_for("admin.users_page"))


@bp.post("/users/<user_id>/sessions/end")
@login_required
def user_sessions(user_id):
    ended = users.end_sessions(g.ctx, _user_id(user_id))
    flash("success", f"Ended {ended} session(s).")
    return redirect(url_for("admin.users_page"))
