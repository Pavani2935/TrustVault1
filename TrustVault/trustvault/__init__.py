"""TrustVault - secure document sharing with a verifiable audit trail."""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import auth
from .audit import AuditLog
from .config import Settings, load_settings
from .context import Ctx
from .crypto import IntegrityError, Vault
from .db import Database
from .errors import TrustVaultError

__version__ = "1.0.0"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
log = logging.getLogger("trustvault")


class RateLimiter:
    """Per-IP sliding window (in-memory; one instance per process). Login throttling is
    separate and persistent in the database."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        limit = self.settings.rate_limit_per_minute
        if limit <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            bucket = self.hits[key]
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            if len(self.hits) > 50_000:  # bound memory
                self.hits.clear()
            return True


def create_app(overrides: dict | None = None) -> Flask:
    settings: Settings = load_settings(overrides)
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=(settings.max_upload_mb + 1) * 1024 * 1024,
        SECRET_KEY=None,  # Flask's signed-cookie session is not used at all
        JSON_SORT_KEYS=False,
        TEMPLATES_AUTO_RELOAD=False,
    )
    if settings.trust_proxy_hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.trust_proxy_hops, x_proto=settings.trust_proxy_hops,
                                x_host=0, x_port=0, x_prefix=0)

    database = Database(settings.database_url)
    database.init_schema()
    vault = Vault(settings.master_key)
    audit_log = AuditLog(settings.audit_key, to_stdout=settings.log_audit_to_stdout)
    limiter = RateLimiter(settings)
    cookie_name = "__Host-tv_session" if settings.secure_cookies else "tv_session"

    app.extensions["trustvault"] = {"settings": settings, "db": database, "vault": vault,
                                    "audit": audit_log, "cookie": cookie_name}

    def make_ctx(user: dict | None, conn=None) -> Ctx:
        return Ctx(conn=conn or database.connect(), user=user, ip=None, settings=settings,
                   vault=vault, audit=audit_log)

    app.extensions["trustvault"]["make_ctx"] = make_ctx

    if settings.seed_demo:
        from .seed import seed_if_empty
        conn = database.connect()
        try:
            if seed_if_empty(lambda user: make_ctx(user, conn)):
                log.warning("Seeded demo accounts and documents.")
        finally:
            conn.close()

    # ------------------------------------------------------------ request cycle --
    @app.before_request
    def open_request():
        g.cookie_to_set = None
        g.clear_cookie = False
        g.session = None
        is_api = request.path.startswith("/api/")
        g.is_api = is_api
        if request.path.startswith("/static/") or request.path == "/healthz":
            g.ctx = None
            return None
        if not limiter.allow(request.remote_addr or "unknown"):
            return _error_response(429, "Too many requests. Slow down.")
        conn = database.connect()
        g.ctx = Ctx(conn=conn, user=None, ip=request.remote_addr, settings=settings, vault=vault, audit=audit_log)
        loaded = auth.load_session(g.ctx, request.cookies.get(cookie_name))
        if loaded:
            g.ctx.user, g.session = loaded
        elif request.cookies.get(cookie_name):
            g.clear_cookie = True

        if request.method in UNSAFE_METHODS:
            if not _same_origin():
                g.ctx.log("origin_rejected", outcome="denied",
                          details={"path": request.path, "origin": (request.headers.get("Origin") or request.headers.get("Referer") or "")[:200]})
                return _error_response(403, "Cross-site request blocked.")
            if g.session is not None:
                submitted = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
                if not auth.csrf_valid(g.session, submitted):
                    g.ctx.log("csrf_rejected", outcome="denied", details={"path": request.path, "method": request.method})
                    return _error_response(403, "Security token missing or expired. Reload the page and try again.")
        return None

    def _same_origin() -> bool:
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source or source == "null":
            return source != "null"
        parsed = urlparse(source)
        return parsed.netloc.lower() == request.host.lower()

    @app.after_request
    def finish_request(response):
        headers = response.headers
        headers.setdefault("Content-Security-Policy",
                           "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                           "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "same-origin"  # "no-referrer" makes browsers send Origin: null on form posts
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.secure_cookies:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.path.startswith("/static/"):
            headers["Cache-Control"] = "no-store"
            headers["Pragma"] = "no-cache"
        token = getattr(g, "cookie_to_set", None)
        if token:
            response.set_cookie(cookie_name, token, httponly=True, secure=settings.secure_cookies,
                                samesite="Lax", path="/")
        elif getattr(g, "clear_cookie", False):
            response.delete_cookie(cookie_name, path="/", secure=settings.secure_cookies, httponly=True, samesite="Lax")
        return response

    @app.teardown_request
    def close_request(_exc):
        ctx = g.pop("ctx", None)
        if ctx is not None:
            ctx.conn.close()

    # ---------------------------------------------------------------- errors ----
    def _error_response(status: int, message: str):
        if getattr(g, "is_api", False) or request.path.startswith("/api/"):
            return jsonify({"error": message, "status": status}), status
        return render_template("error.html", status=status, message=message), status

    app.extensions["trustvault"]["error_response"] = _error_response

    @app.errorhandler(TrustVaultError)
    def handle_domain_error(exc: TrustVaultError):
        return _error_response(exc.status, exc.message)

    @app.errorhandler(IntegrityError)
    def handle_integrity(_exc):
        return _error_response(500, "The stored file failed its integrity check. The event has been recorded.")

    @app.errorhandler(HTTPException)
    def handle_http(exc: HTTPException):
        if exc.code == 413:
            ctx = getattr(g, "ctx", None)
            if ctx is not None:
                ctx.log("upload", outcome="denied", details={"reason": "request body too large", "path": request.path})
            return _error_response(413, f"Upload exceeds {settings.max_upload_mb} MB.")
        messages = {404: "Not found.", 405: "Method not allowed.", 400: "Bad request."}
        return _error_response(exc.code or 500, messages.get(exc.code, exc.description or "Error"))

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):  # never leak stack traces
        log.exception("Unhandled error on %s %s", request.method, request.path)
        return _error_response(500, "Something went wrong. The error has been logged.")

    @app.get("/healthz")
    def healthz():
        conn = database.connect()
        try:
            conn.scalar("SELECT 1 AS ok")
        finally:
            conn.close()
        return jsonify({"status": "ok", "version": __version__})

    from .web import bp as web_bp
    from .admin_web import bp as admin_bp
    from .api import bp as api_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def inject():
        ctx = getattr(g, "ctx", None)
        return {
            "me": ctx.user if ctx else None,
            "csrf_token": g.session["csrf_token"] if getattr(g, "session", None) else "",
            "demo_mode": settings.demo_mode,
            "app_version": __version__,
        }

    log.info("TrustVault %s started (%s, env=%s)", __version__, database.describe(), settings.env)
    return app
