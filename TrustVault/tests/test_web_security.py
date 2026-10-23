"""HTTP-level hardening and configuration. Threat ids refer to THREATS.md."""
import pytest

from conftest import doc_id
from trustvault.config import ConfigError, load_settings


def test_T27_security_headers_on_every_page(app, browser):
    victor = browser("victor")
    for path in ("/login", "/documents", f"/documents/{doc_id(app, 'Salary letter')}"):
        h = victor.get(path).headers
        assert "default-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert "unsafe-inline" not in h["Content-Security-Policy"]
        assert h["X-Frame-Options"] == "DENY"
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"] == "same-origin"
        assert h["Cache-Control"] == "no-store"  # back button after logout shows nothing


def test_T18_stored_xss_is_escaped(app, browser):
    alice = browser("alice")
    alice.upload(title='<script>alert("x")</script><img src=x onerror=alert(1)>', category="<b>HR</b>")
    d = doc_id(app, "<script>")
    for page in (alice.get("/documents").data, alice.get(f"/documents/{d}").data):
        assert b"<script>alert" not in page and b"<img src=x" not in page
        assert b"&lt;script&gt;" in page


def test_T18_bidi_and_control_characters_rejected_in_titles(app, browser):
    alice = browser("alice")
    assert alice.upload(title="invoice‮txt.exe").status_code == 400
    assert alice.upload(title="line\x00break").status_code == 400


def test_T19_sql_injection_in_search_and_ids(app, browser):
    victor = browser("victor")
    for q in ("' OR '1'='1", "%' OR 1=1 --", "\") OR 1=1; DROP TABLE documents; --", "audit%", "!%"):
        response = victor.get("/documents", query_string={"q": q, "owner": q, "category": q})
        assert response.status_code == 200
        assert b"Audit papers" not in response.data
    assert victor.get("/documents/' OR '1'='1").status_code == 404
    assert victor.get("/documents/1 UNION SELECT * FROM users").status_code == 404
    assert victor.get("/documents", query_string={"from": "2026-13-45"}).status_code == 200
    assert browser("bob").get("/documents").data.count(b"Audit papers") == 1  # table still there


def test_T30_request_rate_limit(app, browser):
    app.extensions["trustvault"]["settings"].rate_limit_per_minute = 5
    b = browser()
    statuses = [b.get("/login").status_code for _ in range(7)]
    assert statuses[-1] == 429


def test_T31_production_refuses_to_start_without_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.setenv("TRUSTVAULT_INSTANCE_DIR", str(tmp_path))
    for name in ("DATABASE_URL", "TRUSTVAULT_MASTER_KEY", "TRUSTVAULT_AUDIT_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError):
        load_settings()
    monkeypatch.setenv("DATABASE_URL", "postgresql://x/y")
    monkeypatch.setenv("TRUSTVAULT_MASTER_KEY", "short")
    monkeypatch.setenv("TRUSTVAULT_AUDIT_KEY", "a" * 40)
    with pytest.raises(ConfigError):
        load_settings()
    monkeypatch.setenv("TRUSTVAULT_MASTER_KEY", "a" * 40)
    with pytest.raises(ConfigError):  # same secret for both purposes
        load_settings()
    monkeypatch.setenv("TRUSTVAULT_MASTER_KEY", "m" * 40)
    settings = load_settings()
    assert settings.secure_cookies and settings.trust_proxy_hops == 1


def test_T31_secure_cookie_prefix_in_production_mode(app):
    from trustvault import create_app
    import os
    secure = create_app({"secure_cookies": True, "rate_limit_per_minute": 0, "log_audit_to_stdout": False,
                         "seed_demo": False, "database_url": os.environ["DATABASE_URL"]})
    client = secure.test_client()
    response = client.post("/login", data={"username": "victor", "password": "Victor#Vault2026"})
    cookie = response.headers["Set-Cookie"]
    assert cookie.startswith("__Host-tv_session=") and "Secure" in cookie
    assert "Strict-Transport-Security" in response.headers


def test_healthcheck(app):
    assert app.test_client().get("/healthz").get_json()["status"] == "ok"
