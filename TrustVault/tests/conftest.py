"""Test fixtures.

Tests run against SQLite by default. Set TEST_DATABASE_URL=postgresql://... to run the
whole suite against PostgreSQL instead (the schema is dropped and recreated per test).
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("TRUSTVAULT_PASSWORD_HASH", "pbkdf2:sha256:1000")  # speed only; production uses scrypt
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trustvault import clock, create_app  # noqa: E402

PASSWORDS = {
    "admin": "Admin#Vault2026",
    "alice": "Alice#Vault2026",
    "bob": "Bob#Vault2026!",
    "victor": "Victor#Vault2026",
    "wendy": "Wendy#Vault2026",
}


def _reset_postgres(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_INSTANCE_DIR", str(tmp_path))
    monkeypatch.setenv("TRUSTVAULT_ENV", "development")
    pg = os.environ.get("TEST_DATABASE_URL")
    if pg:
        _reset_postgres(pg)
        url = pg
    else:
        url = "sqlite:///" + (tmp_path / "test.db").as_posix()
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("TRUSTVAULT_MASTER_KEY", "test-master-key-" + "m" * 40)
    monkeypatch.setenv("TRUSTVAULT_AUDIT_KEY", "test-audit-key-" + "a" * 40)
    clock.reset()
    application = create_app({"rate_limit_per_minute": 0, "log_audit_to_stdout": False, "demo_mode": True})
    application.config.update(TESTING=True)
    yield application
    clock.reset()


class Browser:
    """A test client that behaves like a browser: keeps cookies and sends the CSRF token
    for state-changing requests (unless told not to)."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()
        self.csrf = None

    def login(self, username, password=None):
        data = {"username": username, "password": password or PASSWORDS[username]}
        if self.csrf:
            data["csrf_token"] = self.csrf  # re-login while signed in is a state change too
        response = self.client.post("/login", data=data)
        assert response.status_code == 302, f"login failed for {username}: {response.status_code}"
        self.refresh_csrf()
        return response

    def refresh_csrf(self):
        me = self.client.get("/api/v1/me")
        self.csrf = me.get_json()["csrf_token"] if me.status_code == 200 else None

    def get(self, url, **kw):
        return self.client.get(url, **kw)

    def post(self, url, data=None, csrf=True, **kw):
        data = dict(data or {})
        if csrf and self.csrf:
            data.setdefault("csrf_token", self.csrf)
        return self.client.post(url, data=data, **kw)

    def api(self, method, url, json=None, csrf=True, **kw):
        headers = kw.pop("headers", {})
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.client.open(url, method=method, json=json, headers=headers, **kw)

    def upload(self, title="Secret plan", category="Strategy", filename="plan.txt", content=b"top secret plan"):
        return self.post("/documents/new", data={"title": title, "category": category,
                                                 "file": (io.BytesIO(content), filename)},
                         content_type="multipart/form-data")


@pytest.fixture()
def browser(app):
    def make(username=None):
        b = Browser(app)
        if username:
            b.login(username)
        return b
    return make


def db(app):
    return app.extensions["trustvault"]["db"].connect()


def doc_id(app, title_prefix):
    conn = db(app)
    try:
        row = conn.one("SELECT id FROM documents WHERE title LIKE ? ORDER BY created_at DESC", (title_prefix + "%",))
        assert row, f"no document titled {title_prefix!r}"
        return row["id"]
    finally:
        conn.close()


def audit_rows(app, **where):
    conn = db(app)
    try:
        sql = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        for key, value in where.items():
            sql += f" AND {key} = ?"
            params.append(value)
        return conn.all(sql + " ORDER BY seq", params)
    finally:
        conn.close()
