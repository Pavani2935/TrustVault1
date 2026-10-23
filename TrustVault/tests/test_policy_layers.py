"""Each defensive layer tested on its own.

Several protections are deliberately layered (e.g. disabling a user both deletes their
sessions AND makes the policy refuse them). End-to-end tests pass as long as ANY layer
holds, so removing just one layer would go unnoticed. These tests pin each layer
individually; scripts/mutation_check.py proves it.
"""
from conftest import db, doc_id

from trustvault import authz, clock


def load(app, sql, params=()):
    conn = db(app)
    try:
        return conn.one(sql, params)
    finally:
        conn.close()


def run(app, sql, params=()):
    conn = db(app)
    try:
        conn.execute(sql, params)
    finally:
        conn.close()


def policy(app, username, title, action):
    conn = db(app)
    try:
        user = conn.one("SELECT * FROM users WHERE username = ?", (username,))
        doc = conn.one("SELECT * FROM documents WHERE title LIKE ?", (title + "%",))
        return authz.is_allowed(conn, user, doc, action)
    finally:
        conn.close()


def test_policy_refuses_inactive_user_even_with_a_grant(app):
    assert policy(app, "victor", "Salary letter", "download") == (True, "read")
    run(app, "UPDATE users SET is_active = 0 WHERE username = 'victor'")
    assert policy(app, "victor", "Salary letter", "download") == (False, None)


def test_policy_ignores_grants_on_deleted_documents(app):
    d = doc_id(app, "Salary letter")
    run(app, "UPDATE documents SET deleted_at = ? WHERE id = ?", (clock.now_iso(), d))
    conn = db(app)
    try:
        victor = conn.one("SELECT * FROM users WHERE username = 'victor'")
        alice = conn.one("SELECT * FROM users WHERE username = 'alice'")
        doc = conn.one("SELECT * FROM documents WHERE id = ?", (d,))
        assert authz.effective_permission(conn, victor, doc) is None
        assert authz.effective_permission(conn, alice, doc) == "owner"
        assert authz.is_allowed(conn, alice, doc, "download") == (False, "owner")  # trash: restore first
        assert authz.is_allowed(conn, alice, doc, "restore") == (True, "owner")
        assert authz.is_allowed(conn, victor, doc, "restore")[0] is False
    finally:
        conn.close()


def test_policy_expired_and_purged(app):
    d = doc_id(app, "Offer letter")
    assert policy(app, "wendy", "Offer letter", "view")[0]
    run(app, "UPDATE grants SET expires_at = ? WHERE document_id = ?", (clock.ago_iso(seconds=1), d))
    assert policy(app, "wendy", "Offer letter", "view") == (False, None)
    run(app, "UPDATE documents SET purged_at = ? WHERE id = ?", (clock.now_iso(), d))
    assert policy(app, "alice", "Offer letter", "view") == (False, None)


def test_policy_default_deny(app):
    assert policy(app, "alice", "Salary letter", "restore") == (False, "owner")  # trash-only action on live doc
    assert policy(app, "alice", "Salary letter", "something_new") == (False, "owner")
    assert policy(app, "admin", "Salary letter", "view") == (False, None)
    conn = db(app)
    try:
        assert authz.is_allowed(conn, None, None, "view") == (False, None)
    finally:
        conn.close()


def test_session_layer_refuses_inactive_user_with_surviving_session_row(app, browser):
    """E.g. an account disabled by a directory sync that did not clean up sessions."""
    victor = browser("victor")
    run(app, "UPDATE users SET is_active = 0 WHERE username = 'victor'")
    assert victor.api("GET", "/api/v1/me").status_code == 401
    assert load(app, "SELECT COUNT(*) AS n FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = 'victor'")["n"] == 0


def test_session_layer_refuses_sessions_older_than_the_password(app, browser):
    victor = browser("victor")
    run(app, "UPDATE users SET password_changed_at = ? WHERE username = 'victor'", (clock.ahead_iso(seconds=1),))
    assert victor.api("GET", "/api/v1/me").status_code == 401


def test_role_change_applies_on_next_request(app, browser):
    alice = browser("alice")
    assert alice.get("/documents/new").status_code == 200
    run(app, "UPDATE users SET role = 'viewer' WHERE username = 'alice'")
    assert alice.get("/documents/new").status_code == 403
    assert alice.get(f"/documents/{doc_id(app, 'Salary letter')}").status_code == 200  # still owns her documents


def test_search_policy_recheck_catches_a_broken_query(app, browser, monkeypatch):
    """If the listing SQL is ever widened by mistake, the per-row policy check still hides rows."""
    from trustvault import documents
    broken = documents.LIST_SQL.replace(
        "AND (d.owner_id = ? OR (g.id IS NOT NULL AND (g.expires_at IS NULL OR g.expires_at > ?)))",
        "AND (? IS NOT NULL OR ? IS NOT NULL)")
    assert broken != documents.LIST_SQL
    monkeypatch.setattr(documents, "LIST_SQL", broken)
    page = browser("victor").get("/documents").data
    assert b"Audit papers" not in page and b"Customer contract" not in page
