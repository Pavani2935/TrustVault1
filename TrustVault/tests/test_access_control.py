"""Document access control. Threat ids (T-xx) refer to THREATS.md."""
import io

import pytest

from conftest import audit_rows, db, doc_id

PRIVATE = "Audit papers FY2025"      # bob's, no grants at all
SALARY = "Salary letter"             # alice's, victor has read
HANDBOOK = "Employee handbook"       # alice's, victor+wendy read, bob edit
CONTRACT = "Customer contract"       # bob's, wendy edit
OFFER = "Offer letter"               # alice's, wendy read with expiry


def document_routes(d):
    """Every route that touches a single document (method, path, form/json body)."""
    return [
        ("GET", f"/documents/{d}", None),
        ("GET", f"/documents/{d}/download", None),
        ("GET", f"/documents/{d}/download?v=1", None),
        ("GET", f"/documents/{d}/activity", None),
        ("GET", f"/documents/{d}/suggestions", None),
        ("POST", f"/documents/{d}/metadata", {"title": "pwned", "category": "x"}),
        ("POST", f"/documents/{d}/versions", {"file": (io.BytesIO(b"pwned"), "x.txt")}),
        ("POST", f"/documents/{d}/delete", {}),
        ("POST", f"/documents/{d}/restore", {}),
        ("POST", f"/documents/{d}/purge", {}),
        ("POST", f"/documents/{d}/grants", {"username": "victor", "permission": "edit"}),
        ("POST", f"/documents/{d}/grants/alice/revoke", {}),
        ("POST", f"/documents/{d}/suggestions/dismiss", {"username": "victor"}),
    ]


def api_routes(d):
    return [
        ("GET", f"/api/v1/documents/{d}", None),
        ("GET", f"/api/v1/documents/{d}/content", None),
        ("GET", f"/api/v1/documents/{d}/content?version=1", None),
        ("GET", f"/api/v1/documents/{d}/grants", None),
        ("GET", f"/api/v1/documents/{d}/activity", None),
        ("GET", f"/api/v1/documents/{d}/suggestions", None),
        ("PATCH", f"/api/v1/documents/{d}", {"title": "pwned"}),
        ("DELETE", f"/api/v1/documents/{d}", None),
        ("POST", f"/api/v1/documents/{d}/restore", None),
        ("POST", f"/api/v1/documents/{d}/purge", None),
        ("PUT", f"/api/v1/documents/{d}/grants/victor", {"permission": "edit"}),
        ("DELETE", f"/api/v1/documents/{d}/grants/wendy", None),
    ]


def call(b, method, path, body):
    if path.startswith("/api/"):
        return b.api(method, path, json=body)
    if method == "GET":
        return b.get(path)
    return b.post(path, data=body, content_type="multipart/form-data")


def assert_untouched(app, d, title_prefix):
    conn = db(app)
    try:
        row = conn.one("SELECT title, deleted_at, purged_at, current_version FROM documents WHERE id = ?", (d,))
        grants = conn.all("SELECT u.username, g.permission FROM grants g JOIN users u ON u.id = g.user_id"
                          " WHERE g.document_id = ?", (d,))
    finally:
        conn.close()
    assert row["title"].startswith(title_prefix)
    assert row["deleted_at"] is None and row["purged_at"] is None
    assert row["current_version"] == 1
    assert not any(g["username"] == "victor" and g["permission"] == "edit" for g in grants)
    return grants


@pytest.mark.parametrize("who", ["victor", "wendy", "alice", "admin"])
def test_T01_no_route_reaches_an_ungranted_document(app, browser, who):
    """T-01 IDOR: every UI route for a document nobody was granted returns 404."""
    d = doc_id(app, PRIVATE)
    b = browser(who)
    for method, path, body in document_routes(d):
        response = call(b, method, path, body)
        assert response.status_code == 404, (who, method, path, response.status_code)
        assert b"Audit papers" not in response.data
    assert_untouched(app, d, PRIVATE)


@pytest.mark.parametrize("who", ["victor", "wendy", "alice", "admin"])
def test_T01_no_api_route_reaches_an_ungranted_document(app, browser, who):
    """T-01 IDOR through the JSON API."""
    d = doc_id(app, PRIVATE)
    b = browser(who)
    for method, path, body in api_routes(d):
        response = call(b, method, path, body)
        assert response.status_code == 404, (who, method, path, response.status_code)
        assert b"Audit papers" not in response.data
    assert_untouched(app, d, PRIVATE)


def test_T01_owner_still_has_full_access(app, browser):
    """Control case: the same routes work for the owner, so the 404s above are real denials."""
    d = doc_id(app, PRIVATE)
    bob = browser("bob")
    assert bob.get(f"/documents/{d}").status_code == 200
    download = bob.get(f"/documents/{d}/download")
    assert download.status_code == 200 and download.data.startswith(b"account,amount")
    assert bob.get(f"/documents/{d}/activity").status_code == 200
    assert bob.api("GET", f"/api/v1/documents/{d}/grants").status_code == 200


def test_T01_anonymous_cannot_reach_anything(app, browser):
    d = doc_id(app, SALARY)
    anon = browser()
    assert anon.get(f"/documents/{d}/download").status_code == 302  # to login
    assert anon.api("GET", f"/api/v1/documents/{d}/content").status_code == 401
    assert anon.api("GET", "/api/v1/documents").status_code == 401
    assert anon.post(f"/documents/{d}/delete").status_code in (302, 401)
    assert_untouched(app, d, SALARY)


def test_T15_unknown_and_forbidden_ids_are_indistinguishable(app, browser):
    """T-15 Existence oracle: a real-but-forbidden id looks exactly like a random one."""
    victor = browser("victor")
    real = victor.get(f"/documents/{doc_id(app, PRIVATE)}")
    fake = victor.get("/documents/AAAAAAAAAAAAAAAAAAAAAA")
    assert real.status_code == fake.status_code == 404
    assert real.data == fake.data
    real_api = victor.api("GET", f"/api/v1/documents/{doc_id(app, PRIVATE)}/content")
    fake_api = victor.api("GET", "/api/v1/documents/AAAAAAAAAAAAAAAAAAAAAA/content")
    assert real_api.get_json() == fake_api.get_json()


def test_T02_listing_and_search_never_show_other_peoples_documents(app, browser):
    """T-02 Data leak through list/search/filters, including category names."""
    victor = browser("victor")
    page = victor.get("/documents").data
    assert b"Salary letter" in page and b"Employee handbook" in page and b"Partner drawing" in page
    assert b"Audit papers" not in page and b"Customer contract" not in page and b"Offer letter" not in page
    assert b"Finance" not in page and b"Legal" not in page  # category dropdown is scoped too
    for query in ("?q=audit", "?owner=bob", "?category=Finance", "?q=%25", "?q=_", "?owner=b&q=papers&scope=shared"):
        assert b"Audit papers" not in victor.get("/documents" + query).data, query
    api = victor.api("GET", "/api/v1/documents?owner=bob").get_json()["documents"]
    assert {d["title"] for d in api} == {"Partner drawing - Line 4 layout"}


def test_T05_admin_cannot_read_documents_without_a_grant(app, browser):
    """T-05 Admin is an operator, not a reader: no implicit document access."""
    admin = browser("admin")
    assert admin.get("/documents").data.count(b"/download") == 0
    for title in (SALARY, PRIVATE, CONTRACT):
        d = doc_id(app, title)
        assert admin.get(f"/documents/{d}").status_code == 404
        assert admin.get(f"/documents/{d}/download").status_code == 404
        assert admin.api("GET", f"/api/v1/documents/{d}/content").status_code == 404
    inventory = admin.get("/admin/documents")
    assert inventory.status_code == 200 and b"/download" not in inventory.data


def test_T03_read_grant_cannot_change_anything(app, browser):
    """T-03 A read grant used to edit, version, delete, share, revoke or read the access log."""
    d = doc_id(app, SALARY)
    victor = browser("victor")
    assert victor.get(f"/documents/{d}").status_code == 200
    assert victor.get(f"/documents/{d}/download").status_code == 200
    for method, path, body in document_routes(d)[3:]:
        assert call(victor, method, path, body).status_code == 404, path
    for method, path, body in api_routes(d)[3:]:
        assert call(victor, method, path, body).status_code == 404, path
    assert_untouched(app, d, SALARY)


def test_T04_edit_grant_can_edit_but_not_share_delete_or_see_history(app, browser):
    """T-04 Edit holders change content but cannot escalate to owner powers."""
    d = doc_id(app, CONTRACT)
    wendy = browser("wendy")
    assert wendy.post(f"/documents/{d}/metadata", data={"title": "Customer contract - Acme (rev)", "category": "Legal"}).status_code == 302
    assert wendy.post(f"/documents/{d}/versions", data={"file": (io.BytesIO(b"PK\x03\x04bad"), "v2.docx")},
                      content_type="multipart/form-data").status_code == 302  # rejected by validation, not authz
    for method, path, body in [
        ("POST", f"/documents/{d}/grants", {"username": "victor", "permission": "read"}),
        ("POST", f"/documents/{d}/grants/wendy/revoke", {}),
        ("POST", f"/documents/{d}/delete", {}),
        ("POST", f"/documents/{d}/purge", {}),
        ("GET", f"/documents/{d}/activity", None),
        ("GET", f"/documents/{d}/suggestions", None),
    ]:
        assert call(wendy, method, path, body).status_code == 404, path
    conn = db(app)
    try:
        assert conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (d,)) == 1
        assert conn.one("SELECT deleted_at FROM documents WHERE id = ?", (d,))["deleted_at"] is None
    finally:
        conn.close()


def test_T08_revocation_is_immediate_for_an_already_open_session(app, browser):
    """T-08 Taking access away: the viewer's existing session stops working on the next request."""
    d = doc_id(app, SALARY)
    alice, victor = browser("alice"), browser("victor")
    assert victor.get(f"/documents/{d}/download").status_code == 200
    assert victor.api("GET", f"/api/v1/documents/{d}/content").status_code == 200
    assert alice.post(f"/documents/{d}/grants/victor/revoke").status_code == 302
    assert victor.get(f"/documents/{d}/download").status_code == 404
    assert victor.get(f"/documents/{d}/download?v=1").status_code == 404
    assert victor.api("GET", f"/api/v1/documents/{d}/content").status_code == 404
    assert b"Salary letter" not in victor.get("/documents").data
    assert audit_rows(app, action="revoke", document_id=d)[-1]["target"] == "victor"


def test_T08_grant_then_revoke_through_the_api(app, browser):
    d = doc_id(app, PRIVATE)
    bob, wendy = browser("bob"), browser("wendy")
    assert wendy.api("GET", f"/api/v1/documents/{d}/content").status_code == 404
    assert bob.api("PUT", f"/api/v1/documents/{d}/grants/wendy", json={"permission": "read"}).status_code == 200
    assert wendy.api("GET", f"/api/v1/documents/{d}/content").status_code == 200
    assert bob.api("DELETE", f"/api/v1/documents/{d}/grants/wendy").status_code == 200
    assert wendy.api("GET", f"/api/v1/documents/{d}/content").status_code == 404


def test_T08_expired_grant_stops_working(app, browser):
    """T-08 Time-boxed grants end on their own, without anyone revoking them."""
    from trustvault import clock
    d = doc_id(app, OFFER)
    wendy = browser("wendy")
    assert wendy.get(f"/documents/{d}/download").status_code == 200
    clock.advance(days=32)
    wendy.login("wendy")  # fresh session after the time jump (old one idled out)
    assert wendy.get(f"/documents/{d}/download").status_code == 404
    assert b"Offer letter" not in wendy.get("/documents").data


def test_T10_deleted_document_is_gone_for_grantees_and_restorable_by_owner(app, browser):
    """T-10 Deletion and recovery."""
    d = doc_id(app, HANDBOOK)
    alice, victor, bob = browser("alice"), browser("victor"), browser("bob")
    assert alice.post(f"/documents/{d}/delete").status_code == 302
    for b in (victor, bob):
        assert b.get(f"/documents/{d}").status_code == 404
        assert b.get(f"/documents/{d}/download").status_code == 404
        assert b.post(f"/documents/{d}/restore").status_code == 404
    assert alice.get(f"/documents/{d}/download").status_code == 404  # trashed: no downloads, even owner
    assert b"Employee handbook" in alice.get("/trash").data
    assert alice.get(f"/documents/{d}/activity").status_code == 200  # evidence survives deletion
    assert bob.get(f"/documents/{d}/activity").status_code == 404
    assert alice.post(f"/documents/{d}/restore").status_code == 302
    assert victor.get(f"/documents/{d}/download").status_code == 200


def test_T10_purge_destroys_ciphertext_but_keeps_audit(app, browser):
    d = doc_id(app, HANDBOOK)
    alice = browser("alice")
    assert alice.post(f"/documents/{d}/purge").status_code == 404  # must be in trash first
    alice.post(f"/documents/{d}/delete")
    assert alice.post(f"/documents/{d}/purge").status_code == 302
    conn = db(app)
    try:
        assert conn.scalar("SELECT COUNT(*) AS n FROM document_versions WHERE document_id = ? AND ciphertext IS NOT NULL", (d,)) == 0
        assert conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (d,)) == 0
    finally:
        conn.close()
    assert alice.post(f"/documents/{d}/restore").status_code == 404
    assert audit_rows(app, action="purge", document_id=d)


def test_T26_grant_validation(app, browser):
    """T-26 Grants only to real, active, non-owner people, with valid permissions."""
    d = doc_id(app, PRIVATE)
    bob = browser("bob")
    for body in ({"username": "bob", "permission": "read"},
                 {"username": "nobody", "permission": "read"},
                 {"username": "victor", "permission": "owner"},
                 {"username": "victor", "permission": "admin"},
                 {"username": "victor", "permission": "read", "expires_on": "2001-01-01"},
                 {"username": "victor", "permission": "read", "expires_on": "not-a-date"}):
        response = bob.api("PUT", f"/api/v1/documents/{d}/grants/{body['username']}", json=body)
        assert response.status_code == 400, body
    conn = db(app)
    try:
        assert conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (d,)) == 0
    finally:
        conn.close()


def test_T26_grantee_cannot_reshare(app, browser):
    """A read or edit holder cannot pass access on to someone else."""
    d = doc_id(app, HANDBOOK)
    bob = browser("bob")  # holds edit
    assert bob.api("PUT", f"/api/v1/documents/{d}/grants/admin", json={"permission": "read"}).status_code == 404
    assert browser("admin").get(f"/documents/{d}").status_code == 404


def test_T32_versions_follow_document_permission(app, browser):
    """T-32 Old versions are protected exactly like the current one."""
    d = doc_id(app, CONTRACT)
    bob = browser("bob")
    from trustvault.seed import _docx
    response = bob.post(f"/documents/{d}/versions", data={"file": (io.BytesIO(_docx(["v2"])), "acme-v2.docx")},
                        content_type="multipart/form-data")
    assert response.status_code == 302
    wendy, victor = browser("wendy"), browser("victor")
    assert wendy.get(f"/documents/{d}/download?v=1").status_code == 200
    assert wendy.get(f"/documents/{d}/download?v=2").status_code == 200
    assert wendy.get(f"/documents/{d}/download?v=9").status_code == 404
    assert victor.get(f"/documents/{d}/download?v=1").status_code == 404


def test_T28_mass_assignment_is_ignored(app, browser):
    """T-28 Extra fields such as owner_id cannot be smuggled into an update."""
    d = doc_id(app, CONTRACT)
    wendy = browser("wendy")
    response = wendy.api("PATCH", f"/api/v1/documents/{d}", json={"title": "Changed", "owner_id": 4, "owner": "wendy",
                                                                   "deleted_at": "2020", "current_version": 99})
    assert response.status_code == 200
    conn = db(app)
    try:
        row = conn.one("SELECT d.title, u.username, d.current_version FROM documents d JOIN users u ON u.id = d.owner_id WHERE d.id = ?", (d,))
    finally:
        conn.close()
    assert row == {"title": "Changed", "username": "bob", "current_version": 1}


def test_T07_role_capabilities(app, browser):
    """T-07 Role-level checks: viewers and admins cannot upload; only admins administer."""
    for who in ("victor", "admin"):
        b = browser(who)
        assert b.get("/documents/new").status_code == 403
        assert b.upload().status_code == 403
    for who in ("alice", "victor"):
        b = browser(who)
        for path in ("/admin/", "/admin/audit", "/admin/users", "/admin/documents", "/admin/audit/export.csv"):
            assert b.get(path).status_code == 403, (who, path)
        for path in ("/api/v1/admin/audit", "/api/v1/admin/users", "/api/v1/admin/dashboard"):
            assert b.api("GET", path).status_code == 403
        assert b.api("POST", "/api/v1/admin/users", json={"username": "evil", "password": "Evil#Password2026",
                                                          "role": "admin"}).status_code == 403
        assert b.api("PATCH", "/api/v1/admin/users/4", json={"role": "admin"}).status_code == 403
        assert b.post("/admin/users/4/role", data={"role": "admin"}).status_code == 403
        assert b.post("/admin/audit/verify").status_code == 403
    conn = db(app)
    try:
        assert conn.one("SELECT role FROM users WHERE username = 'victor'")["role"] == "viewer"
        assert conn.one("SELECT id FROM users WHERE username = 'evil'") is None
    finally:
        conn.close()


def test_T06_admin_has_no_password_reset_or_impersonation(app, browser):
    """T-06 There is no admin route that sets someone else's password or signs in as them."""
    admin = browser("admin")
    for path in ("/admin/users/2/password", "/admin/users/2/impersonate", "/api/v1/admin/users/2/password"):
        assert admin.post(path).status_code in (404, 405)
    response = admin.api("PATCH", "/api/v1/admin/users/2", json={"password": "Hijacked#2026x", "password_hash": "x"})
    assert response.status_code == 200
    browser().login("alice")  # alice's password unchanged


def test_T09_disabled_user_loses_access_immediately(app, browser):
    """T-09 Someone leaves the company: their open session dies on the next request."""
    app.extensions["trustvault"]["settings"].demo_mode = False
    d = doc_id(app, SALARY)
    victor, admin = browser("victor"), browser("admin")
    assert victor.get(f"/documents/{d}/download").status_code == 200
    conn = db(app)
    victor_id = conn.one("SELECT id FROM users WHERE username='victor'")["id"]
    conn.close()
    assert admin.post(f"/admin/users/{victor_id}/status", data={"active": "0"}).status_code == 302
    assert victor.get(f"/documents/{d}/download").status_code == 302  # bounced to login
    assert victor.api("GET", f"/api/v1/documents/{d}/content").status_code == 401
    retry = browser().client.post("/login", data={"username": "victor", "password": "Victor#Vault2026"})
    assert retry.status_code == 401
    bob = browser("bob")
    assert bob.api("PUT", f"/api/v1/documents/{doc_id(app, PRIVATE)}/grants/victor",
                   json={"permission": "read"}).status_code == 400  # cannot grant to a disabled account
    assert audit_rows(app, action="user_disabled")[-1]["target"] == "victor"


def test_T40_demo_accounts_are_protected_in_demo_mode(app, browser):
    admin = browser("admin")
    conn = db(app)
    alice_id = conn.one("SELECT id FROM users WHERE username='alice'")["id"]
    conn.close()
    admin.post(f"/admin/users/{alice_id}/status", data={"active": "0"})
    browser("alice")  # still able to sign in


def test_T29_upload_quota_and_rate(app, browser):
    """T-29 Storage exhaustion: per-user quota and hourly upload cap."""
    settings = app.extensions["trustvault"]["settings"]
    settings.uploads_per_hour = 3
    alice = browser("alice")
    statuses = [alice.upload(title=f"Note {i}").status_code for i in range(4)]
    assert statuses[-1] == 429
    settings.uploads_per_hour = 100
    settings.user_quota_mb = 0
    assert alice.upload(title="Too much").status_code == 400


def test_T07_admin_api_requires_real_booleans(app, browser):
    app.extensions["trustvault"]["settings"].demo_mode = False
    admin = browser("admin")
    conn = db(app)
    vid = conn.one("SELECT id FROM users WHERE username='victor'")["id"]
    conn.close()
    assert admin.api("PATCH", f"/api/v1/admin/users/{vid}", json={"is_active": "false"}).status_code == 400
    assert admin.api("PATCH", f"/api/v1/admin/users/{vid}", json={"is_active": False}).status_code == 200
    assert browser().client.post("/login", data={"username": "victor", "password": "Victor#Vault2026"}).status_code == 401
