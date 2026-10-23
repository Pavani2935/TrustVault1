"""Authentication, sessions and cross-site request forgery. Threat ids refer to THREATS.md."""
from conftest import PASSWORDS, audit_rows, db, doc_id

from trustvault import clock


def cookie_value(b):
    for name in ("tv_session", "__Host-tv_session"):
        cookie = b.client.get_cookie(name)
        if cookie:
            return cookie.value
    return None


def test_T11_logout_kills_the_session_server_side(app, browser):
    """T-11 A copied cookie must not work after logout (no stateless signed sessions)."""
    victor = browser("victor")
    stolen = cookie_value(victor)
    victor.post("/logout")
    attacker = browser()
    attacker.client.set_cookie("tv_session", stolen)
    assert attacker.get("/documents").status_code == 302
    assert attacker.api("GET", "/api/v1/me").status_code == 401


def test_T11_forged_cookie_is_useless(app, browser):
    attacker = browser()
    for value in ("1", "admin", "eyJ1aWQiOjF9.forged.sig", "A" * 43, "x" * 500):
        attacker.client.set_cookie("tv_session", value)
        assert attacker.api("GET", "/api/v1/me").status_code == 401


def test_T11_login_issues_a_fresh_session(app, browser):
    """Session fixation: a cookie planted before login is not reused after login."""
    b = browser("victor")
    first = cookie_value(b)
    b.login("victor")
    second = cookie_value(b)
    assert first != second
    old = browser()
    old.client.set_cookie("tv_session", first)
    assert old.api("GET", "/api/v1/me").status_code == 401


def test_T11_idle_and_absolute_timeouts(app, browser):
    victor = browser("victor")
    clock.advance(minutes=31)
    assert victor.api("GET", "/api/v1/me").status_code == 401
    victor.login("victor")
    for _ in range(20):  # stay active, but the absolute limit still ends it
        clock.advance(minutes=25)
        victor.api("GET", "/api/v1/me")
    assert victor.api("GET", "/api/v1/me").status_code == 401


def test_T11_password_change_ends_other_sessions(app, browser):
    app.extensions["trustvault"]["settings"].demo_mode = False
    laptop, phone = browser("victor"), browser("victor")
    response = laptop.post("/account", data={"current": PASSWORDS["victor"], "new": "N3w-Secret#Pass"})
    assert response.status_code == 302
    assert phone.api("GET", "/api/v1/me").status_code == 401
    laptop.refresh_csrf()
    assert laptop.api("GET", "/api/v1/me").status_code == 200  # this browser got a fresh session
    assert browser().client.post("/login", data={"username": "victor", "password": PASSWORDS["victor"]}).status_code == 401


def test_T11_admin_can_end_someones_sessions(app, browser):
    victor, admin = browser("victor"), browser("admin")
    conn = db(app)
    vid = conn.one("SELECT id FROM users WHERE username='victor'")["id"]
    conn.close()
    assert admin.api("POST", f"/api/v1/admin/users/{vid}/sessions/end").get_json()["sessions_ended"] >= 1
    assert victor.api("GET", "/api/v1/me").status_code == 401


def test_T11_cookie_flags(app, browser):
    response = browser().client.post("/login", data={"username": "victor", "password": PASSWORDS["victor"]})
    header = response.headers["Set-Cookie"]
    assert "HttpOnly" in header and "SameSite=Lax" in header and "Path=/" in header


def test_T12_state_change_without_csrf_token_is_refused(app, browser):
    """T-12 CSRF: a forged form post from another site carries the cookie but not the token."""
    d = doc_id(app, "Salary letter")
    alice = browser("alice")
    for path, body in ((f"/documents/{d}/grants", {"username": "wendy", "permission": "edit"}),
                       (f"/documents/{d}/grants/victor/revoke", {}),
                       (f"/documents/{d}/delete", {}),
                       ("/logout", {})):
        assert alice.post(path, data=body, csrf=False).status_code == 403, path
        assert alice.post(path, data={**body, "csrf_token": "guess"}, csrf=False).status_code == 403
    assert alice.api("DELETE", f"/api/v1/documents/{d}", csrf=False).status_code == 403
    conn = db(app)
    try:
        assert conn.one("SELECT deleted_at FROM documents WHERE id = ?", (d,))["deleted_at"] is None
        assert not conn.one("SELECT 1 AS x FROM grants g JOIN users u ON u.id=g.user_id WHERE g.document_id=? AND u.username='wendy'", (d,))
    finally:
        conn.close()
    assert len(audit_rows(app, action="csrf_rejected")) >= 9


def test_T12_token_from_another_session_is_refused(app, browser):
    d = doc_id(app, "Salary letter")
    alice, mallory = browser("alice"), browser("victor")
    assert alice.post(f"/documents/{d}/delete", data={"csrf_token": mallory.csrf}, csrf=False).status_code == 403


def test_T12_cross_origin_request_is_refused_even_with_token(app, browser):
    d = doc_id(app, "Salary letter")
    alice = browser("alice")
    response = alice.post(f"/documents/{d}/delete", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    login = browser().client.post("/login", data={"username": "alice", "password": PASSWORDS["alice"]},
                                  headers={"Origin": "https://evil.example"})
    assert login.status_code == 403  # login CSRF
    assert audit_rows(app, action="origin_rejected")


def test_T13_login_throttling_per_account_and_address(app, browser):
    """T-13 Password guessing: locked after 5 failures from one address, not from others."""
    attacker = browser()
    for _ in range(5):
        assert attacker.client.post("/login", data={"username": "alice", "password": "wrong-password"}).status_code == 401
    blocked = attacker.client.post("/login", data={"username": "alice", "password": PASSWORDS["alice"]})
    assert blocked.status_code == 429  # correct password, still refused while throttled
    other = browser()
    ok = other.client.post("/login", data={"username": "alice", "password": PASSWORDS["alice"]},
                           environ_base={"REMOTE_ADDR": "10.9.9.9"})
    assert ok.status_code == 302  # the real alice, elsewhere, is not locked out
    assert any("throttled" in r["details"] for r in audit_rows(app, action="login", outcome="denied"))
    clock.advance(minutes=16)
    assert attacker.client.post("/login", data={"username": "alice", "password": PASSWORDS["alice"]}).status_code == 302


def test_T13_password_spraying_from_one_address(app, browser):
    settings = app.extensions["trustvault"]["settings"]
    settings.login_ip_max_failures = 6
    attacker = browser()
    for i in range(6):
        attacker.client.post("/login", data={"username": f"user{i}", "password": "Spring2026!"})
    assert attacker.client.post("/login", data={"username": "victor", "password": PASSWORDS["victor"]}).status_code == 429


def test_T14_login_does_not_reveal_which_usernames_exist(app, browser):
    b = browser()
    unknown = b.client.post("/login", data={"username": "nosuchuser", "password": "whatever-password"})
    wrong = b.client.post("/login", data={"username": "alice", "password": "whatever-password"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.data == wrong.data


def test_T20_login_next_cannot_redirect_off_site(app, browser):
    for target in ("https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)",
                   "/%09/evil.example", "/%0A/evil.example", "/ /evil.example"):
        response = browser().client.post("/login?next=" + target,
                                         data={"username": "victor", "password": PASSWORDS["victor"]})
        assert response.status_code == 302
        location = response.headers["Location"]
        assert "evil" not in location and not location.startswith("javascript"), location


def test_T33_get_cannot_change_state(app, browser):
    d = doc_id(app, "Salary letter")
    alice = browser("alice")
    assert alice.get(f"/documents/{d}/delete").status_code == 405
    assert alice.get(f"/documents/{d}/grants/victor/revoke").status_code == 405
    assert alice.get("/logout").status_code == 405
    assert browser("victor").get(f"/documents/{d}").status_code == 200


def test_T12_real_browser_origin_headers(app, browser):
    """Regression: with Referrer-Policy no-referrer, Chrome sent 'Origin: null' on our own login
    form and every sign-in was refused. Same-origin must pass; 'null' and foreign origins must not."""
    ok = browser().client.post("/login", data={"username": "victor", "password": PASSWORDS["victor"]},
                               headers={"Origin": "http://localhost"})
    assert ok.status_code == 302
    for origin in ("null", "http://localhost.evil.example", "http://evil.example"):
        refused = browser().client.post("/login", data={"username": "victor", "password": PASSWORDS["victor"]},
                                        headers={"Origin": origin})
        assert refused.status_code == 403, origin
