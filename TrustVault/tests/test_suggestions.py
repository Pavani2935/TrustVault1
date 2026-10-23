"""AI-style access suggestions must never widen access by themselves. See THREATS.md T-25."""
import json

from conftest import audit_rows, db, doc_id


def grant_count(app, d):
    conn = db(app)
    try:
        return conn.scalar("SELECT COUNT(*) AS n FROM grants WHERE document_id = ?", (d,))
    finally:
        conn.close()


def test_T25_suggestions_are_shown_and_audited_but_never_applied(app, browser):
    alice = browser("alice")
    alice.upload(title="Appraisal cycle 2026", category="HR")
    d = doc_id(app, "Appraisal cycle")
    response = alice.api("GET", f"/api/v1/documents/{d}/suggestions")
    suggested = [s["username"] for s in response.get_json()["suggestions"]]
    assert set(suggested) == {"victor", "wendy", "bob"}  # people alice already shares HR documents with
    assert grant_count(app, d) == 0
    assert browser("victor").get(f"/documents/{d}").status_code == 404
    event = audit_rows(app, action="access_suggested", document_id=d)[-1]
    assert {s["user"] for s in json.loads(event["details"])["suggested"]} == {"victor", "wendy", "bob"}


def test_T25_accepting_a_suggestion_is_a_recorded_human_decision(app, browser):
    alice = browser("alice")
    alice.upload(title="Appraisal cycle 2026", category="HR")
    d = doc_id(app, "Appraisal cycle")
    alice.get(f"/documents/{d}/suggestions")
    alice.post(f"/documents/{d}/grants", data={"username": "victor", "permission": "read", "source": "suggestion",
                                               "reason": "you share 2 other 'HR' document(s) with them"})
    alice.post(f"/documents/{d}/suggestions/dismiss", data={"username": "wendy"})
    grant = audit_rows(app, action="grant", document_id=d)[-1]
    details = json.loads(grant["details"])
    assert grant["actor_username"] == "alice" and details["source"] == "suggestion" and details["suggestion"]["user"] == "victor"
    assert audit_rows(app, action="suggestion_dismissed", document_id=d)[-1]["target"] == "wendy"
    assert grant_count(app, d) == 1
    assert browser("wendy").get(f"/documents/{d}").status_code == 404


def test_T25_suggestions_only_learn_from_the_owners_own_sharing(app, browser):
    """Bob never shared HR documents, so he must not be told who can see Alice's HR files."""
    bob = browser("bob")
    bob.upload(title="Bob HR note", category="HR")
    d = doc_id(app, "Bob HR note")
    assert bob.api("GET", f"/api/v1/documents/{d}/suggestions").get_json()["suggestions"] == []


def test_T25_only_the_owner_can_ask_for_suggestions(app, browser):
    d = doc_id(app, "Employee handbook")
    for who in ("bob", "victor", "admin"):  # bob has edit, victor read, admin nothing
        assert browser(who).api("GET", f"/api/v1/documents/{d}/suggestions").status_code == 404
