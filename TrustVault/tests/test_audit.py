"""Audit trail: completeness and tamper evidence. Threat ids refer to THREATS.md."""
import hashlib
import json

import pytest

from conftest import audit_rows, db, doc_id


def verify(app):
    tv = app.extensions["trustvault"]
    conn = tv["db"].connect()
    try:
        return tv["audit"].verify_chain(conn)
    finally:
        conn.close()


def drop_triggers(conn):
    if conn.kind == "sqlite":
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("DROP TRIGGER audit_events_no_delete")
    else:
        conn.execute("DROP TRIGGER audit_events_no_update ON audit_events")
        conn.execute("DROP TRIGGER audit_events_no_delete ON audit_events")


def test_T21_refused_attempts_are_recorded_with_who_what_where(app, browser):
    """T-21 'Prove who reached it, including attempts that were refused.'"""
    d = doc_id(app, "Audit papers")
    victor = browser("victor")
    victor.get(f"/documents/{d}/download")
    victor.api("PUT", f"/api/v1/documents/{d}/grants/victor", json={"permission": "edit"})
    events = audit_rows(app, action="access_denied", document_id=d)
    assert len(events) == 2
    for event in events:
        assert event["actor_username"] == "victor" and event["actor_role"] == "viewer"
        assert event["outcome"] == "denied" and event["ip"]
    attempted = {json.loads(e["details"])["attempted"] for e in events}
    assert attempted == {"download", "manage_grants"}
    # unknown ids are recorded too (scanning shows up even when nothing exists)
    victor.get("/documents/ZZZZZZZZZZZZZZZZZZZZZZ/download")
    assert audit_rows(app, action="access_denied", document_id="ZZZZZZZZZZZZZZZZZZZZZZ")


def test_T21_successful_access_and_permission_changes_are_recorded(app, browser):
    d = doc_id(app, "Audit papers")
    bob, wendy = browser("bob"), browser("wendy")
    bob.post(f"/documents/{d}/grants", data={"username": "wendy", "permission": "read"})
    wendy.get(f"/documents/{d}/download")
    bob.post(f"/documents/{d}/grants/wendy/revoke")
    wendy.get(f"/documents/{d}/download")
    actions = [(e["actor_username"], e["action"], e["outcome"]) for e in audit_rows(app, document_id=d)]
    assert actions[-4:] == [("bob", "grant", "success"), ("wendy", "download", "success"),
                            ("bob", "revoke", "success"), ("wendy", "access_denied", "denied")]
    assert verify(app)["ok"]


def test_T21_owner_sees_who_accessed_their_document(app, browser):
    d = doc_id(app, "Salary letter")
    browser("victor").get(f"/documents/{d}/download")
    browser("wendy").get(f"/documents/{d}/download")  # refused
    page = browser("alice").get(f"/documents/{d}/activity").data
    assert b"victor" in page and b"wendy" in page and b"access_denied" in page


def test_T22_database_refuses_update_and_delete_of_audit_rows(app):
    """T-22 Append-only enforced by the database itself, not only by the app."""
    conn = db(app)
    try:
        with pytest.raises(Exception):
            conn.execute("UPDATE audit_events SET actor_username = 'someone-else' WHERE seq = 1")
        with pytest.raises(Exception):
            conn.execute("DELETE FROM audit_events WHERE seq = 1")
    finally:
        conn.close()
    assert verify(app)["ok"]


def test_T22_edited_row_is_detected_even_if_triggers_are_bypassed(app, browser):
    browser("victor").get(f"/documents/{doc_id(app, 'Audit papers')}/download")
    target = audit_rows(app, action="access_denied")[-1]["seq"]
    conn = db(app)
    try:
        drop_triggers(conn)
        conn.execute("UPDATE audit_events SET actor_username = 'alice' WHERE seq = ?", (target,))
    finally:
        conn.close()
    result = verify(app)
    assert not result["ok"] and result["broken_at"] == target and "HMAC" in result["reason"]
    page = browser("admin").post("/admin/audit/verify").data
    assert b"Tampering detected" in page


def test_T22_recomputing_hashes_without_the_key_does_not_help(app, browser):
    """The starter used plain SHA-256: anyone with DB access could recompute it. HMAC needs a key the DB never sees."""
    conn = db(app)
    try:
        drop_triggers(conn)
        row = conn.one("SELECT * FROM audit_events WHERE seq = 2")
        forged = dict(row, actor_username="nobody")
        payload = {k: forged[k] for k in ("seq", "event_time", "actor_id", "actor_username", "actor_role", "ip",
                                          "action", "outcome", "document_id", "target", "details", "prev_hash")}
        fake_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        conn.execute("UPDATE audit_events SET actor_username = 'nobody', event_hash = ? WHERE seq = 2", (fake_hash,))
        conn.execute("UPDATE audit_events SET prev_hash = ? WHERE seq = 3", (fake_hash,))
    finally:
        conn.close()
    result = verify(app)
    assert not result["ok"] and result["broken_at"] == 2


def test_T22_deleted_row_is_detected(app):
    conn = db(app)
    try:
        drop_triggers(conn)
        conn.execute("DELETE FROM audit_events WHERE seq = 3")
    finally:
        conn.close()
    result = verify(app)
    assert not result["ok"] and result["broken_at"] == 3 and "gap" in result["reason"]


def test_T22_audit_lines_are_also_shipped_to_stdout(app, browser, capsys):
    """Second, independent copy of every event in the host's log store."""
    app.extensions["trustvault"]["audit"].to_stdout = True
    browser("victor").get(f"/documents/{doc_id(app, 'Audit papers')}/download")
    out = capsys.readouterr().out
    lines = [json.loads(line)["audit"] for line in out.splitlines() if line.startswith('{"audit"')]
    assert any(e["action"] == "access_denied" and e["actor_username"] == "victor" and e["event_hash"] for e in lines)


def test_T23_audit_is_admin_only_and_owner_sees_only_their_documents(app, browser):
    for who in ("alice", "victor"):
        assert browser(who).get("/admin/audit").status_code == 403
        assert browser(who).api("GET", "/api/v1/admin/audit").status_code == 403
    alice = browser("alice")
    assert alice.get(f"/documents/{doc_id(app, 'Customer contract')}/activity").status_code == 404
    assert browser("admin").api("GET", "/api/v1/admin/audit?outcome=denied").status_code == 200


def test_T23_audit_reads_and_exports_are_themselves_audited(app, browser):
    admin = browser("admin")
    admin.get("/admin/audit")
    admin.get("/admin/audit/export.csv")
    admin.post("/admin/audit/verify")
    actions = {e["action"] for e in audit_rows(app, actor_username="admin")}
    assert {"read_audit", "export_audit", "verify_audit"} <= actions


def test_T23_csv_export_neutralises_formulas(app, browser):
    browser().client.post("/login", data={"username": "=cmd|' /C calc'!A0", "password": "x"})
    csv_text = browser("admin").get("/admin/audit/export.csv").data.decode()
    assert ",'=cmd" in csv_text and ",=cmd" not in csv_text


def test_T21_admin_dashboard_flags_probing(app, browser):
    victor = browser("victor")
    for _ in range(3):
        victor.get(f"/documents/{doc_id(app, 'Audit papers')}/download")
    page = browser("admin").get("/admin/").data
    assert b"victor was refused" in page


def test_T22_concurrent_writers_do_not_fork_the_chain(app):
    """The starter read the last hash and inserted without a lock, so parallel requests could
    fork the chain. Appends are now serialised (BEGIN IMMEDIATE / advisory lock)."""
    import threading

    tv = app.extensions["trustvault"]
    errors = []

    def worker(n):
        conn = tv["db"].connect()
        try:
            for i in range(15):
                tv["audit"].record(conn, action="load_test", actor=None, actor_name_hint=f"thread{n}", details={"i": i})
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    result = verify(app)
    assert result["ok"], result
    assert len(audit_rows(app, action="load_test")) == 90


def test_T21_anonymous_attempts_are_recorded(app, browser):
    d = doc_id(app, "Salary letter")
    anon = browser()
    anon.get(f"/documents/{d}/download")
    anon.api("GET", f"/api/v1/documents/{d}/content")
    events = audit_rows(app, action="access_denied", document_id=d)
    assert len(events) == 2 and all(e["actor_username"] == "anonymous" for e in events)
