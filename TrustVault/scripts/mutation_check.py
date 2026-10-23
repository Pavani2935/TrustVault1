"""Remove one security check at a time and prove the test suite notices.

The challenge says: "We will take one authorisation check out of your code and run your
tests. If they still pass, they were not testing anything." This script does exactly
that for every check we know about, in a throw-away copy of the project.

    python scripts/mutation_check.py            # all mutations
    python scripts/mutation_check.py M03 M07    # selected ones

Exit code 0 means every mutation was caught ("killed") by at least one failing test.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# id, description, file, original text, replacement
MUTATIONS = [
    ("M01", "grant lookup ignored: any signed-in user is a reader", "trustvault/authz.py",
     "    if not grant:\n        return None\n", "    if not grant:\n        return \"read\"\n"),
    ("M02", "admin bypass added (the starter's design)", "trustvault/authz.py",
     "    if doc[\"owner_id\"] == user[\"id\"]:\n        return \"owner\"\n",
     "    if doc[\"owner_id\"] == user[\"id\"] or user[\"role\"] == \"admin\":\n        return \"owner\"\n"),
    ("M03", "grant expiry not enforced", "trustvault/authz.py",
     "    if grant[\"expires_at\"] and grant[\"expires_at\"] <= clock.now_iso():\n        return None\n", ""),
    ("M04", "deleted documents keep their grants", "trustvault/authz.py",
     "    if doc.get(\"deleted_at\"):\n        return None  # grants", "    if False:\n        return None  # grants"),
    ("M05", "permission level not compared (read can edit/delete/share)", "trustvault/authz.py",
     "    return LEVEL[permission] >= LEVEL[required], permission",
     "    return permission is not None, permission"),
    ("M06", "disabled accounts still authorised", "trustvault/authz.py",
     "    if not user or not doc or not user.get(\"is_active\"):", "    if not user or not doc:"),
    ("M07", "download does not authorise at all", "trustvault/documents.py",
     "        doc, _ = _authorize(ctx, doc_id, \"download\")",
     "        doc = ctx.conn.one(\"SELECT * FROM documents WHERE id = ?\", (doc_id,))"),
    ("M08", "grant endpoint checks 'view' instead of owner", "trustvault/documents.py",
     "        doc, _ = _authorize(ctx, doc_id, \"manage_grants\")\n        if permission not in",
     "        doc, _ = _authorize(ctx, doc_id, \"view\")\n        if permission not in"),
    ("M09", "revoke endpoint checks 'view' instead of owner", "trustvault/documents.py",
     "        _authorize(ctx, doc_id, \"manage_grants\")\n        target = ctx.conn.one(\"SELECT id, username FROM",
     "        _authorize(ctx, doc_id, \"view\")\n        target = ctx.conn.one(\"SELECT id, username FROM"),
    ("M10", "delete checks 'edit' instead of owner", "trustvault/documents.py",
     "        _authorize(ctx, doc_id, \"delete\")", "        _authorize(ctx, doc_id, \"edit_metadata\")"),
    ("M11", "metadata edit checks 'view'", "trustvault/documents.py",
     "        doc, _ = _authorize(ctx, doc_id, \"edit_metadata\")\n        ctx.conn.execute(\"UPDATE documents SET title",
     "        doc, _ = _authorize(ctx, doc_id, \"view\")\n        ctx.conn.execute(\"UPDATE documents SET title"),
    ("M12", "document detail does not authorise", "trustvault/documents.py",
     "        doc, permission = _authorize(ctx, doc_id, \"view\")",
     "        doc = ctx.conn.one(\"SELECT * FROM documents WHERE id = ?\", (doc_id,)); permission = \"read\""),
    ("M13", "search: per-row policy re-check removed", "trustvault/documents.py",
     "        if allowed:  # defence in depth", "        if True:  # defence in depth"),
    ("M14", "access log open to readers", "trustvault/documents.py",
     "        _authorize(ctx, doc_id, \"view_access_log\")\n        ctx.log(", "        _authorize(ctx, doc_id, \"view\")\n        ctx.log("),
    ("M15", "denied attempts not audited", "trustvault/documents.py",
     "            ctx.log(\"access_denied\", outcome=\"denied\"", "            (lambda *a, **k: None)(\"access_denied\", outcome=\"denied\""),
    ("M16", "CSRF token not checked", "trustvault/__init__.py",
     "                if not auth.csrf_valid(g.session, submitted):", "                if False:"),
    ("M17", "Origin header not checked", "trustvault/__init__.py",
     "            if not _same_origin():", "            if False:"),
    ("M18", "logout leaves the session alive", "trustvault/auth.py",
     "    if token:\n        ctx.conn.execute(\"DELETE FROM sessions WHERE token_hash = ?\", (_token_hash(token),))",
     "    if token:\n        pass"),
    ("M19", "disabled user's session keeps working", "trustvault/auth.py",
     "    if not user or not user[\"is_active\"]:\n        end_reason = \"account disabled\"",
     "    if not user:\n        end_reason = \"account disabled\""),
    ("M20", "idle timeout removed", "trustvault/auth.py",
     "    elif row[\"last_seen_at\"] < idle_cutoff:", "    elif False:"),
    ("M21", "login throttling removed", "trustvault/auth.py",
     "    if int(pair_failures) >= s.login_max_failures:", "    if False:"),
    ("M22", "user admin open to everyone", "trustvault/users.py",
     "    if not authz.has_capability(ctx.user, \"manage_users\"):", "    if False:"),
    ("M23", "audit/oversight open to everyone", "trustvault/reports.py",
     "    if not authz.has_capability(ctx.user, capability):", "    if False:"),
    ("M24", "audit HMAC not verified", "trustvault/audit.py",
     "                if not hmac.compare_digest(self._digest(row), row[\"event_hash\"]):", "                if False:"),
    ("M25", "audit append-only trigger removed (SQLite)", "trustvault/schema/sqlite.sql",
     "CREATE TRIGGER IF NOT EXISTS audit_events_no_update", "CREATE TRIGGER IF NOT EXISTS audit_events_disabled_x\nAFTER INSERT ON users BEGIN SELECT 1; END;\nCREATE TRIGGER IF NOT EXISTS audit_events_unused"),
    ("M26", "file signature (magic bytes) not checked", "trustvault/validation.py",
     "    checker(data)\n", "    pass\n"),
    ("M27", "macro-enabled Office files accepted", "trustvault/validation.py",
     "                if any(n.lower().endswith((\"vbaproject.bin\", \".bin\")) for n in names):", "                if False:"),
    ("M28", "viewer can upload", "trustvault/documents.py",
     "    if not authz.has_capability(ctx.user, \"upload\"):", "    if False:"),
    ("M29", "suggestions open to non-owners", "trustvault/authz.py",
     "    \"suggest_access\": \"owner\",", "    \"suggest_access\": \"read\","),
    ("M30", "audit chain appends not serialised (SQLite)", "trustvault/db.py",
     "                self.raw.execute(\"BEGIN IMMEDIATE\")", "                self.raw.execute(\"BEGIN DEFERRED\")"),
    ("M31", "download served inline with client-controlled type", "trustvault/web.py",
     "    response = send_file(io.BytesIO(data), mimetype=version[\"content_type\"], as_attachment=True,",
     "    response = send_file(io.BytesIO(data), mimetype=\"text/html\", as_attachment=False,"),
    ("M32", "grant to inactive users allowed", "trustvault/documents.py",
     "        if not target or not target[\"is_active\"]:", "        if not target:"),
    ("M33", "password change does not end other sessions", "trustvault/auth.py",
     "    elif row[\"created_at\"] < user[\"password_changed_at\"]:", "    elif False:"),
]


def run(selected: set[str]) -> int:
    survivors = []
    for mid, description, rel, old, new in MUTATIONS:
        if selected and mid not in selected:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "proj"
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", ".venv", "venv", "instance",
                                                                       "__pycache__", ".pytest_cache"))
            target = copy / rel
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"{mid}  ERROR  mutation text not found exactly once in {rel}")
                survivors.append(mid)
                continue
            target.write_text(text.replace(old, new), encoding="utf-8")
            result = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                                    cwd=copy, capture_output=True, text=True)
            killed = result.returncode != 0
            failing = next((line for line in result.stdout.splitlines() if line.startswith("FAILED")), "")
            print(f"{mid}  {'KILLED  ' if killed else 'SURVIVED'}  {description}" + (f"\n        by {failing[7:]}" if failing else ""))
            if not killed:
                survivors.append(mid)
    print()
    if survivors:
        print("Mutations NOT caught by the tests:", ", ".join(survivors))
        return 1
    print("Every removed check was caught by at least one failing test.")
    return 0


if __name__ == "__main__":
    sys.exit(run(set(sys.argv[1:])))
