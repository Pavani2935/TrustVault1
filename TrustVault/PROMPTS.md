# PROMPTS.md: how AI was used, and where it was wrong

AI assistants were used throughout: to generate a first prototype, to review it adversarially, to rebuild it, and to write tests. Every entry below records something the AI produced that was **wrong**, how it was noticed, and what replaced it. Entries are dated on the day they happened. Commit links are added as the work is pushed.

> Entry format: **Asked** · **Produced** · **What was wrong** · **What I did instead** · **Commit**

---

## 2026-10-23 · 1. The generated prototype: authorisation looked right but wasn't *(access control)*

**Asked.** "Build TrustVault: Flask, three roles, per-document read/edit grants, encrypted storage, hash-chained audit trail, tests that one user can't reach another's documents."

**Produced.** A single-file Flask app with a `require_document` decorator, Fernet-encrypted files on disk, a SHA-256 audit chain and six tests. It looked complete.

**What was wrong.** A route-by-route review against the brief ("the server decides, every time, through any route") found:

- `app.secret_key = os.environ.get("TRUSTVAULT_SECRET", "dev-only-change-me")`. Flask sessions are signed cookies holding `uid`. If the variable is ever missing on the host, anyone can sign `{"uid": 1}` with the public default and become the administrator. That would be a total breach caused by one missing setting.
- `permission_for()` returned `"owner"` for any admin. Administrators could read every document. This contradicts "reachable only by someone who was granted it".
- The search page ran `SELECT DISTINCT category FROM documents` with no scope, so every user saw every other user's category names.
- No CSRF protection on grant, revoke or delete.
- The grant and revoke routes had no negative tests, so deleting their ownership check would have passed the whole suite.

**What I did instead.**
- Rebuilt around a single policy function (`authz.is_allowed`) with default deny, called through one gate (`documents._authorize`) by both the UI and a new JSON API.
- Removed the admin bypass: admins oversee, they don't read.
- Made production refuse to start without secrets, and dropped Flask's signed-cookie session entirely.
- Scoped categories to visible documents.
- Added synchronizer CSRF tokens and an Origin check.
- Wrote `test_T01_*`, which hits every document route for four users over both the UI and the API.

**Commit:** _add link_

## 2026-10-23 · 2. The audit chain could be rewritten by anyone with the database *(audit trail)*

**Asked.** "Make the audit trail tamper-evident."

**Produced.** `event_hash = sha256(json(fields) + previous_hash)`, verified on the admin page. It was described as tamper-evident.

**What was wrong.**
1. The hash used no secret. Anyone who can edit a row can recompute every hash after it, and the chain still verifies. The brief asks "what stops that?", and for this design the answer was "nothing".
2. It read the last hash and inserted the next event without a lock, so two simultaneous requests could chain off the same parent and fork the log.
3. Nothing in the database stopped `UPDATE` or `DELETE`.
4. Deleting the newest rows left a valid-looking shorter chain.

**What I did instead.**
- HMAC-SHA256 keyed with `TRUSTVAULT_AUDIT_KEY`, which lives only in the host's secret store.
- Contiguous sequence numbers covered by the HMAC, so gaps are detected.
- Appends serialised with `BEGIN IMMEDIATE` (SQLite) or `pg_advisory_xact_lock` (PostgreSQL).
- Triggers that reject UPDATE, DELETE and TRUNCATE.
- Every event also printed to the platform log as an independent copy.
- Audit writes moved into the same transaction as the change they describe.

**How I checked.**
- `test_T22_recomputing_hashes_without_the_key_does_not_help` performs exactly the old attack and now fails verification.
- `test_T22_concurrent_writers_do_not_fork_the_chain` runs 6 threads × 15 events.
- Mutations M24, M25 and M30 confirm that each protection is load-bearing.

**Commit:** _add link_

## 2026-10-23 · 3. "Revocation is immediate" was only half true *(access control / sessions)*

**Asked.** "Make sure revoking access works immediately."

**Produced.** The revoke route deleted the grant row and the tests confirmed the next request got a 404. True for grants.

**What was wrong.** The brief says *"whatever you have issued to that person before that moment stops working."* The prototype issued stateless signed cookies:
- Logging out didn't invalidate the cookie. A copied cookie kept working until it expired.
- There was no way to disable a leaver's account at all.
- There was no session timeout.

**What I did instead.**
- Server-side sessions: a random token in the cookie and only its SHA-256 in the database.
- Logout, disabling a user, an admin "sign out everywhere" and a password change each delete or refuse sessions on the next request.
- Idle and absolute timeouts.
- Session rotation on login.
- Grant expiry dates checked at request time.

Tests: `test_T11_logout_kills_the_session_server_side` replays a stolen cookie after logout; `test_T09_*` disables a user mid-session.

**Commit:** _add link_

## 2026-10-23 · 4. Upload validation trusted the filename *(input validation)*

**Asked.** "Validate uploads."

**Produced.** An extension allow-list plus a check that the client-supplied MIME type wasn't `application/x-msdownload`.

**What was wrong.**
- The client controls both the extension and the MIME type, so an `.exe` renamed to `invoice.pdf` was accepted.
- The download used `mimetypes.guess_type(filename)`, so the served type also came from user input.
- No macro, zip-bomb or PDF-script checks.

**What I did instead.**
- The server decides the type from the bytes: PDF header and trailer, PNG/JPEG magic, OOXML structure, UTF-8 text.
- Rejects macros, `.bin` parts, high-ratio archives and PDF `/JavaScript`, `/Launch` and `/EmbeddedFile`.
- Stores the server-decided content type.
- Always serves downloads as attachments with `nosniff` and a sandbox CSP.

Tests: 15 hostile files in `test_T16_*`.

**Commit:** _add link_

## 2026-10-23 · 5. The deployment advice would have lost all data *(deployment)*

**Asked.** "How do I deploy this to Render?"

**Produced.** "Use `gunicorn app:app`; on Render use a persistent disk." The app stored SQLite and the Fernet key file under `instance/`, and generated a new key if the file was missing.

**What was wrong.**
- Free Render services can't have persistent disks. The filesystem is wiped on every restart and spin-down. All documents and the audit trail would have vanished after 15 idle minutes.
- A fresh encryption key would have been generated on the next boot, making any surviving ciphertext unreadable.
- `gunicorn` doesn't run on Windows, which is where I develop.

**What I did instead.**
- PostgreSQL support behind a small adapter, with files stored encrypted in the database.
- A `render.yaml` Blueprint that creates the database and generates both secrets.
- `waitress` as the server, since it runs on Windows and Linux.
- `.bat` scripts for setup, run, test and publish.
- `scripts/live_check.py` to verify the deployed URL from outside.

The full suite now runs on SQLite and PostgreSQL.

**Commit:** _add link_

## 2026-10-23 · 6. The new test suite passed even with security checks removed *(authorisation tests)*

**Asked.** "Write tests for every threat in THREATS.md."

**Produced.** About 95 tests, all passing.

**What was wrong.** I wrote `scripts/mutation_check.py` to do what the judges will do: delete one check and re-run the tests. **5 of 33 mutations survived:**
- M04: deleted documents keep their grants.
- M06: the policy ignores disabled accounts.
- M13: the search per-row re-check removed.
- M19: the session layer ignores disabled accounts.
- M33: password change doesn't invalidate older sessions.

Each survived because a *second* layer still blocked the attack end-to-end. For example, disabling a user both deletes their sessions and makes the policy refuse them. The tests proved the system was safe, but they didn't prove that each check mattered. If one layer were later removed, nothing would notice until the other one also broke.

**What I did instead.** Added `tests/test_policy_layers.py`, which tests each layer in isolation:
- The policy with an inactive user who still has a grant.
- A session row that survives a disable.
- A widened listing query, with the per-row check expected to hide the extra rows.
- And so on for the other two survivors.

All 33 mutations are now killed, and CI runs the mutation check on every push.

**Commit:** _add link_

## 2026-10-23 · 7. Header hardening broke sign-in in real browsers *(CSRF / Origin check)*

**Asked.** "Add strict security headers."

**Produced.** `Referrer-Policy: no-referrer`, alongside the new rule that state-changing requests must have a same-origin `Origin` header, with `Origin: null` refused.

**What was wrong.** With `no-referrer`, Chromium sends `Origin: null` on form POSTs, so **every sign-in from a real browser returned 403 "Cross-site request blocked"**. All automated tests passed, because Flask's test client sends no Origin header. I only noticed when I ran the production-mode build and drove it with a headless browser, screenshotting each page.

**What I did instead.**
- `Referrer-Policy: same-origin`. This still keeps document ids out of the Referer header sent to other sites.
- Kept refusing `null`.
- Added `test_T12_real_browser_origin_headers` with real-browser Origin values.

**Lesson:** I now load every page in a real browser before calling a security change done.

**Commit:** _add link_

## 2026-10-23 · 8. JSON clients were redirected to an HTML login page *(API / error handling)*

**Asked.** "Add a JSON API that reuses the same services."

**Produced.** API routes raising `Unauthenticated`, but the error handler had been registered globally by the web blueprint and always redirected.

**What was wrong.** Unauthenticated API calls got `302 → /login` instead of `401`. Scripted clients would follow the redirect and get an HTML page with status 200, which some tools treat as success. Caught by `test_T01_anonymous_cannot_reach_anything` (`assert 302 == 401`).

**What I did instead.** The handler returns a JSON 401 for `/api/` paths. Anonymous attempts on document URLs are now also written to the audit trail (`test_T21_anonymous_attempts_are_recorded`).

**Commit:** _add link_

---

## Reusable context and instructions

These two blocks were distilled from the mistakes above. From now on they go at the start of every AI session in this project.

**1. Security reviewer instructions** (for every review pass):

> You are reviewing TrustVault, a document vault judged on whether the wrong person can reach a file. Treat every document id, filename, username, role, permission value and header from a request as attacker-controlled. For every route, HTML or JSON, name the exact line where the server decides access, and say what happens if that line is deleted. Admins do not get implicit document access. Revocation must affect sessions and tokens issued earlier, not only future grants. Audit events must be written in the same transaction as the change, including refusals, and must not be recomputable by someone with database access alone. For each finding give the attack, the fix, and a test that fails without the fix. Say explicitly what the code does NOT protect against.

**2. Test-writing rule:**

> Every test is named `test_Txx_<behaviour>` after a THREATS.md row. Each test must first show the action *succeeds* for someone who should be allowed (so a 404 is a real denial, not a broken route), then that it fails for each kind of person who should not. When a protection has two layers, add one test per layer that bypasses the other.

**Checking AI output:**
- Run `test.bat` and `mutation-check.bat` after every change.
- Run the suite against PostgreSQL as well as SQLite.
- Load the pages in a real browser.
- Run `scripts/live_check.py` against the deployed URL.
