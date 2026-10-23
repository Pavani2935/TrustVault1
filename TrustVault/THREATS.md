# TrustVault threat model

This file covers the ways this system could be broken, what was done about each one, and the risks that were knowingly accepted.

Each row names the tests that prove it (`tests/test_*.py::test_Txx_*`). Several protections are deliberately layered, for example a disabled user is refused both by the session layer and by the policy. End-to-end tests pass as long as *any* layer holds, so `tests/test_policy_layers.py` also tests each layer on its own.

`scripts/mutation_check.py` removes 33 security checks one at a time and confirms that a test fails for every one. Run it with `mutation-check.bat`. A CI job runs it on every push.

**Assets:** document bytes, document metadata (titles can be sensitive, e.g. *"Salary letter – Victor"*), grants, identities and sessions, and the audit trail as evidence.

**Attackers considered:**
- An anonymous internet user.
- A signed-in user with a legitimate account but no grant, which is the judges' main scenario.
- A grantee trying to go beyond their grant.
- A malicious or compromised administrator.
- Someone with read/write access to the database or a backup.
- A malicious website visited by a signed-in user.

---

## A. Reaching a document you were not given

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-01 | **IDOR.** Take a document id, or guess one, and call any route directly: detail, download, version download, metadata edit, new version, delete, restore, purge, grant, revoke, access log, suggestions. Covers both the HTML and JSON APIs, with buttons hidden or not. | Every service function authorises through `documents._authorize()` → `authz.is_allowed()` inside the transaction that does the work. Ids are 128-bit random values, but secrecy of the id is **not** relied on. Default deny: an action not listed in the policy is refused. | `test_T01_*` (every route × 4 users × UI and API), `test_policy_layers.py::test_policy_default_deny`. Mutations M01, M05, M07, M12. |
| T-02 | **Leak through listing and search.** Search for someone else's title, owner or category; use `%` or `_` wildcards; read the category dropdown, which listed every category in the starter. | The listing SQL is scoped to owned or currently granted documents, and every row is then re-checked with the policy. Categories are derived from the caller's visible documents only. LIKE wildcards are escaped. | `test_T02_*`, `test_search_policy_recheck_catches_a_broken_query`. Mutation M13. |
| T-03 | **Read grant used to write.** A viewer POSTs to edit, versions, delete, grants or revoke, or opens the access log. | Permission levels are ordered (read < edit < owner). Each action declares the minimum level it needs. | `test_T03_*`. Mutations M05, M08, M09, M11, M14, M29. |
| T-04 | **Edit grant escalated to owner powers.** An editor re-shares, deletes, purges or reads the access history. | Sharing, deletion, purge, access history and suggestions require `owner`. | `test_T04_*`, `test_T26_grantee_cannot_reshare`. Mutation M10. |
| T-05 | **Administrator reads documents.** The starter gave admins implicit owner rights. | Admins have no document permission at all. The role carries `manage_users`, `read_audit` and `view_inventory` only. The inventory screen deliberately has no download link. | `test_T05_*`, `test_policy_default_deny`. Mutation M02. |
| T-06 | **Administrator becomes the owner** by resetting their password or impersonating them. | No password-reset or impersonation feature exists, and API fields like `password` are ignored. Account recovery is out of scope by design (see WRITEUP). | `test_T06_*` |
| T-07 | **Role bypass.** A viewer uploads; a non-admin calls admin pages or the API; a user promotes themselves. | Role capabilities are checked inside the services (`authz.has_capability`), not in templates. The role is re-read from the DB on every request, and an admin can't change their own role. | `test_T07_*`, `test_role_change_applies_on_next_request`. Mutations M22, M23, M28. |
| T-15 | **Existence oracle.** Telling "exists but forbidden" from "doesn't exist" via status code or body. | Both return a byte-identical 404, from the HTML and the API. | `test_T15_*` |
| T-26 | **Grant abuse.** Grant to yourself, to the owner, to a disabled or unknown user; use permission `owner`/`admin`; set an expiry in the past. | Validated in `set_grant`. Only `read` and `edit` exist. The target must be active. Expiry must be in the future and at most a year away. | `test_T26_*`. Mutation M32. |
| T-28 | **Mass assignment.** Send `owner_id`, `deleted_at`, `current_version` or `role` in JSON. | Services take explicit arguments, so request bodies are never spread into SQL. | `test_T28_*`, `test_T06_*` |
| T-32 | **Old versions.** Download version 1 after losing access, or request a version that doesn't exist. | Version download goes through the same `download` authorisation. Unknown versions return 404. | `test_T32_*` |
| T-33 | **Verb tampering.** `GET /documents/<id>/delete`, or using HEAD to skip checks. | State changes are POST/PUT/PATCH/DELETE only (405 otherwise). HEAD runs the same view, including the authorisation. | `test_T33_*` |

## B. Revocation, sessions and identity

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-08 | **Stale access after revocation.** Keep a session open, a tab open or a URL bookmarked after the owner revokes. Expired grants keep working. | No caches, signed URLs, share links or tokens. Every request re-reads the grant row, and expiry is checked at request time. Pages are sent with `Cache-Control: no-store`, so the back button shows nothing. | `test_T08_*` (same open session, UI and API). Mutation M03. |
| T-09 | **Leaver.** An employee is disabled but their session or grants still work. | Disabling deletes their sessions. Independently, the session loader refuses inactive users and the policy refuses inactive users, so either layer alone is enough. | `test_T09_*`, `test_session_layer_refuses_inactive_user_with_surviving_session_row`, `test_policy_refuses_inactive_user_even_with_a_grant`. Mutations M06, M19. |
| T-10 | **Deleted document still reachable**, or deletion that can't be undone. | Deleted documents are invisible to grantees, and even the owner can only restore or purge them. Purge destroys ciphertext and wrapped keys and removes grants, but keeps the audit trail. | `test_T10_*`, `test_policy_ignores_grants_on_deleted_documents`. Mutation M04. |
| T-11 | **Session theft, replay, fixation, forgery.** Re-use a cookie after logout; forge a cookie (the starter's default secret `dev-only-change-me` allowed forging `uid=1`); plant a cookie before login; leave a session open forever; keep sessions after a password change. | Sessions are random 256-bit tokens; only their SHA-256 is stored server-side. Logout deletes the row. A new token is issued at login and the old one destroyed. Sessions expire after 30 min idle and 8 h absolute. Sessions older than the password are refused. Cookies are `HttpOnly`, `SameSite=Lax`, and `__Host-` + `Secure` + HSTS in production. Users can end their other sessions; admins can end anyone's. | `test_T11_*`, `test_session_layer_refuses_sessions_older_than_the_password`. Mutations M18, M20, M33. |
| T-12 | **CSRF.** A malicious page makes a signed-in owner grant access or delete a document. Also login CSRF, and tokens borrowed from another session. | A per-session synchronizer token is required on every state-changing request (form field or `X-CSRF-Token` header) and compared in constant time. The `Origin`/`Referer` must match the host, and `Origin: null` is refused. `SameSite=Lax` adds another layer. Rejections are audited. | `test_T12_*`. Mutations M16, M17. |
| T-13 | **Password guessing and spraying.** | DB-backed throttling: 5 failures per (username, IP) per 15 min, and 30 failures per IP across usernames. Keying on the pair means an attacker can't lock the real user out from everywhere. scrypt password hashing. | `test_T13_*`. Mutation M21. |
| T-14 | **Username enumeration** via messages, status codes or timing. | Same message and status for unknown user and wrong password. A dummy hash is checked when the user doesn't exist, so timing matches. | `test_T14_*` |
| T-20 | **Open redirect** via `?next=` after login. | Only local paths are allowed; `//host`, schemes and backslashes are rejected. | `test_T20_*` |
| T-31 | **Misconfiguration: default or weak secrets.** This was the starter's worst flaw: a forged admin session if the env var was missing. | In production the app refuses to start without `DATABASE_URL` and two distinct secrets of at least 32 characters. Flask's signed-cookie session isn't used at all. | `test_T31_*` |

## C. The audit trail as evidence

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-21 | **Incomplete record.** Refused attempts, anonymous probing or downloads aren't logged, so "who opened it" can't be answered. | Every view, download, upload, version, edit, delete, restore, purge, grant, grant change, revoke, suggestion, dismissal, login (ok, failed, throttled), logout, CSRF/Origin rejection, admin action and audit read/export/verify is recorded with actor, role, IP, time and details. Business changes and their audit events commit in one transaction, so there is no action without a record. The owner sees their own document's history. The admin dashboard flags probing and bulk downloads. | `test_T21_*`. Mutation M15. |
| T-22 | **Quietly altering the record.** `UPDATE`, `DELETE` or `TRUNCATE` audit rows; edit a row and recompute the hash (the starter used plain SHA-256, so anyone with DB access could); delete a row from the middle; race two writers so the chain forks (the starter had this race). | 1. The app has no route that changes audit rows. 2. DB triggers refuse UPDATE/DELETE/TRUNCATE. 3. Each event is HMAC-SHA256 over its fields plus the previous hash, keyed with `TRUSTVAULT_AUDIT_KEY`, which never touches the DB, so recomputing is impossible without the key. 4. Contiguous sequence numbers reveal gaps. 5. Appends are serialised (`BEGIN IMMEDIATE` / `pg_advisory_xact_lock`). 6. Every event is also written to the host's log stream as a second copy. The verifier reports the first broken event. | `test_T22_*`. Mutations M24, M25, M30. |
| T-23 | **Audit confidentiality and export abuse.** Non-admins read the audit; a CSV export runs formulas in Excel. | Admins only; owners see only their own documents' events. Reading, exporting and verifying are themselves audited. Cells starting with `= + - @` are neutralised in the CSV. | `test_T23_*` |

## D. Files and storage

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-16 | **Malicious uploads.** An `.exe` renamed to `.pdf`; HTML or SVG; macro-enabled Office files; PDFs with JavaScript, launch actions or embedded files; zip bombs; empty or oversized files; path-traversal names. | Extension allow-list, **plus** content signature checks per type (PDF header and trailer, PNG/JPEG magic, OOXML structure, UTF-8 text with no NULs). Macros and `.bin` parts are rejected; expansion ratio and total size are capped; PDF active-content markers are rejected. 10 MB cap enforced by the validator and by the request size limit (413). Filenames are reduced to a safe character set and the last path component. | `test_T16_*` (15 bad files, 7 good). Mutations M26, M27. |
| T-17 | **Download runs in the browser** (stored XSS via file, MIME sniffing). | Content type is decided by the server at upload time. Downloads are always `Content-Disposition: attachment`, with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; sandbox`. | `test_T17_*`. Mutation M31. |
| T-24 | **Data at rest.** A DB dump or backup leaks files; someone copies one row's ciphertext over another's; the master key is wrong or lost. | AES-256-GCM with a fresh key per version. That key is wrapped by a KEK derived (HKDF) from `TRUSTVAULT_MASTER_KEY`, which is not in the DB. The associated data binds ciphertext to document id, version id and hash, so swapped blobs fail authentication, the failure is audited, and nothing is served. The plaintext hash is re-checked after decryption. Files live in the DB, never on a public path. | `test_T24_*` |
| T-29 | **Storage exhaustion** that takes the demo down. | 100 MB per-user quota and 60 uploads per hour (both configurable). | `test_T29_*` |

## E. Web and HTTP

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-18 | **Stored XSS** in titles or categories; **Unicode bidi spoofing** (`invoice‮txt.exe`). | Jinja auto-escaping. Strict CSP with no inline script or style and no third-party origins. Control and bidi-override characters are rejected in text fields. | `test_T18_*` |
| T-19 | **SQL injection** in search, ids or filters. | All SQL is parameterised. Ids are format-checked before any query. Dates are parsed, not interpolated. | `test_T19_*` |
| T-27 | **Clickjacking, referrer leaks, caching.** | `frame-ancestors 'none'` plus `X-Frame-Options: DENY`; `Referrer-Policy: same-origin`; `no-store` on every dynamic response; COOP/CORP; HSTS in production. | `test_T27_*` |
| T-30 | **Request flooding.** | Per-IP sliding-window limit (300/min by default) returns 429. | `test_T30_*` |
| T-34 | **Spoofed proxy headers.** Send your own `X-Forwarded-For` to dodge throttling or plant a fake IP in the audit. | Only the configured number of proxy hops is trusted (`ProxyFix`, 1 on Render), so a client-supplied value is ignored. The admin dashboard shows the recorded IP next to the raw header so the setting can be verified after deploying. Authorisation never depends on IP or headers. | `scripts/live_check.py` ("spoofed proxy headers do not bypass authorisation"). |

## F. AI inside the product

| ID | Threat and attack path | What stops it | Proof |
|---|---|---|---|
| T-25 | **The assistant widens access by itself**, or leaks other people's sharing patterns. | Suggestions have no write path to `grants`; a human must press *Grant*, which goes through the normal owner-only endpoint. The suggestion (`access_suggested`) and the decision (`grant` with `source=suggestion`, or `suggestion_dismissed`) are both audited. Suggestions only learn from the requesting owner's own grants. No document content or metadata leaves the server. | `test_T25_*`. Mutation M29. |

---

## Known and accepted risks

These are left open deliberately; the reason for each is given. Each could be found by a reviewer, so they are listed here.

| ID | Risk | Why it is accepted, and what production would do |
|---|---|---|
| T-35 | **No malware scanning.** An allowed file type can still carry an exploit for a viewer application (e.g. a malicious but well-formed PDF). | Signature checks stop disguised types, and downloads can't run in the browser. Real AV (ClamAV or a cloud scanner) needs infrastructure the free tier doesn't have. Production: scan on upload and quarantine until clean. |
| T-36 | **An insider with both the database and the audit key** could rewrite history consistently. | The HMAC chain defeats someone with the DB alone, and the stdout copy defeats someone with the DB and the key but not the log store. Defeating all three needs external anchoring: periodically write the head hash to WORM storage (S3 Object Lock) or a separate logging account. Not built (no free WORM store). |
| T-37 | **A legitimate grantee leaks what they were given** (download, screenshot, forward). | No server can recall bytes it rightly delivered. The trail records exactly who downloaded which version and when, and the dashboard flags bulk downloads. Watermarking and view-only rendering were considered and not built. |
| T-38 | **A download already in flight** when access is revoked finishes. | Authorisation happens before decryption. A response that has started can't be recalled. Files are 10 MB at most, so the window is short. |
| T-39 | **A compromised administrator account.** No MFA. | An admin can't read documents, reset passwords or impersonate, which limits the blast radius. An admin *can* disable users and create accounts, all audited. Production: SSO with MFA, and two-person approval for admin actions. |
| T-40 | **Lockout or griefing of the shared demo accounts** by one reviewer. | Throttling is keyed per (username, IP), so one reviewer can't lock out another. In demo mode the five seeded accounts can't be disabled, demoted or have their password changed. This is a demo-only guard, and the same flows are tested on non-demo accounts. `test_T40_*` |
| T-41 | **Vulnerable dependencies.** | Versions are pinned; CI runs on Windows and Linux. Automated scanning (`pip-audit`, Dependabot) is not set up and is one config file away. |
| T-42 | **Metadata in platform logs.** The stdout audit copy includes titles and usernames. | That copy is intended as a second record. Render's log store is access-controlled. Production would ship to a dedicated log account. |
| T-43 | **Availability on the free tier.** The instance sleeps after 15 min idle (about 1 min cold start). Render's free PostgreSQL expires 30 days after creation. | It's a demo. `DATABASE_URL` can point to any PostgreSQL (paid Render, Neon, Supabase) with no code change; see DEPLOY.md. |
| T-44 | **Small timing differences** between an unknown id (format rejected, no DB lookup) and a real-but-forbidden id. | Ids are 128-bit random values, so learning that an id exists requires already holding it. Response bodies and status codes are identical. |
| T-45 | **Polyglot files** (a valid PNG with HTML appended), and PDF active content hidden inside compressed object streams. | No full parser. The mitigation is that downloads are attachments with `nosniff` and a sandbox CSP, so the browser never interprets them. A desktop viewer is the residual risk (see T-35). |
| T-46 | **Per-process in-memory request limiter** resets on restart and isn't shared across instances. | One instance on the free tier. Login throttling, which is the part that matters, is stored in the DB. Production: shared limiter (Redis) or edge rate limiting. |
| T-47 | **Master key loss means data loss.** | This is the property of real encryption. The key must be backed up outside the host (DEPLOY.md says so). Key rotation is designed for (`key_id` on every version) but not implemented. |
| T-48 | **Usernames are visible to document owners** in the grant picker. | Needed to grant to named people. Viewers and anonymous users can't list users. |
| T-49 | **Restore re-enables previous grants.** | Deliberate: restore is a true undo of an accidental delete. The restore event records how many grants were reinstated, and the owner sees them immediately on the document page. |
| T-50 | **CSV and spreadsheet uploads with formulas** are stored unmodified. | Changing users' files would break integrity (hashes) and evidentiary value. Only our own audit export is neutralised. |

## How to re-check this list

1. `test.bat` (or `python -m pytest -q`) runs all threat tests, on SQLite by default. Set `TEST_DATABASE_URL` to run them on PostgreSQL.
2. `mutation-check.bat` removes each listed check and confirms a test fails.
3. `python scripts/live_check.py https://YOUR-APP.onrender.com` runs the black-box version against the deployed system.
