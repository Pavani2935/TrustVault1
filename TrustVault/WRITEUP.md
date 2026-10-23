# TrustVault write-up

## What I built

TrustVault is a document vault built around three promises: the wrong person can't reach a file, you can prove who did, and taking access away works at once. In more detail:

- **Three roles.**
  - *Administrator*: manages accounts and oversees activity.
  - *Owner*: uploads documents and controls who sees them.
  - *Viewer*: sees only what they are given.
- **Documents.** Upload with content-based validation. Every version is encrypted with its own key. Versioning, metadata editing, search by name, owner, category and date, a trash with restore, and permanent purge.
- **Per-document grants** to named people, `read` or `edit`, with an optional expiry date. Owners grant and revoke; revocation applies to the grantee's very next request.
- **Audit trail.** Every access and refusal is recorded, HMAC-chained, append-only in the database, and copied to the platform log. Owners see their own document's history; admins see everything and can verify integrity with one click.
- **Admin oversight.** Activity stats, a "worth noticing" list (probing, bulk downloads, failed sign-ins, blocked cross-site requests, edit grants, integrity failures), recent permission changes, a metadata-only inventory, user lifecycle and CSV export.
- **Access suggestions.** An assistant proposes who might need a document; the owner decides. Both the suggestion and the decision are audited.
- **A JSON API** next to the HTML UI. Both use the same service layer, so there is one authorisation path, not two.
- **108 automated tests**, named after the threats they cover, running on SQLite and PostgreSQL. A **mutation check** removes 33 security checks one at a time and requires a test to fail for each.
- **Deployment.** One-click Render Blueprint (web service + PostgreSQL + generated secrets), Windows scripts, a Dockerfile, and a black-box `live_check.py` to run against the live URL.

## The permission model, in my own words

Access belongs to **the document and a named person**, nothing else.

- The person who uploads a document **owns** it.
- Nobody else can see it, not even an administrator, until the owner grants it to a named person as `read` (view and download any version) or `edit` (also change details and upload new versions).
- Only the owner can share, revoke, delete, purge or look at who accessed it. A grantee can never pass access on.

**Roles are separate from document access.** A role says what kind of thing you may do in the system: owners can create documents and admins can manage accounts and read the audit trail. A role never opens a document.

I made the administrator a pure operator on purpose. If admins could read everything, "only someone who was granted it" would quietly become "only someone who was granted it, plus the people who run the system", and a compromised admin account would expose every file. The same reasoning removed **admin password resets and impersonation**: either one would let an admin turn themselves into an owner.

**One policy function decides everything.** `authz.is_allowed(user, document, action)` looks at the database *at that moment*: is the user active, are they the owner, do they hold a grant, has it expired, is the document in the trash. Each action declares the minimum level it needs (`download` needs read, `upload_version` needs edit, `manage_grants` needs owner). Unknown actions are refused.

Every service function calls this through `_authorize()` **inside the same transaction** that does the work, so the decision and the change see the same state. A refusal is turned into a 404 identical to "no such document", and it is written to the audit trail.

**Why no folders, groups or links?**

- **Folder inheritance** is exactly the failure in the brief: you share a folder for one file and expose forty.
- **Groups** make "who can see this?" a join across membership history. That is solvable, but it's harder to show correct in a week.
- **Public links** are bearer tokens: whoever holds the URL is "the right person". That contradicts the first promise, and they are hard to revoke cleanly.

I chose a model I can prove instead of one that sounds richer.

## What "taking access away immediately" means here, and what it costs

Nothing that grants access is cached or signed into a token:

- **Sessions** are rows in the database, and the browser holds only a random token. Every request reloads the session, the user (active? role?) and the grant (exists? expired?). So revoking, deleting, disabling an account, changing a password or "sign out everywhere" all take effect on the next request, including for tabs that are already open.
- **No share links and no pre-signed download URLs.** Every download is authorised by the server before decryption.

**What it costs:**
- Every request does a few indexed lookups that a token-based design would skip. That is fine at this scale; at a large scale I would add a short-lived cache with explicit invalidation on revoke.
- Files are streamed through the application rather than straight from object storage, which costs bandwidth.
- What can't be revoked is what was legitimately delivered: a file someone already downloaded, or a download in flight. The audit trail is the answer to that.

## How files are stored, and what makes them unreachable

- Files are kept in the database, encrypted with AES-256-GCM. Each version gets a fresh data key, which is wrapped by a key derived from `TRUSTVAULT_MASTER_KEY`.
- The ciphertext is bound to its document id, version id and hash. A database-level swap of one file's bytes into another record fails to decrypt; the failure is audited and nothing is served.
- No file is ever on a web-reachable path.
- A database dump or backup on its own reveals nothing.

I put files in the database rather than on disk for three reasons:
- Free hosts wipe the disk.
- It keeps data, grants and audit in one transactional store.
- The 10 MB limit keeps it reasonable.

In production I would move the blobs to a private object store behind the same `Vault` interface, with the master key in a KMS.

## How the audit trail is protected

These layers are described in detail in THREATS.md (T-22):

1. **The application can't change it.** There is no route for it.
2. **The database refuses** UPDATE, DELETE and TRUNCATE (triggers).
3. **It can't be rewritten** without a key the database never sees. Each event's HMAC covers its fields, its sequence number and the previous hash.
4. **Appends are serialised**, so the chain can't fork under load.
5. **A second copy** of every event goes to the hosting platform's log store.

**Remaining risk:** someone holding the database, the audit key *and* the log store could rewrite history. The production answer is anchoring the head hash in WORM storage, which I describe but did not build.

## What I deliberately did not build

| Not built | Why |
|---|---|
| Public or external share links | Bearer tokens contradict "only a granted person", and are hard to revoke cleanly. External partners get an account instead. |
| Folders, groups, inheritance | Inheritance is the over-sharing failure from the brief; groups add membership-history complexity I could not prove correct in a week. |
| Admin password reset / impersonation | Either one lets an admin become an owner. Recovery belongs in an identity provider with MFA. |
| MFA / SSO | Needs an identity provider. Listed as the first production step (THREATS T-39). |
| Malware scanning | Needs scanner infrastructure. Mitigated by content validation and attachment-only, sandboxed downloads (T-35). |
| WORM anchoring of the audit head | No free WORM store. The HMAC chain plus an independent log copy covers everything short of a full insider (T-36). |
| Automatic retention / trash expiry | A trash with explicit purge exists. A timed purge job is easy to add, but retention policy is a business decision. |
| Watermarking / view-only rendering | Doesn't stop a determined grantee, and adds a rendering pipeline. Audit plus bulk-download alerts instead (T-37). |
| An LLM in the product | The suggestion feature is a transparent heuristic over the owner's own sharing history. I didn't want document titles or sharing patterns leaving the server for a feature whose output a human must confirm anyway. An LLM ranker could sit behind the same interface without changing the guarantees. |

## How I used AI, and where it was wrong

AI generated the first prototype and much of the rebuild and tests. I directed it with a written reviewer brief (in PROMPTS.md) and checked it four ways: tests, a mutation check, running on a second database, and looking at pages in a real browser. The important corrections, all detailed in PROMPTS.md:

- **Authorisation.** The prototype had a default session secret that allowed forging an admin session, gave admins access to every document, and leaked other users' categories through search.
- **Audit.** Its "tamper-evident" chain was a plain SHA-256 that anyone with database access could recompute, and parallel writes could fork it.
- **Revocation.** Logout didn't invalidate the cookie, and there was no way to disable a leaver.
- **Tests.** My first rebuilt test suite let 5 of 33 deliberately removed checks pass unnoticed, because a second defensive layer hid each one. I added per-layer tests until every mutation was caught.
- **Headers.** A hardening change (`Referrer-Policy: no-referrer`) silently broke sign-in in every real browser while all tests passed. I caught it with a headless browser, and a regression test now covers it.

## What is unfinished

- MFA, an identity provider and account recovery.
- WORM anchoring of the audit head, and automated key rotation (the per-version `key_id` exists so rotation can be added).
- Antivirus scanning.
- Dependency scanning in CI.
- A shared rate limiter for multiple instances.
- Retention automation.
- The free-tier database expires after 30 days. DEPLOY.md explains how to point at a non-expiring PostgreSQL.

## Five-minute demo script

| Time | Show |
|---|---|
| 0:00–0:30 | The three promises, and the role model: admins don't read documents. |
| 0:30–1:15 | Sign in as **bob**. Open *Audit papers FY2025*, shared with no one. Copy its URL. |
| 1:15–2:00 | In another browser, sign in as **victor** and paste the URL: 404. Try the API (`/api/v1/documents/<id>/content`): 404. Sign in as **admin** and try the same URL: 404. |
| 2:00–2:45 | As bob, grant victor *read*. Victor downloads. Bob revokes. Victor refreshes the **same tab**: 404 immediately. |
| 2:45–3:30 | As bob, open *Who accessed this*. It shows victor's and admin's refused attempts with time and IP, plus the grant, download and revoke. |
| 3:30–4:15 | As admin: *Oversight* flags the probing; *Audit trail → Verify integrity* shows the chain intact. Explain the HMAC key and the DB triggers (optionally show `test_T22_recomputing_hashes_without_the_key_does_not_help`). |
| 4:15–5:00 | Run `mutation-check.bat`: all 33 removed checks are caught. Close with one accepted risk from THREATS.md (e.g. T-37, a grantee can still leak what they were given) and why. |
