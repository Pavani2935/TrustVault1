# TrustVault

Secure document sharing where the wrong person cannot reach a file, and where you can prove who did.

**Live demo:** `https://YOUR-APP.onrender.com` ← replace after deploying (see [DEPLOY.md](DEPLOY.md))

| Document | What it covers |
|---|---|
| [WRITEUP.md](WRITEUP.md) | What was built, what was deliberately left out, the permission model, and how AI was used |
| [THREATS.md](THREATS.md) | 50 threats: what was done about each one, which test proves it, and which risks were accepted |
| [PROMPTS.md](PROMPTS.md) | Log of AI prompts and the AI mistakes that were caught |
| [API.md](API.md) | Every endpoint and who is allowed to call it |
| [DEPLOY.md](DEPLOY.md) | Running it on Windows and deploying to Render, Docker or any PostgreSQL host |
| [`trustvault/schema/`](trustvault/schema) | Database schema (PostgreSQL and SQLite) |

## Demo accounts

These accounts are seeded on first start. Every document is sample data.

| Role | Username | Password | What to try |
|---|---|---|---|
| Administrator | `admin` | `Admin#Vault2026` | Oversight, audit trail, integrity check, users. It **cannot** open any document. |
| Document owner | `alice` | `Alice#Vault2026` | Owns HR documents. Grant, revoke, view access history, ask for suggestions. |
| Document owner | `bob` | `Bob#Vault2026!` | Owns *"Audit papers FY2025"*, which is shared with nobody. Use it as the target. |
| Viewer | `victor` | `Victor#Vault2026` | Has read access to three documents. |
| Viewer | `wendy` | `Wendy#Vault2026` | Has edit access to one contract and a read grant that expires. |

On the public demo (`TRUSTVAULT_DEMO_MODE=true`), these five accounts can't be disabled, demoted or given a new password, so one reviewer can't lock out the others. To exercise those flows, create a new account as `admin`.

## Run it on Windows (2 minutes)

You need Python 3.10 or newer from [python.org](https://www.python.org/downloads/windows/). In the installer, tick **Add python.exe to PATH**.

1. Unzip the folder and double-click **`setup.bat`**. It creates a virtual environment, installs dependencies and generates secrets in `.env`.
2. Double-click **`run.bat`**. The browser opens at http://127.0.0.1:8000.
3. Double-click **`test.bat`** to run the 100+ security tests. Double-click **`mutation-check.bat`** to remove each security check in turn and confirm a test fails every time.

To deploy, see [DEPLOY.md](DEPLOY.md). In short: `publish-to-github.bat <your empty repo URL>`, then Render deploys `render.yaml` in one click.

## The three guarantees, and where they live in the code

**1. A document is reachable only by someone who was granted it, through any route.**

- Every document operation, from both the HTML UI and the JSON API, goes through `documents._authorize()`.
- `_authorize()` asks `authz.is_allowed()`, the single policy function, using the database state at that moment.
- Unknown and forbidden document ids get an identical 404. Administrators get no implicit access.
- Listings are scoped in SQL and then re-checked row by row against the same policy.

**2. You can prove who reached it, including refused attempts.**

- Every view, download, change, grant, revoke, login and refusal is appended to `audit_events`, in the same transaction as the change it describes.
- Each event is HMAC-SHA256-chained with a key that lives in the host's secret store, not in the database.
- Triggers in the database refuse `UPDATE`, `DELETE` and `TRUNCATE` on that table.
- Each event is also written to the platform log stream as an independent copy.
- An administrator can verify the chain from the UI, the API or the command line (`python -m trustvault verify-audit`).

**3. Taking access away works immediately.**

- Sessions are server-side rows, and nothing is cached.
- Revoking a grant, deleting a document, disabling a user or changing a password takes effect on the very next request.
- There are no signed URLs, share links or long-lived tokens that could outlive the revocation.

> **Where is the authorisation decision made when someone downloads a file?**
> In `trustvault/documents.py`, `get_content()` calls `_authorize(ctx, doc_id, "download")`, inside the same transaction that reads the ciphertext. If that line is removed, `test_T01_no_route_reaches_an_ungranted_document` and others fail. `scripts/mutation_check.py` (mutation M07) proves it.

## Architecture

```
Browser ──HTML forms──┐
                      ├─► Flask (waitress) ─► service layer ─► authz.is_allowed()  ◄── the only policy
curl / scripts ─JSON──┘        │                 │
                               │                 ├─► audit.record()  (HMAC chain, same transaction)
                               │                 └─► crypto.Vault    (AES-256-GCM per file, wrapped key)
                               └─► server-side sessions + CSRF + Origin check + rate limits
                                                      │
                                     PostgreSQL (production) / SQLite (local, tests)
```

| Path | Responsibility |
|---|---|
| `trustvault/authz.py` | The permission model: one policy function, default deny |
| `trustvault/documents.py` | Document service; every function authorises through `_authorize` |
| `trustvault/auth.py` | Login, throttling, server-side sessions, CSRF tokens |
| `trustvault/audit.py` | HMAC-chained append-only audit log and its verifier |
| `trustvault/crypto.py` | Envelope encryption bound to document and version ids |
| `trustvault/validation.py` | Input and file validation based on file contents |
| `trustvault/suggestions.py` | Access suggestions: shown to the owner, never applied automatically |
| `trustvault/reports.py` | Admin oversight: alerts, permission changes, inventory |
| `trustvault/web.py`, `admin_web.py`, `api.py` | Thin HTTP layers over the services |
| `tests/` | 108 tests, each named after the threat id it covers in THREATS.md |
| `scripts/mutation_check.py` | Removes 33 security checks one at a time; every removal must break a test |
| `scripts/live_check.py` | Black-box attack and regression check against a deployed URL |

**Stack:** Python 3.10+ · Flask · waitress (WSGI server for Windows and Linux) · PostgreSQL 13+ (SQLite locally) · `cryptography` (AES-GCM, HKDF) · server-rendered HTML with a strict CSP and no inline script.
