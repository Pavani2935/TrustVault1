# TrustVault API

The HTML UI and the JSON API call the same service functions, so they share one authorisation path. The rules below apply to both.

## Conventions

- **Authentication**
  - Sign in with `POST /api/v1/auth/login`. It sets an `HttpOnly` session cookie and returns a `csrf_token`.
  - Send the cookie with every request.
  - Every `POST`, `PUT`, `PATCH` and `DELETE` must also carry the `X-CSRF-Token: <csrf_token>` header (HTML forms send a `csrf_token` field instead).
  - If a request has an `Origin` or `Referer` header, it must match the host.
- **Errors** are `{"error": "...", "status": n}`.
  - **404 means "not found or not yours".** The API never says which.
  - `401`: not signed in.
  - `403`: your *role* can't do this, or the CSRF/Origin check failed.
  - `400`: validation.
  - `413`: upload too large.
  - `429`: throttled.
- **Permission levels on a document:** `owner` (uploader) > `edit` > `read` > none.
  - Administrators have **no** document permission unless an owner grants them one.
  - Nothing is cached, so a revoked grant fails on the very next call.
- Every call marked † writes an audit event, including when it is refused.

## Authentication

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /api/v1/auth/login` `{username, password}` | Anyone | † Returns `{user, csrf_token}`. Throttled per (username, IP) and per IP. |
| `POST /api/v1/auth/logout` | Signed in | † Deletes the session server-side. |
| `GET /api/v1/me` | Signed in | Current user and CSRF token. |
| `GET /api/v1/meta` | Anyone | Allowed file types and size limit. |
| `GET /healthz` | Anyone | Liveness plus DB connectivity. |

## Documents

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /api/v1/documents?q=&owner=&category=&from=YYYY-MM-DD&to=YYYY-MM-DD&scope=all\|mine\|shared` | Signed in | Only documents the caller owns or holds a live grant on. Search by name, owner, category and date. |
| `POST /api/v1/documents` (multipart: `title`, `category`, `file`) | Role **owner** | † Validated by content, encrypted, private to the uploader. `201 {id}`. |
| `GET /api/v1/documents/{id}` | read, edit, owner | † Metadata and version list. |
| `GET /api/v1/documents/{id}/content?version=n` | read, edit, owner | † Decrypted file, always as an attachment. Defaults to the latest version. |
| `PATCH /api/v1/documents/{id}` `{title?, category?}` | edit, owner | † Other fields are ignored. |
| `POST /api/v1/documents/{id}/versions` (multipart `file`) | edit, owner | † Adds a new version. Old versions are kept. |
| `DELETE /api/v1/documents/{id}` | owner | † Moves to trash. Every grantee loses access immediately. |
| `POST /api/v1/documents/{id}/restore` | owner (document in trash) | † Restores it, along with its previous grants. |
| `POST /api/v1/documents/{id}/purge` | owner (document in trash) | † Destroys ciphertext and keys and removes grants. The audit trail is kept. |
| `GET /api/v1/trash` | Signed in | The caller's own trashed documents. |
| `GET /api/v1/documents/{id}/activity` | owner (also while the document is in trash) | † Every event on this document, including refused attempts. |

## Sharing

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /api/v1/documents/{id}/grants` | owner | Current grants and their expiry. |
| `PUT /api/v1/documents/{id}/grants/{username}` `{permission: read\|edit, expires_on?: YYYY-MM-DD}` | owner | † Creates or changes a grant. The target must be an active user who isn't the owner. |
| `DELETE /api/v1/documents/{id}/grants/{username}` | owner | † Revokes. Takes effect on the grantee's next request. |
| `GET /api/v1/documents/{id}/suggestions` | owner | † Suggested people with reasons. **Never applied automatically.** To accept one, `PUT` the grant yourself. |

## Administration (role **admin**)

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /api/v1/admin/dashboard` | admin | † Stats, alerts ("worth noticing") and recent permission changes. |
| `GET /api/v1/admin/audit?actor=&action=&outcome=&document_id=&from=&to=&limit=&before_seq=` | admin | † Audit search. `action=permissions` returns all permission changes. |
| `POST /api/v1/admin/audit/verify` | admin | † Verifies the whole HMAC chain and returns `{ok, checked, broken_at, reason, head_hash}`. |
| `GET /api/v1/admin/documents` | admin | † Metadata-only inventory. There is no content endpoint for admins. |
| `GET /api/v1/admin/users` | admin | Accounts, roles, status, session counts. |
| `POST /api/v1/admin/users` `{username, display_name, password, role}` | admin | † Creates an account. Password policy applies. |
| `PATCH /api/v1/admin/users/{id}` `{is_active?, role?}` | admin, not on self | † Disabling ends the user's sessions immediately. A role change applies on their next request. Password fields are ignored: admins can't set other people's passwords. |
| `POST /api/v1/admin/users/{id}/sessions/end` | admin | † Signs the user out everywhere. |

## HTML routes

These follow the same rules: same service call, same check.

| Route | Who |
|---|---|
| `GET/POST /login`, `POST /logout` | Anyone / signed in |
| `GET /documents` (search), `GET /documents/{id}`, `GET /documents/{id}/download?v=n` | Signed in; document routes need read |
| `GET/POST /documents/new` | Role owner |
| `POST /documents/{id}/metadata`, `POST /documents/{id}/versions` | edit, owner |
| `POST /documents/{id}/delete\|restore\|purge`, `POST /documents/{id}/grants`, `POST /documents/{id}/grants/{username}/revoke`, `GET /documents/{id}/activity`, `GET /documents/{id}/suggestions`, `POST /documents/{id}/suggestions/dismiss`, `GET /trash` | owner |
| `GET/POST /account`, `POST /account/sessions/end-others` | Signed in (own account only) |
| `GET /admin/`, `/admin/audit`, `POST /admin/audit/verify`, `GET /admin/audit/export.csv`, `/admin/documents`, `GET/POST /admin/users`, `POST /admin/users/{id}/status\|role\|sessions/end` | Role admin |

## Example (PowerShell)

```powershell
$base = "https://YOUR-APP.onrender.com"
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$login = Invoke-RestMethod "$base/api/v1/auth/login" -Method Post -WebSession $s `
           -ContentType "application/json" -Body '{"username":"bob","password":"Bob#Vault2026!"}'
$h = @{ "X-CSRF-Token" = $login.csrf_token }
$docs = Invoke-RestMethod "$base/api/v1/documents" -WebSession $s
$id = ($docs.documents | Where-Object { $_.title -like "Audit papers*" }).id
Invoke-RestMethod "$base/api/v1/documents/$id/grants/victor" -Method Put -WebSession $s -Headers $h `
  -ContentType "application/json" -Body '{"permission":"read","expires_on":"2026-12-31"}'
```
