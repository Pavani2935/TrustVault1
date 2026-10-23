-- TrustVault schema (SQLite). Idempotent: safe to run on every start.
-- Timestamps are fixed-width UTC ISO-8601 text (see trustvault/clock.py).

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    is_demo             INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);

-- Server-side sessions: the cookie holds a random token; only its SHA-256 is stored.
-- Deleting a row ends that session on the very next request.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash          TEXT PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    ip                  TEXT,
    user_agent          TEXT,
    flash               TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,
    ip           TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    success      INTEGER NOT NULL CHECK (success IN (0, 1))
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_user_ip ON login_attempts(username, ip, attempted_at);
CREATE INDEX IF NOT EXISTS ix_login_attempts_ip ON login_attempts(ip, attempted_at);

CREATE TABLE IF NOT EXISTS documents (
    id              TEXT PRIMARY KEY,           -- 128-bit random, URL-safe; not guessable
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    owner_id        INTEGER NOT NULL REFERENCES users(id),
    current_version INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT,
    deleted_by      INTEGER REFERENCES users(id),
    purged_at       TEXT
);
CREATE INDEX IF NOT EXISTS ix_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS ix_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS ix_documents_created ON documents(created_at);

-- File bytes live here, encrypted (AES-256-GCM, per-version data key wrapped by the master key).
CREATE TABLE IF NOT EXISTS document_versions (
    id            TEXT PRIMARY KEY,
    document_id   TEXT NOT NULL REFERENCES documents(id),
    version_no    INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    wrapped_key   BLOB,
    ciphertext    BLOB,
    uploaded_by   INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    UNIQUE (document_id, version_no)
);

CREATE TABLE IF NOT EXISTS grants (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    permission  TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    UNIQUE (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_grants_user ON grants(user_id, document_id);

-- Append-only, HMAC-chained evidence. seq is assigned by the application under a lock
-- so gaps are detectable; UPDATE and DELETE are refused by triggers.
CREATE TABLE IF NOT EXISTS audit_events (
    seq            INTEGER PRIMARY KEY,
    event_time     TEXT NOT NULL,
    actor_id       INTEGER,
    actor_username TEXT NOT NULL,
    actor_role     TEXT,
    ip             TEXT,
    action         TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    document_id    TEXT,
    target         TEXT,
    details        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    event_hash     TEXT NOT NULL UNIQUE,
    key_id         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_document ON audit_events(document_id, seq);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_events(actor_id, seq);
CREATE INDEX IF NOT EXISTS ix_audit_time ON audit_events(event_time);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
