-- TrustVault schema (PostgreSQL 13+). Idempotent: safe to run on every start.
-- Timestamps are fixed-width UTC ISO-8601 text (see trustvault/clock.py) so that the
-- same queries behave identically on SQLite and PostgreSQL.

CREATE TABLE IF NOT EXISTS users (
    id                  BIGSERIAL PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS sessions (
    token_hash          TEXT PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
    id           BIGSERIAL PRIMARY KEY,
    username     TEXT NOT NULL,
    ip           TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    success      INTEGER NOT NULL CHECK (success IN (0, 1))
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_user_ip ON login_attempts(username, ip, attempted_at);
CREATE INDEX IF NOT EXISTS ix_login_attempts_ip ON login_attempts(ip, attempted_at);

CREATE TABLE IF NOT EXISTS documents (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    owner_id        BIGINT NOT NULL REFERENCES users(id),
    current_version INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT,
    deleted_by      BIGINT REFERENCES users(id),
    purged_at       TEXT
);
CREATE INDEX IF NOT EXISTS ix_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS ix_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS ix_documents_created ON documents(created_at);

CREATE TABLE IF NOT EXISTS document_versions (
    id            TEXT PRIMARY KEY,
    document_id   TEXT NOT NULL REFERENCES documents(id),
    version_no    INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    sha256        TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    wrapped_key   BYTEA,
    ciphertext    BYTEA,
    uploaded_by   BIGINT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    UNIQUE (document_id, version_no)
);

CREATE TABLE IF NOT EXISTS grants (
    id          BIGSERIAL PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id     BIGINT NOT NULL REFERENCES users(id),
    permission  TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by  BIGINT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    UNIQUE (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_grants_user ON grants(user_id, document_id);

CREATE TABLE IF NOT EXISTS audit_events (
    seq            BIGINT PRIMARY KEY,
    event_time     TEXT NOT NULL,
    actor_id       BIGINT,
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

CREATE OR REPLACE FUNCTION trustvault_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION trustvault_audit_append_only();

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION trustvault_audit_append_only();

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION trustvault_audit_append_only();

-- Optional hardening when you control database roles (not possible on every free host):
--   CREATE ROLE trustvault_app LOGIN PASSWORD '...';
--   GRANT SELECT, INSERT ON audit_events TO trustvault_app;   -- no UPDATE/DELETE/TRUNCATE
--   ALTER TABLE audit_events OWNER TO trustvault_admin;       -- app role cannot drop triggers
