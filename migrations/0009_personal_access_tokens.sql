-- Personal access tokens: opaque long-lived bearer tokens a user mints from the
-- Account page for MCP clients that cannot run the OAuth flow. Only the SHA-256
-- hash is stored; the plaintext is shown once at creation.

CREATE TABLE personal_access_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX idx_pat_user ON personal_access_tokens(user_id);
