-- Initial schema for the MCP Hub.
--
-- Identifiers are text UUIDs. Timestamps are unix epoch seconds (INTEGER).

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Users & passkeys
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    handle       TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    -- Serialized webauthn-rs Passkey (JSON) holding the public key, counter, etc.
    passkey_json  TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_webauthn_user ON webauthn_credentials(user_id);

-- Browser sessions for the web UI / OAuth authorize flow.
CREATE TABLE web_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_web_sessions_user ON web_sessions(user_id);

-- ---------------------------------------------------------------------------
-- Catalog & user-configured instances
-- ---------------------------------------------------------------------------
CREATE TABLE catalog_servers (
    id                 TEXT PRIMARY KEY,
    slug               TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    -- 'stdio' | 'http'
    transport          TEXT NOT NULL,
    -- stdio backends: program + JSON array of args; http backends: url
    command            TEXT,
    args_json          TEXT NOT NULL DEFAULT '[]',
    url                TEXT,
    -- informational: 'node' | 'python' | 'binary' | 'remote'
    runtime            TEXT NOT NULL DEFAULT 'remote',
    -- JSON array of {name,label,secret,required} describing required config keys
    secret_schema_json TEXT NOT NULL DEFAULT '[]',
    is_builtin         INTEGER NOT NULL DEFAULT 0,
    -- 1 if usable in the current version (e.g. upstream-OAuth servers are not yet)
    supported          INTEGER NOT NULL DEFAULT 1,
    created_by         TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at         INTEGER NOT NULL
);

CREATE TABLE user_server_instances (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Either references a catalog entry, or carries an inline custom definition.
    catalog_server_id TEXT REFERENCES catalog_servers(id) ON DELETE SET NULL,
    custom_def_json   TEXT,
    -- Stable, user-chosen namespace prefix for aggregated tool names.
    namespace         TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    -- Non-secret configuration (e.g. extra args) as JSON.
    config_json       TEXT NOT NULL DEFAULT '{}',
    created_at        INTEGER NOT NULL,
    UNIQUE(user_id, namespace)
);
CREATE INDEX idx_instances_user ON user_server_instances(user_id);

-- Encrypted per-instance secrets (one row per config key).
CREATE TABLE instance_secrets (
    id          TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES user_server_instances(id) ON DELETE CASCADE,
    key_name    TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    UNIQUE(instance_id, key_name)
);

-- ---------------------------------------------------------------------------
-- OAuth 2.1 Authorization Server state
-- ---------------------------------------------------------------------------
-- Dynamically registered clients (RFC 7591).
CREATE TABLE oauth_clients (
    client_id          TEXT PRIMARY KEY,
    client_secret_hash TEXT,            -- NULL for public clients
    redirect_uris_json TEXT NOT NULL,
    metadata_json      TEXT NOT NULL DEFAULT '{}',
    created_at         INTEGER NOT NULL
);

-- Short-lived authorization codes (code + PKCE + resource binding).
CREATE TABLE oauth_auth_codes (
    code           TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    scope          TEXT NOT NULL DEFAULT '',
    resource       TEXT,
    expires_at     INTEGER NOT NULL
);

-- Refresh tokens (access tokens are stateless ES256 JWTs).
CREATE TABLE oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT '',
    resource   TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_refresh_user ON oauth_refresh_tokens(user_id);

-- The hub's ES256 signing key for access tokens (single active key for v1).
CREATE TABLE oauth_signing_keys (
    kid         TEXT PRIMARY KEY,
    -- PKCS#8 DER of the EC private key, base64.
    private_pkcs8_b64 TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);
