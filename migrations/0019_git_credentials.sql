-- Per-user git credentials, keyed by git host.
--
-- A user stores at most one HTTPS token per host (github.com,
-- gitlab.company.com, ...). When one of their git-sourced servers is built, the
-- credential whose host matches the repo URL's host is handed to git — through
-- the environment, never argv, since /proc/<pid>/cmdline is world readable (see
-- gitsrc::credential_env). The token is sealed with the same
-- XChaCha20-Poly1305 SecretBox as instance_secrets (nonce + ciphertext) and is
-- never rendered back to the UI or returned by any tool; only its metadata is.
--
-- `host` is normalised on write (lowercase, scheme/path stripped, default port
-- 443 dropped) so a lookup is an exact match on the repo URL's host — never a
-- suffix match, which would offer github.com's token to github.com.evil.net.
--
-- No separate user index: UNIQUE(user_id, host) already serves the per-user
-- listing query as a prefix.

CREATE TABLE git_credentials (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,              -- 'github.com' or 'gl.example.com:8443'
    username     TEXT NOT NULL DEFAULT '',   -- HTTP basic user ('' -> x-access-token)
    nonce        BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,              -- sealed access token
    label        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE(user_id, host)
);
