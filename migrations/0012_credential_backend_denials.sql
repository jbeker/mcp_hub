-- Per-credential backend access control. A row means a specific credential (an
-- OAuth client, or a personal access token) is DENIED one of the user's backend
-- MCP servers. Absence of a row = allowed, so a new credential — and any newly
-- added backend — is reachable by default; users opt out per credential on the
-- Account page.
--
-- `credential_id` is polymorphic (oauth client_id or PAT id), so it has no FK;
-- PAT-revoke cleanup is explicit in code. `instance_id` cascades so removing a
-- backend drops its denials, and `user_id` cascades on account deletion.

CREATE TABLE credential_backend_denials (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,          -- 'oauth' | 'pat'
    credential_id   TEXT NOT NULL,          -- oauth client_id, or PAT id
    instance_id     TEXT NOT NULL REFERENCES user_server_instances(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (credential_type, credential_id, instance_id)
);
CREATE INDEX idx_cred_denials ON credential_backend_denials(credential_type, credential_id);
