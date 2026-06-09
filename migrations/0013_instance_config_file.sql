-- One encrypted configuration file per stdio instance.
--
-- Some stdio MCP servers need a config file on disk rather than env vars. The
-- contents are sealed with the same XChaCha20-Poly1305 SecretBox used for
-- instance_secrets (nonce + ciphertext); at launch the file is written into the
-- instance's working directory and its path exposed via MCP_CONFIG_FILE.

CREATE TABLE instance_config_files (
    instance_id TEXT PRIMARY KEY REFERENCES user_server_instances(id) ON DELETE CASCADE,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
