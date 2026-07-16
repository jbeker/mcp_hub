-- Hub-level settings, sealed at rest like instance_secrets. Currently holds
-- the metrics API key ('metrics_api_key') that gates GET /metrics; the shape
-- is generic so later hub-wide settings need no new table.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);
