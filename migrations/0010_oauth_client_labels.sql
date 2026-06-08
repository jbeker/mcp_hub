-- Per-user labels for connected OAuth (MCP) clients. MCP clients register via
-- Dynamic Client Registration and often share identical default names (several
-- "Claude"), so the Account page lets a user give each connection a custom name
-- and a freeform note. Scoped per user because oauth_clients is global (no user
-- column); the (user_id, client_id) key keeps one user's labels invisible to
-- another's.

CREATE TABLE oauth_client_labels (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    name       TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
