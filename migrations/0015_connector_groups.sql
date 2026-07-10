-- Named connector groups: each group of a user's backend servers is exposed as
-- its own MCP endpoint at /mcp/<slug>, added to clients as a separate
-- connector. This keeps every connector's tool count under client-side caps
-- (claude.ai truncates a connector's tool registry at 256 tools).
--
-- Groups are per-user: the slug is resolved against the authenticated user, so
-- two users may use the same slug without conflict. Membership rows cascade on
-- both group delete and instance delete — removing a backend silently drops it
-- from its groups; the group itself remains (possibly empty).

CREATE TABLE connector_groups (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,       -- lowercase [a-z0-9-]; path segment of /mcp/<slug>
    name       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, slug)
);
CREATE INDEX idx_groups_user ON connector_groups(user_id);

CREATE TABLE connector_group_members (
    group_id    TEXT NOT NULL REFERENCES connector_groups(id) ON DELETE CASCADE,
    instance_id TEXT NOT NULL REFERENCES user_server_instances(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, instance_id)
);
