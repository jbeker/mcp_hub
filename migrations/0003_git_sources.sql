-- Git-sourced backends.
--
-- A catalog entry with transport='git' is built once from a GitHub repo into a
-- per-instance virtualenv on the data volume; connecting runs that prebuilt
-- environment directly (no fetch/install). Updates are explicit.

-- Source definition on the catalog entry.
ALTER TABLE catalog_servers ADD COLUMN repo TEXT;       -- https git URL
ALTER TABLE catalog_servers ADD COLUMN git_ref TEXT;    -- branch or tag (default main)
ALTER TABLE catalog_servers ADD COLUMN entry TEXT;      -- console script name in the venv
ALTER TABLE catalog_servers ADD COLUMN module TEXT;     -- or a `python -m` module

-- Per-instance build state.
ALTER TABLE user_server_instances ADD COLUMN built_commit TEXT;
ALTER TABLE user_server_instances ADD COLUMN build_status TEXT NOT NULL DEFAULT 'unbuilt';
