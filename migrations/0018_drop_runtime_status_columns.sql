-- Runtime status is ephemeral observability state, rewritten on every spawn
-- attempt; it now lives in process memory (AppState.runtime_status), keeping
-- the pool's status churn off the database's single write lock. Persisted
-- values were stale lies after every restart anyway — keep-warm rebuilds the
-- real picture within a minute. Like the rest of the in-memory state, this
-- assumes the single hub process per database the architecture already
-- requires.
ALTER TABLE user_server_instances DROP COLUMN runtime_status;
ALTER TABLE user_server_instances DROP COLUMN runtime_detail;
ALTER TABLE user_server_instances DROP COLUMN runtime_checked_at;
