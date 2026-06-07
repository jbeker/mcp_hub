-- Per-instance backend runtime status, recorded each time a client session
-- connects the backend. Lets the UI and hub__ tools explain why a backend is
-- not contributing tools (bad secret, crashed subprocess, capacity, unbuilt)
-- instead of it silently disappearing.

ALTER TABLE user_server_instances ADD COLUMN runtime_status TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE user_server_instances ADD COLUMN runtime_detail TEXT;        -- error/explanation
ALTER TABLE user_server_instances ADD COLUMN runtime_checked_at INTEGER; -- unix seconds
