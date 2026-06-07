-- Per-user sandbox slot. A small stable integer per user; the actual sandbox
-- UID a stdio subprocess runs as is HUB_SANDBOX_UID_BASE + sandbox_uid. Lets the
-- hub drop each user's subprocesses to a distinct unprivileged UID so they can
-- neither read the hub's master key (/proc/1/environ) nor each other's.

ALTER TABLE users ADD COLUMN sandbox_uid INTEGER;
