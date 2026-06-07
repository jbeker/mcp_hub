-- Refresh-token reuse detection.
--
-- Rotated tokens are kept and marked `consumed` rather than deleted, so a
-- replay of an already-used token can be detected. Tokens are grouped into a
-- `family`; detecting reuse revokes the whole family.

ALTER TABLE oauth_refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_refresh_tokens ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_refresh_family ON oauth_refresh_tokens(family_id);
