-- Allow an admin to disable a user without deleting them. A disabled user
-- cannot sign in, their existing sessions/tokens are revoked, and the proxy
-- refuses their access tokens.

ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
