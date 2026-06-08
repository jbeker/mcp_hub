-- Track where each credential / session / OAuth connection was last used, so the
-- Account page can show the last IP and User-Agent. The hub runs behind a TLS
-- reverse proxy, so the IP is taken from X-Forwarded-For (first hop), falling
-- back to X-Real-IP. All columns are nullable: existing rows have no recorded
-- use, and a request may arrive without the forwarded headers.

-- Passkeys: recorded each time the credential completes an authentication.
ALTER TABLE webauthn_credentials ADD COLUMN last_used_at  INTEGER;
ALTER TABLE webauthn_credentials ADD COLUMN last_ip       TEXT;
ALTER TABLE webauthn_credentials ADD COLUMN last_user_agent TEXT;

-- Browser sessions: recorded at login (the session's origin).
ALTER TABLE web_sessions ADD COLUMN last_ip         TEXT;
ALTER TABLE web_sessions ADD COLUMN last_user_agent TEXT;

-- OAuth refresh tokens: recorded when issued (initial auth or a refresh). The
-- newest non-expired row per client gives a connection's last-seen IP/UA.
ALTER TABLE oauth_refresh_tokens ADD COLUMN last_ip         TEXT;
ALTER TABLE oauth_refresh_tokens ADD COLUMN last_user_agent TEXT;
