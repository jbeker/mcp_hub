-- Recovery codes reuse the single-use invite machinery.
--
-- An invite with recovery_user_id set is a *recovery* code: redeeming it does
-- not create an account but binds a new passkey onto that existing user (for a
-- user who has lost all their authenticators). recovery_user_id IS NULL marks a
-- normal registration invite.

ALTER TABLE invites ADD COLUMN recovery_user_id TEXT REFERENCES users(id) ON DELETE CASCADE;
