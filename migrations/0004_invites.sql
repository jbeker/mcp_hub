-- Single-use invite codes for closed (invite-only) registration.
--
-- After the first account (which bootstraps the admin and needs no code), every
-- new user must redeem an unused invite. Only the SHA-256 of each code is
-- stored, so the plaintext exists only in the admin's browser at creation and in
-- the registrant's request; a database leak yields no usable codes.

CREATE TABLE invites (
    code_hash  TEXT PRIMARY KEY,          -- base64url(sha256(code))
    note       TEXT NOT NULL DEFAULT '',  -- admin label, e.g. who it is for
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER,                    -- NULL until redeemed
    used_by    TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_invites_unused ON invites(used_at);
