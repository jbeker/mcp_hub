-- Authorization codes are 10-minute, single-use handshake state; they now
-- live in process memory (AppState.auth_codes), which assumes the single hub
-- process per database the architecture already requires (backend pool,
-- reload epochs and sessions are all in-memory). Any rows here are dead —
-- a code issued by a previous process could never be exchanged anyway.
DROP TABLE oauth_auth_codes;
