# Security Review — MCP Hub

Defensive review of the hub conducted 2026-06-10 against the code on `trunk` (commit `69e03a3`). Four reviewers covered separate surfaces: OAuth/tokens, web/session, crypto/secrets, and sandbox/proxy. Every finding below was verified against the source; each cites `file:line`.

## What the hub already does well

Do not weaken these — they are correct and load-bearing:

- **OAuth core is sound.** PKCE is S256-only and verified constant-time; auth codes are single-use with a 600s TTL consumed atomically in a transaction; `redirect_uri` is exact-matched before any bounce; JWTs pin ES256, issuer, audience, and `kid`; refresh tokens are stored as SHA-256 hashes, rotated on every use, with replay detection that revokes the whole family.
- **Session and CSRF handling is solid.** Cookies are signed, HttpOnly, SameSite=Lax, Secure (when the base URL is https). Login always mints a fresh server-side session (no fixation). Every state-changing POST checks a per-session CSRF token compared in constant time. Logout deletes the server-side row.
- **Crypto primitives are right.** XChaCha20-Poly1305 with a fresh 24-byte OsRng nonce per seal; CSPRNG everywhere; bearer material (refresh tokens, PATs, invite/recovery codes) stored hash-only; the OAuth signing key is encrypted at rest; the master key has no `Debug` impl and is never logged; children get `env_clear()` so they never inherit `HUB_MASTER_KEY`.
- **Sandbox does what it claims.** Per-user UID separation isolates one user's cache, venv, and config from another's. Build-time `pip install` (which runs arbitrary repo code) is dropped to the owner's UID, not root. The system fails closed: no backend or build runs as root when sandboxing is configured but unavailable.
- **Authorization is consistent.** Per-credential backend ACLs are checked on every fan-out path (tools, prompts, resources, and their sub-calls). All web routes resolve through ownership-scoped queries. Admin handlers check `is_admin` before acting.

## Priority fixes

Ordered by risk-reduction per unit of effort. The top three close the widest gaps.

### P0 — do these first

**1. Add resource limits to user subprocesses.** *(sandbox H3)*
`stdio_command` (`src/proxy/backend.rs:294-321`) sets uid/gid/env and nothing else — no `setrlimit`, cgroup, or quota anywhere in the tree. One user's command can fork-bomb, exhaust memory and OOM-kill the hub (PID 1), spin CPU forever, or fill `/data` (git venvs and uv/npm caches have no quota) and break every other user plus the database. This is the easiest full-container denial of service.
*Fix:* apply per-child `RLIMIT_NPROC`, `RLIMIT_AS`, `RLIMIT_CPU`, and `RLIMIT_FSIZE` via a `pre_exec` hook, or run children under a per-user cgroup v2 slice (`pids.max`, `memory.max`, `cpu.max`). Add a disk quota on the cache and env dirs, and a wall-clock cap on backend liveness.

**2. Isolate subprocess and backend networking.** *(sandbox H1, H2)*
Sandboxed stdio children share the hub's network namespace (`backend.rs:251-322`), so a user's command can reach `127.0.0.1:8080` (the hub itself), `169.254.169.254` (cloud metadata / IMDS), and anything else on the Docker network — UID separation does nothing here. Separately, HTTP backends are an SSRF primitive: `validate_remote_url` (`src/instances.rs:90-97`) accepts any host, including loopback, link-local, and RFC1918 (a test explicitly allows `http://10.0.0.5:8080/mcp`), and the hub attaches the backend's `AUTHORIZATION` header to the request. reqwest follows up to 10 redirects by default, so even an allow-listed host can 302 the hub to the metadata IP.
*Fix:* run stdio children in a network namespace with egress filtering. For HTTP backends, validate the resolved IP (deny loopback, link-local, RFC1918, ULA, the hub's own bind address), disable or bound redirect following, and re-validate after each redirect. At minimum, block `169.254.169.254` and loopback with nftables in the container.

> **Update (egress + /proc):** The HTTP-backend SSRF guard now exists (`HUB_BLOCK_PRIVATE_BACKEND_IPS`, re-resolved at connect time — see `instances.rs check_backend_host`). For stdio children, `docker-entrypoint.sh` installs an nftables ruleset (`HUB_EGRESS_HARDENING`, needs `CAP_NET_ADMIN`) that drops sandbox-UID (`skuid >= HUB_SANDBOX_UID_BASE`) egress to link-local/cloud-metadata and to the hub's own loopback port, and remounts `/proc` with `hidepid=2` (`HUB_HIDEPID`, needs `CAP_SYS_ADMIN`) — which also closes the shared-`/proc` argv-secret leak noted in cross-cutting theme 1. RFC1918 stays allowed (internal backends rely on it), so this is a targeted block, not a full network namespace. Both steps are best-effort and skipped (logged) when the capability is absent. The hub also warns in the server UI when a stored secret is referenced in argv rather than passed via env (`instances::secret_refs_in_argv`).

**3. Add rate limiting to authentication and OAuth endpoints.** *(web M1/M2, oauth M2)*
No rate-limit layer exists anywhere (`src/lib.rs:123-219`); `Cargo.toml` has no limiter dependency in use. `/token`, `/authorize`, `/register`, and the five `/auth/*` routes are all unthrottled. Token secrets are 256-bit, so this is not credential brute-forcing — it is DB-write and CPU DoS, plus audit-log flooding. Relatedly, the WebAuthn ceremony store (`src/auth/webauthn.rs:34`, cap 4096) is shared across login/register/recover and only evicts expired entries, so one IP can fill it and return 503 to every legitimate sign-in for up to five minutes.
*Fix:* add a per-IP rate-limit layer (e.g. `tower_governor`) in front of `/auth/*`, `/token`, `/authorize`, and `/register`, keyed on the forwarded client IP. Add a per-IP cap on in-flight WebAuthn ceremonies and LRU-evict the oldest rather than rejecting.

### P1 — close real gaps soon

**4. Bind ciphertexts to their row with AAD.** *(crypto M2)*
`SecretBox::seal` (`src/crypto.rs:38-48`) uses no associated data, so a ciphertext is not bound to where it lives. An attacker with database write access (and no master key) can copy another user's `(nonce, ciphertext)` from `instance_secrets` into their own instance's row; the hub decrypts it and hands back the plaintext via the edit form or injects it into a backend the attacker controls. The same applies to config files and the signing-key blob.
*Fix:* pass AAD via `chacha20poly1305::aead::Payload { msg, aad }` with `aad = instance_id || key_name` (and `kid` for the signing key). Accept-and-rewrite old rows on first successful no-AAD decrypt to migrate.

**5. Remove the plaintext-PEM signing-key fallback.** *(crypto M1)*
`unseal_pem` (`src/oauth/keys.rs:171-174`) accepts any stored value starting with `-----BEGIN` as a plaintext key. A database-write attacker can replace the signing key with their own plaintext PEM; after the next restart the hub signs with the attacker's key and they forge admin JWTs offline. This defeats the "a database compromise alone cannot forge tokens" claim in the same file's comment.
*Fix:* on boot, re-seal any plaintext PEM found and rewrite the row, then remove the fallback.

**6. Check `user.disabled` at the token endpoint and in the web session path.** *(oauth M1, web M4)*
Both OAuth grant handlers (`src/oauth/token.rs:129-131`, `:183-185`) check that the user exists but not whether they are disabled, and `deactivate_user` (`src/web.rs:1825-1831`) leaves `oauth_auth_codes` intact. An auth code issued in the window before disable can be exchanged afterward, spawning a fresh refresh-token family that survives "revoke everything" and reactivates the moment the account is re-enabled. The web session extractor (`src/auth/session.rs:210-224`) has the same gap, currently masked only because disable deletes sessions.
*Fix:* reject disabled users in both grant handlers and in `user_for_session`; delete the user's `oauth_auth_codes` rows in `deactivate_user`.

**7. Harden decrypted file and database permissions.** *(crypto M3, M4)*
`write_config_file` (`src/proxy/backend.rs:334-351`) writes the decrypted config with umask-default permissions and chmods afterward; with sandboxing off (a legal config) the file stays world-readable for the backend's lifetime. `db::connect` (`src/db.rs:13-41`) sets no file mode, and the 0600 lock runs only when sandboxing is on and the hub is root — so a non-sandboxed deployment leaves the database (WebAuthn credentials, session ids, token hashes, encrypted secrets) at 0644.
*Fix:* create the workdir `0o700` and the config file `0o600` before writing content; chmod the database files 0600 at startup regardless of sandbox mode.

**8. Implement the idle reaper the config already promises.** *(sandbox M4)*
`backend_idle_secs` (default 300) is parsed but never consumed (`src/config.rs:45,53,96`); no idle reclamation exists. Backends are released only when a session rebinds or drops. Combined with the global cap of 128 (`src/proxy/server.rs:147`), a user opening many sessions can exhaust the global semaphore and deny service to everyone.
*Fix:* shut down backends with no recent activity and release their permit; account global slots per user, not just per session.

**9. Cap proxied response size and time.** *(sandbox M1)*
The live `call_tool`/`read_resource` path (`src/proxy/backend.rs:222-234`, `176-192`) forwards backend output with no size or time limit. A malicious or compromised backend — or an SSRF target from finding 2 — can return a multi-gigabyte result and OOM the hub.
*Fix:* cap response sizes and apply a per-call timeout on the proxied path.

### P2 — defense in depth

- **Sweep expired OAuth rows.** Expired/consumed `oauth_refresh_tokens` and abandoned `oauth_auth_codes` are deleted only when re-presented (`src/oauth/store.rs:212-218`), growing unbounded. Add a periodic `DELETE ... WHERE expires_at < ?`. *(oauth M4)*
- **Purge stale OAuth clients, or rate-limit registration.** The 10,000-client cap (`src/oauth/register.rs:40-51`) becomes a lockout: an attacker fills it and no legitimate client can register again. Rows have no expiry and nothing cleans them up. *(oauth M3)*
- **Validate registered redirect URIs.** `register.rs:60-68` accepts any parseable URL including plain `http://` to arbitrary hosts. Require https, loopback http, or private-use schemes, and reject fragments. *(oauth L1)*
- **Validate repo URLs at write time.** `add_server`/`edit_server` (`src/proxy/management.rs:526,609`) accept any parseable URL for `repo`; the https-only check runs only at build time. Call `validate_repo` in both handlers. *(sandbox M2)*
- **Stop trusting `X-Forwarded-For` blindly.** `client_ip` (`src/auth/mod.rs:42-51`) takes the first XFF hop, which the client controls; this pollutes the audit trail. Take the last untrusted hop or make the trusted-proxy count configurable, and validate it parses as an IP. *(web L4)*
- **Add `form-action 'self'` to the CSP** (`src/lib.rs:198-199`) so a future HTML-injection foothold cannot exfiltrate form contents. *(web L3)*
- **Mask secrets in the edit form.** `server_detail` (`src/web.rs:405-421`) decrypts the full env and config back into the HTML form, so a hijacked session exfiltrates every credential with simple GETs. Render masked placeholders and only overwrite changed keys. *(crypto L4)*
- **Genericize error messages to clients.** Web handlers render `{e:#}` anyhow chains and `management::internal` sends `e.to_string()` (`src/proxy/management.rs:975-978`), leaking filesystem paths and sandbox internals. Apply the log-then-genericize pattern the OAuth surface already uses. *(crypto L5)*
- **Derive subkeys with HKDF.** The master key is used raw for encryption, and the CSRF token is an `H(key||msg)` construction subject to length extension (`src/auth/session.rs:72-79`). Use HKDF-SHA256 with distinct `info` labels and make the CSRF token an HMAC. *(crypto L1)*
- **Drop the unused `danger-allow-state-serialisation` feature** from `Cargo.toml:41` — ceremony state is never serialized, so the flag is dead weight that invites future misuse. *(web L1)*

## Cross-cutting themes

Three patterns explain most of the findings:

1. **The sandbox is a single layer — UID separation — and the deployment leans on it.** It does not bound network, CPU, memory, disk, PIDs, `/proc`, or `/tmp`. The highest-impact fixes (1 and 2) add the missing layers. Several "low" findings (shared `/proc` exposing argv secrets, shared `/tmp` races) also fall away once you add PID and mount namespaces.

2. **Several protections only engage when sandboxing is on and the hub runs as root.** Database and file permission locking are gated this way, yet non-sandboxed operation is a documented, legal config. Make at-rest hardening unconditional (finding 7).

3. **Nothing is rate-limited or swept.** The hub assumes a benign, low-volume client. Authenticated and unauthenticated endpoints alike can be flooded, and several tables grow without bound. Findings 3 and the P2 sweep items address this.

The database-write-attacker findings (4, 5) are worth taking seriously despite needing write access: that access is exactly what a SQL-injection bug or a backup leak would grant, and these two fixes are small and localized.
