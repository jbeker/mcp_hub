# MCP Hub

A multi-user management and proxy server for [Model Context Protocol](https://modelcontextprotocol.io) servers.

Run one hub, let your users sign in with **passkeys**, pick MCP servers from a **catalog**, configure them with their own keys, and connect any MCP client (Claude Desktop, Claude Code, Claude iOS) to a **single OAuth-protected endpoint** that aggregates all of their servers.

## What it does

- **Catalog** of MCP servers (admin-curated built-ins + user-defined custom servers).
- **Per-user instances**: each user configures servers with their own secrets, encrypted at rest.
- **One proxy endpoint** (`/mcp`, Streamable HTTP) that aggregates every enabled backend, exposing their **tools and prompts** namespaced as `<server>__<name>` and their **resources** as `hub://<server>/<uri>`.
- **Built-in management interface**: a reserved `hub__` toolset on the same endpoint, so the hub can be configured programmatically from any MCP client.
- **Standards-based auth**: passkeys (WebAuthn) authenticate humans; the hub is its own OAuth 2.1 Authorization Server (PKCE, Dynamic Client Registration, ES256 JWTs, JWKS) for MCP clients.

Backends can be **stdio** servers (launched as subprocesses with `uvx`/`npx`) or **remote HTTP** servers (proxied with a static auth header).

## Architecture

```
 Claude Desktop / Code / iOS
        │  Streamable HTTP MCP + OAuth 2.1 Bearer
        ▼
   reverse proxy (TLS — your responsibility)
        ▼
 ┌──────────────── MCP Hub (one binary) ─────────────────┐
 │ Web UI (passkey login, catalog, instance config)      │
 │ OAuth 2.1 AS: /.well-known/* /authorize /token JWKS   │
 │ MCP proxy /mcp: token → user → backend fan-out        │
 └───────────┬───────────────────────────┬───────────────┘
             ▼ stdio subprocess           ▼ remote HTTP
        zabbix, homeassistant, …      memory, …
             │
        SQLite (users, passkeys, catalog, instances,
                encrypted secrets, OAuth state)
```

TLS is intentionally **out of scope** — run the hub behind a reverse proxy (Caddy, nginx, Traefik) that terminates TLS and forwards to port 8080.

## Quick start (Docker)

```bash
export HUB_BASE_URL="https://hub.example.com"          # public URL, no trailing slash
export HUB_MASTER_KEY="$(openssl rand -base64 32)"     # 32 bytes, base64 — keep this safe!
export HUB_BOOTSTRAP_ADMIN="yourhandle"                # first account must use this handle
docker compose up -d
```

Then open `https://hub.example.com/register`, create the admin account with a passkey (the **first** account needs no invite and becomes the admin), and start adding servers from the catalog.

Registration is **invite-only**: every account after the first must redeem a single-use invite code. As the admin, generate codes under **Manage invites** on the dashboard (or with `hub__create_invite`) and hand them out. See [Inviting users](#inviting-users).

> The runtime image bundles **Node.js** (`npx`) and **uv** (`uvx`) because stdio backends run as child processes inside the container.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `HUB_BASE_URL` | yes | — | Public base URL; OAuth issuer, MCP resource id, WebAuthn origin. No trailing slash. |
| `HUB_MASTER_KEY` | yes | — | base64-encoded 32-byte key. Encrypts secrets at rest and signs cookies. |
| `HUB_RP_ID` | no | host of base URL | WebAuthn relying-party id (registrable domain). |
| `HUB_BOOTSTRAP_ADMIN` | no | — | If set, the first registration must use this handle (and becomes admin). |
| `HUB_ALLOW_OPEN_REGISTRATION` | no | `false` | Escape hatch: when `true`, anyone may self-register **without an invite**. Leave `false` to keep registration invite-only. |
| `HUB_DB_PATH` | no | `/data/hub.db` | SQLite database path. |
| `HUB_ENV_DIR` | no | `/data/envs` | Where prebuilt virtualenvs for git-sourced servers live (keep on the data volume). |
| `HUB_LISTEN` | no | `0.0.0.0:8080` | Bind address. |
| `HUB_MAX_BACKENDS_PER_USER` | no | `16` | Max backends per client session. |
| `HUB_MAX_BACKENDS_GLOBAL` | no | `128` | Max concurrent backends across all users. |
| `HUB_BACKEND_IDLE_SECS` | no | `300` | Backend idle reclamation window. |

## Connecting a client

Point any MCP client at `https://hub.example.com/mcp`. The client will discover the
authorization server (RFC 9728 / RFC 8414), register itself (RFC 7591), and run the
OAuth flow — you'll log in with your passkey and approve access in the browser.

Claude Code, for example:

```bash
claude mcp add --transport http hub https://hub.example.com/mcp
```

Once connected, your servers' tools and prompts appear namespaced (`zabbix__host_get`, …),
their resources as `hub://zabbix/…`, and the
`hub__*` tools let you manage your configuration from inside the client.

### Management tools (`hub__`)

| Tool | Who | Description |
|---|---|---|
| `hub__whoami` | user | Current user + configured servers |
| `hub__list_catalog` | user | Browse the catalog |
| `hub__list_my_servers` | user | Your instances + each backend's last connection status (`runtime_status`/`runtime_detail`) |
| `hub__add_server` | user | Add a catalog server |
| `hub__configure` / `hub__set_secret` | user | Provide credentials |
| `hub__enable` / `hub__disable` / `hub__remove` | user | Manage instances |
| `hub__list_users` | admin | List users |
| `hub__catalog_upsert` / `hub__catalog_remove` | admin | Manage the catalog |
| `hub__create_invite` / `hub__list_invites` / `hub__revoke_invite` | admin | Manage invite codes |
| `hub__create_recovery` | admin | Issue a one-time account-recovery code |

Newly added/enabled servers take effect on the next client session.

## Inviting users

Registration is closed by default: the first account bootstraps the admin, and
every later account must redeem a **single-use invite code**.

As an admin, create a code one of two ways:

- **Web UI:** dashboard → **Manage invites** → *Generate invite*. The code is
  shown **once** — copy it then.
- **From an MCP client:** call `hub__create_invite` (optionally with a `note`);
  the returned `code` is shown once.

Hand the code to the new user. They register at `/register`, entering the code
alongside their handle and display name. The code is consumed the moment their
account is created, so it cannot be reused.

Only the SHA-256 of each code is stored, so codes can never be recovered from the
database — `hub__list_invites` and the web list show status and a short id, not
the code. Revoke an unused code with `hub__revoke_invite` (or the **Revoke**
button); used codes are kept for audit.

To allow open self-registration instead (no invite needed), set
`HUB_ALLOW_OPEN_REGISTRATION=true`.

## Passkeys and account recovery

Auth is passkey-only, so a lost device must not mean a lost account. Two
safeguards:

- **Multiple passkeys.** On the **Account** page (`/account`), a signed-in user
  enrolls additional passkeys — a second device or a hardware key. The hub
  refuses to remove your *last* passkey, so you cannot lock yourself out from the
  UI. Enroll a backup key early.
- **Admin recovery codes.** If a user loses every passkey, an admin issues a
  one-time recovery code (Invites page → *Recovery code*, or
  `hub__create_recovery`). The user enters their handle and the code at
  `/recover` and enrolls a fresh passkey on their **existing** account. Recovery
  codes share the invite protections: 128-bit, stored only as a hash, single-use.

## Running a server from a GitHub repo

A catalog entry with `transport: "git"` is **built once** into a virtualenv on the data
volume; connecting then runs that prebuilt environment directly — no fetch, no install — so
startup stays fast. Updates are explicit: you push to GitHub, then run an update.

Add the catalog entry (admin, via `hub__catalog_upsert` or `catalog/builtins.json`):

```json
{
  "slug": "my-mcp",
  "name": "My MCP",
  "transport": "git",
  "runtime": "python",
  "repo": "https://github.com/you/my-mcp",
  "git_ref": "main",
  "entry": "my-mcp",
  "supported": true,
  "secret_schema": [
    { "name": "MY_TOKEN", "label": "API token", "secret": true, "required": true }
  ]
}
```

- `entry` is the console-script your package defines; use `"module": "pkg.server"` instead to run
  `python -m pkg.server`.
- `git_ref` is the branch or tag to track; pin a tag or commit for reproducibility.

Then, as a user:

1. `hub__add_server` → `{ "catalog_slug": "my-mcp", "namespace": "mine" }`
2. `hub__update_server` → `{ "namespace": "mine" }` — builds it (the one slow step).
3. `hub__set_secret` for any credentials, then connect.

**Updating after you push:** run `hub__update_server` again (or the "Update from repository"
button on the server's page). It resolves the branch tip; if nothing changed it's a no-op,
otherwise it rebuilds in the background and the next session uses the new code. The previously
built version keeps serving until the rebuild succeeds.

Notes:
- v1 supports **Python (uv)** git sources; the repo must be `pip`-installable (has a
  `pyproject.toml`). The image ships `git` + `uv`; packages needing C build tools may need a
  customized image.
- **Public repos only** for now — a private repo would need a token, which isn't yet handled
  cleanly.

## Security notes

- Secrets **and the OAuth signing key** are encrypted at rest with XChaCha20-Poly1305 using
  `HUB_MASTER_KEY`; plaintext only exists in memory while a backend is being launched, and is
  never logged. A database compromise alone cannot decrypt secrets or forge tokens.
- Access tokens are short-lived (15 min) ES256 JWTs bound to the `/mcp` resource (audience) and
  pinned to the active key id; refresh tokens are stored hashed and **rotated with reuse
  detection** — replaying a rotated token revokes the whole session.
- OAuth uses PKCE (S256, mandatory), exact-match `redirect_uri`, and a per-session **CSRF token**
  on the consent and management forms. Responses carry `X-Frame-Options`, `nosniff`, and a CSP
  that forbids inline scripts.
- Backend config keys are restricted to each catalog entry's declared schema, so a user cannot
  inject arbitrary process environment (e.g. `LD_PRELOAD`) into a spawned backend.
- Registration is invite-only. Invite codes carry 128 bits of entropy, are stored only as a
  SHA-256 hash, and are consumed by a single atomic update so a code cannot be redeemed twice.
- **Back up `HUB_MASTER_KEY`** — losing it makes every stored secret, signing key, and session
  unrecoverable. Run only behind a TLS-terminating reverse proxy, and rate-limit `/auth/*`,
  `/token`, and `/register` there.
- Some MCP servers are inherently local to a developer's machine (e.g. IDE bridges, desktop-app
  tools) and are not meant to be centralized here.
- Backends needing interactive upstream OAuth (e.g. GitHub's hosted MCP) are flagged
  `supported: false` in the catalog and deferred to a later version.

## Development

```bash
cargo test                                   # unit + integration tests
cargo build --example mock_mcp_server        # mock backend used by e2e tests
cargo run                                     # needs HUB_BASE_URL + HUB_MASTER_KEY
```

### Verifying against a real client

1. `cargo run` with `HUB_BASE_URL=http://localhost:8080` and a `HUB_MASTER_KEY`.
   (For passkeys over plain HTTP, `localhost` is treated as a secure context by browsers.)
2. Register an admin passkey at `http://localhost:8080/register`.
3. Add and configure a server (e.g. `zabbix`) via the web UI or the `hub__` tools.
4. Connect with the MCP Inspector or a Claude client and confirm the namespaced tools work:
   ```bash
   npx @modelcontextprotocol/inspector
   ```

## License

MIT OR Apache-2.0
