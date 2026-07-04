# MCP Hub

A multi-user management and proxy server for [Model Context Protocol](https://modelcontextprotocol.io) servers.

Run one hub, let your users sign in with **passkeys**, add their own MCP servers, and connect any MCP client (Claude Desktop, Claude Code, Claude iOS) to a **single OAuth-protected endpoint** that aggregates all of their servers.

## What it does

- **User-defined servers**: every user adds their own MCP servers — pick a transport (stdio or http) and fill in the details. No central catalog.
- **Per-user config**, encrypted at rest: a stdio server is a command line + an environment-variables block; an http server is a URL + env.
- **One proxy endpoint** (`/mcp`, Streamable HTTP) that aggregates every enabled backend, exposing their **tools and prompts** namespaced as `<server>__<name>` and their **resources** as `hub://<server>/<uri>`.
- **Built-in management interface**: a reserved `hub__` toolset on the same endpoint, so servers can be added/edited programmatically from any MCP client.
- **Standards-based auth**: passkeys (WebAuthn) authenticate humans; the hub is its own OAuth 2.1 Authorization Server (PKCE, Dynamic Client Registration, ES256 JWTs, JWKS) for MCP clients.
- **Sandboxed stdio**: each user's stdio subprocesses run as a distinct unprivileged UID, so a user's command cannot read the master key or other users' secrets.

A **stdio** server runs a command (`uvx …`, `npx …`) as a subprocess; it may optionally point at a **git repo**, which the hub builds once into a cached virtualenv. An **http** server is a remote endpoint the hub proxies (with an `AUTHORIZATION` env var sent as the request header).

## Architecture

```
 Claude Desktop / Code / iOS
        │  Streamable HTTP MCP + OAuth 2.1 Bearer
        ▼
   reverse proxy (TLS — your responsibility)
        ▼
 ┌──────────────── MCP Hub (one binary) ─────────────────┐
 │ Web UI (passkey login, add/edit your own servers)     │
 │ OAuth 2.1 AS: /.well-known/* /authorize /token JWKS   │
 │ MCP proxy /mcp: token → user → backend fan-out        │
 └───────────┬───────────────────────────┬───────────────┘
             ▼ stdio subprocess           ▼ remote HTTP
        zabbix, homeassistant, …      memory, …
             │
        SQLite (users, passkeys, server instances,
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

Then open `https://hub.example.com/register`, create the admin account with a passkey (the **first** account needs no invite and becomes the admin), and start adding your own servers.

Registration is **invite-only**: every account after the first must redeem a single-use invite code. As the admin, generate codes under **Manage invites** on the dashboard (or with `hub__create_invite`) and hand them out. See [Inviting users](#inviting-users).

> The runtime image bundles **Node.js** (`npx`) and **uv** (`uvx`) because stdio backends run as child processes inside the container.

> **Optional runtime hardening.** The entrypoint can hide other users' `/proc` entries (`hidepid=2`) and firewall sandbox-UID network egress, but each needs a Linux capability the container isn't granted by default. To enable, add them to your compose service (the hub still starts without them, logging that each was skipped):
> ```yaml
>     cap_add:
>       - SYS_ADMIN   # HUB_HIDEPID: remount /proc hidepid=2
>       - NET_ADMIN   # HUB_EGRESS_HARDENING: sandbox-UID egress firewall
> ```

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `HUB_BASE_URL` | yes | — | Public base URL; OAuth issuer, MCP resource id, WebAuthn origin. No trailing slash. |
| `HUB_MASTER_KEY` | yes | — | base64-encoded 32-byte key. Encrypts secrets at rest and signs cookies. |
| `HUB_RP_ID` | no | host of base URL | WebAuthn relying-party id (registrable domain). |
| `HUB_ALLOWED_HOSTS` | no | host of base URL | Comma-separated extra `Host` authorities accepted on `/mcp` (anti-DNS-rebinding). The base URL's own host is always allowed; set this only if your reverse proxy forwards a different `Host` (e.g. `hub.internal,hub.example.com:8443`). |
| `HUB_SESSION_IDLE_SECS` | no | `1800` (30 min) | Browser-session idle timeout: a login expires this long after its last request (each request slides it forward). Sessions also end on browser close. |
| `HUB_SESSION_ABSOLUTE_SECS` | no | `43200` (12 h) | Absolute cap on a browser session from login, regardless of activity. Clamped to be ≥ `HUB_SESSION_IDLE_SECS`. |
| `HUB_BOOTSTRAP_ADMIN` | no | — | If set, the first registration must use this handle (and becomes admin). |
| `HUB_ALLOW_OPEN_REGISTRATION` | no | `false` | Escape hatch: when `true`, anyone may self-register **without an invite**. Leave `false` to keep registration invite-only. |
| `HUB_SANDBOX_UID_BASE` | no | `20000` (in image) | Base UID for the per-user stdio sandbox; each user runs as `base + slot`. Requires the container to run as root (it does). `0`/unset disables it. |
| `HUB_DB_PATH` | no | `/data/hub.db` | SQLite database path. |
| `HUB_ENV_DIR` | no | `/data/envs` | Where prebuilt virtualenvs for git-sourced servers live (keep on the data volume). |
| `HUB_LISTEN` | no | `0.0.0.0:8080` | Bind address. |
| `HUB_HIDEPID` | no | `1` (in image) | Remount `/proc` with `hidepid=2` so a sandbox UID can't read another user's process `cmdline`/`environ`. Needs `CAP_SYS_ADMIN`; skipped (logged) without it. `0` disables. |
| `HUB_EGRESS_HARDENING` | no | `1` (in image) | Install nftables rules dropping sandbox-UID egress to link-local/cloud-metadata and the hub's own loopback port (RFC1918 stays allowed). Needs `CAP_NET_ADMIN`; skipped (logged) without it. `0` disables. |
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
| `hub__list_my_servers` | user | Your servers, their launch command and last connection status |
| `hub__add_server` | user | Add a server (`transport` + `command`/`url`/`repo`/`env`) |
| `hub__edit_server` | user | Change a server's command / url / repo |
| `hub__set_env` | user | Replace a server's environment variables |
| `hub__update_server` | user | (Re)build a git-sourced server from its repo |
| `hub__enable` / `hub__disable` / `hub__remove` | user | Manage your servers |
| `hub__list_users` | admin | List users (with admin/disabled status) |
| `hub__disable_user` / `hub__enable_user` / `hub__delete_user` | admin | Suspend or remove an account |
| `hub__create_invite` / `hub__list_invites` / `hub__revoke_invite` | admin | Manage invite codes |
| `hub__create_recovery` | admin | Issue a one-time account-recovery code |

Newly added/enabled servers take effect on the next client session.

## Adding servers

Every user manages their own servers — there is no shared catalog. Add one from
the dashboard (**+ Add a server**) or with `hub__add_server`:

- **stdio**: a command line (e.g. `uvx zabbix-mcp-server`) plus environment
  variables. Optionally give a **git repo**; the hub builds it once into a cached
  virtualenv and runs the command inside it (see below).
- **http**: a remote URL the hub proxies. Put an auth token in the `AUTHORIZATION`
  env var and it is sent as the request's `Authorization` header.

Environment variables are entered as `KEY=VALUE` lines, encrypted at rest, and
shown back to you (your own data) when editing.

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

A stdio server with a **repository** is **built once** into a virtualenv on the data
volume; connecting then runs that prebuilt environment directly — no fetch, no install — so
startup stays fast. Updates are explicit: you push to GitHub, then run an update.

Add it (web form, or `hub__add_server`):

```jsonc
{
  "namespace": "mine",
  "transport": "stdio",
  "command": "my-mcp",          // a console script your package defines, or `python -m pkg.server`
  "repo": "https://github.com/you/my-mcp",
  "git_ref": "main",            // branch/tag to track; pin a tag for reproducibility
  "env": { "MY_TOKEN": "..." }
}
```

The `command`'s first word resolves to the built venv's `bin/` (so a console
script or `python` comes from the repo's environment). Then:

1. `hub__update_server` → `{ "namespace": "mine" }` builds it (the one slow step).
2. Connect — the cached venv runs directly.

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

## Managing access

- **Your connections.** The **Account** page lists the MCP clients you have
  authorized and your active browser sessions. *Disconnect* revokes a client's
  refresh token; *Sign out other sessions* ends every browser session but the
  current one.
- **Admin user management.** The **Users** page (and `hub__disable_user` /
  `hub__enable_user` / `hub__delete_user`) let an admin suspend or remove an
  account. Disabling ends the user's sessions and revokes their tokens at once;
  deleting also removes their servers, secrets and passkeys. An admin cannot act
  on their own account or the last remaining admin.

Because access tokens are short-lived JWTs, a revoked or disabled user keeps any
already-issued access token until it expires — but the proxy re-checks the
account on every request, so revocation takes effect within seconds, well inside
the 15-minute token lifetime.

## Security notes

- Secrets **and the OAuth signing key** are encrypted at rest with XChaCha20-Poly1305 using
  `HUB_MASTER_KEY`; plaintext only exists in memory while a backend is being launched, and is
  never logged. A database compromise alone cannot decrypt secrets or forge tokens.
- **stdio servers run arbitrary commands**, so each user's stdio subprocesses are dropped to a
  distinct unprivileged UID (`HUB_SANDBOX_UID_BASE + slot`). A non-root child cannot read the
  hub's master key (`/proc/1/environ`), the secrets DB (locked to root), or another user's
  subprocess environment. Network and non-secret filesystem reads are *not* restricted, so keep
  the hub invite-only and trust your users. The container runs as **root on purpose** so it can
  drop children to those UIDs.
- Access tokens are short-lived (15 min) ES256 JWTs bound to the `/mcp` resource (audience) and
  pinned to the active key id; refresh tokens are stored hashed and **rotated with reuse
  detection** — replaying a rotated token revokes the whole session.
- OAuth uses PKCE (S256, mandatory), exact-match `redirect_uri`, and a per-session **CSRF token**
  on the consent and management forms. Responses carry `X-Frame-Options`, `nosniff`, and a CSP
  that forbids inline scripts.
- Registration is invite-only. Invite codes carry 128 bits of entropy, are stored only as a
  SHA-256 hash, and are consumed by a single atomic update so a code cannot be redeemed twice.
- **Back up `HUB_MASTER_KEY`** — losing it makes every stored secret, signing key, and session
  unrecoverable. Run only behind a TLS-terminating reverse proxy, and rate-limit `/auth/*`,
  `/token`, and `/register` there.
- Some MCP servers are inherently local to a developer's machine (e.g. IDE bridges, desktop-app
  tools) and are not meant to be centralized here.

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
3. Add a server (e.g. `uvx zabbix-mcp-server` + env) via the web UI or `hub__add_server`.
4. Connect with the MCP Inspector or a Claude client and confirm the namespaced tools work:
   ```bash
   npx @modelcontextprotocol/inspector
   ```

## License

MIT OR Apache-2.0
