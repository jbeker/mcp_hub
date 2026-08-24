//! Environment-driven configuration.
//!
//! All configuration comes from environment variables so the hub can be
//! deployed as a single container with a reverse proxy in front handling TLS.

use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use base64::Engine;

/// Fully resolved runtime configuration.
#[derive(Clone)]
pub struct Config {
    /// Public base URL the hub is reachable at, e.g. `https://hub.example.com`.
    /// Used as the OAuth issuer, the MCP resource identifier and to derive the
    /// WebAuthn relying-party origin. No trailing slash.
    pub base_url: String,
    /// WebAuthn relying-party ID — the registrable domain, e.g. `hub.example.com`.
    pub rp_id: String,
    /// Address the server binds to.
    pub listen: SocketAddr,
    /// Filesystem path to the SQLite database file.
    pub db_path: String,
    /// Directory holding prebuilt virtualenvs for git-sourced backends.
    pub env_dir: String,
    /// 32-byte master key used to encrypt secrets at rest.
    pub master_key: [u8; 32],
    /// Optional handle that is granted admin on first registration.
    pub bootstrap_admin: Option<String>,
    /// Whether anyone may self-register after the first (admin) account exists.
    pub allow_open_registration: bool,
    /// Base UID for the per-user stdio sandbox (`HUB_SANDBOX_UID_BASE`). When set
    /// and the hub runs as root, each user's stdio subprocesses run as
    /// `base + the user's slot`. Unset → no sandbox (dev/test).
    pub sandbox_uid_base: Option<u32>,
    /// Keep every enabled user's pooled backends warm (`HUB_KEEP_WARM`, default
    /// on): a background task binds them at startup and re-touches them every
    /// minute, so a new connection always finds hot tools and a crashed backend
    /// is respawned without waiting for a request. While on, the warmer's touch
    /// counts as use, so `HUB_BACKEND_IDLE_SECS` never fires for warmed users.
    pub keep_warm: bool,
    /// How often the warmer exercises each pooled backend with a real
    /// `tools/list` (`HUB_KEEP_WARM_SECS`, default 300; 0 = never). The cheap
    /// per-minute touch above only checks the process is alive; this deeper
    /// heartbeat keeps the child actually responsive (its pages resident under
    /// host memory/IO pressure) and detects a wedged backend so it can be
    /// respawned.
    pub keep_warm_interval_secs: u64,
    /// Backend lifecycle limits.
    pub limits: Limits,
    /// Per-child OS resource limits applied to stdio backend subprocesses.
    pub child_limits: ChildLimits,
    /// When true (`HUB_BLOCK_PRIVATE_BACKEND_IPS`), an http backend whose host
    /// resolves to a loopback/private/link-local address is rejected — an
    /// anti-SSRF guard so a user-configured remote URL can't reach the
    /// container's own network. Off by default (home/LAN deployments often
    /// point at private IPs on purpose).
    pub block_private_backend_ips: bool,
    /// Allowed `Host` header authorities for the `/mcp` Streamable HTTP endpoint,
    /// enforced by rmcp as an anti-DNS-rebinding measure. Derived from
    /// `HUB_BASE_URL`'s authority plus any comma-separated `HUB_ALLOWED_HOSTS`
    /// (needed when the reverse proxy forwards a Host other than the base URL's).
    /// Empty → rmcp keeps its default loopback-only allowlist (dev/test).
    pub allowed_hosts: Vec<String>,
    /// Browser-session idle timeout in seconds (`HUB_SESSION_IDLE_SECS`). A
    /// session expires this long after its last request; each request slides the
    /// deadline forward. Default 1800 (30 min).
    pub session_idle_ttl_secs: i64,
    /// Browser-session absolute cap in seconds (`HUB_SESSION_ABSOLUTE_SECS`).
    /// A session cannot outlive this from login, regardless of activity.
    /// Default 43200 (12 h). Never less than `session_idle_ttl_secs`.
    pub session_absolute_ttl_secs: i64,
}

/// `setrlimit` caps applied to every stdio backend subprocess, as a last line
/// of defence against a runaway server taking down the container. Each is
/// `None` (the field is 0 / the env var unset) to leave that limit untouched.
#[derive(Clone, Copy, Default)]
pub struct ChildLimits {
    /// `RLIMIT_NPROC` — max processes/threads for the child's UID (`HUB_CHILD_MAX_PROCS`).
    pub max_procs: Option<u64>,
    /// `RLIMIT_DATA` in megabytes (`HUB_CHILD_MAX_MEM_MB`). Deliberately
    /// `RLIMIT_DATA`, not `RLIMIT_AS`: a Node child's V8/Wasm engine *reserves*
    /// ~10 GiB of virtual address space without committing it, which an
    /// `RLIMIT_AS` cap rejects at startup (`WebAssembly.instantiate: Out of
    /// memory`). `RLIMIT_DATA` bounds the heap that is actually written, so
    /// real runaway growth is still caught.
    pub max_mem_mb: Option<u64>,
    /// `RLIMIT_CPU` in seconds of CPU time (`HUB_CHILD_MAX_CPU_SECS`).
    pub max_cpu_secs: Option<u64>,
    /// `RLIMIT_FSIZE` in megabytes (`HUB_CHILD_MAX_FILE_MB`).
    pub max_file_mb: Option<u64>,
}

impl ChildLimits {
    /// True when at least one limit is configured (so the spawn can skip the
    /// `pre_exec` hook entirely when nothing is set).
    pub fn any(&self) -> bool {
        self.max_procs.is_some()
            || self.max_mem_mb.is_some()
            || self.max_cpu_secs.is_some()
            || self.max_file_mb.is_some()
    }
}

/// Limits governing backend MCP server processes/connections.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_backends_per_user: usize,
    pub max_backends_global: usize,
    /// How long a user's pooled backends outlive their last request
    /// (`HUB_BACKEND_IDLE_SECS`); 0 = never reaped. Backends are shared across
    /// that user's MCP sessions, so this is the only thing that shuts them down.
    pub backend_idle_secs: u64,
    /// Per-call wall-clock cap for a proxied backend RPC (`HUB_BACKEND_CALL_TIMEOUT_SECS`);
    /// 0 = no timeout. Stops one wedged backend from hanging a client forever.
    /// Defaults to 90s; set the env var to `0` to opt back into unbounded calls.
    pub backend_call_timeout_secs: u64,
    /// Wall-clock cap on spawning + `initialize`-ing one backend
    /// (`HUB_BACKEND_CONNECT_TIMEOUT_SECS`); 0 = unbounded. A backend that hangs
    /// during its handshake is marked failed instead of stalling the bind.
    pub backend_connect_timeout_secs: u64,
    /// Wall-clock cap on one backend's tools/resources/prompts list call
    /// (`HUB_BACKEND_LIST_TIMEOUT_SECS`); 0 = unbounded. A backend that hangs
    /// mid-list is skipped (partial aggregate) instead of stalling the client.
    pub backend_list_timeout_secs: u64,
    /// How long a bind/reconcile waits for backends to connect before answering
    /// with whatever is ready (`HUB_BIND_BUDGET_SECS`); 0 = wait for all.
    /// Backends that miss the budget keep connecting in the background and
    /// announce themselves via `tools/list_changed` when they arrive.
    pub bind_budget_secs: u64,
    /// Cap on a single backend response's serialized size in megabytes
    /// (`HUB_MAX_RESPONSE_MB`); 0 = uncapped. Bounds memory blow-up from a
    /// backend returning a huge payload.
    pub max_response_mb: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_backends_per_user: 16,
            max_backends_global: 128,
            backend_idle_secs: 900,
            backend_call_timeout_secs: 90,
            backend_connect_timeout_secs: 20,
            backend_list_timeout_secs: 10,
            bind_budget_secs: 5,
            max_response_mb: 0,
        }
    }
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        let base_url = req("HUB_BASE_URL")?;
        let base_url = base_url.trim_end_matches('/').to_string();

        // Derive RP ID from the base URL host unless explicitly overridden.
        let rp_id = match std::env::var("HUB_RP_ID") {
            Ok(v) if !v.is_empty() => v,
            _ => host_of(&base_url)
                .context("could not derive HUB_RP_ID from HUB_BASE_URL; set HUB_RP_ID")?,
        };

        let listen: SocketAddr = opt("HUB_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:8080".to_string())
            .parse()
            .context("HUB_LISTEN must be a valid socket address, e.g. 0.0.0.0:8080")?;

        let db_path = opt("HUB_DB_PATH").unwrap_or_else(|| "./data/hub.db".to_string());
        let env_dir = opt("HUB_ENV_DIR").unwrap_or_else(|| "./data/envs".to_string());

        let master_key = parse_master_key(&req("HUB_MASTER_KEY")?)?;

        let bootstrap_admin = opt("HUB_BOOTSTRAP_ADMIN");
        let allow_open_registration = opt("HUB_ALLOW_OPEN_REGISTRATION")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        // A base of 0 (or unset) disables sandboxing — never run children as root.
        let sandbox_uid_base = opt_parse::<u32>("HUB_SANDBOX_UID_BASE")?.filter(|&b| b > 0);

        // On unless explicitly turned off.
        let keep_warm = opt("HUB_KEEP_WARM")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
        let keep_warm_interval_secs = opt_parse::<u64>("HUB_KEEP_WARM_SECS")?.unwrap_or(300);

        let mut limits = Limits::default();
        if let Some(v) = opt_parse("HUB_MAX_BACKENDS_PER_USER")? {
            limits.max_backends_per_user = v;
        }
        if let Some(v) = opt_parse("HUB_MAX_BACKENDS_GLOBAL")? {
            limits.max_backends_global = v;
        }
        if let Some(v) = opt_parse("HUB_BACKEND_IDLE_SECS")? {
            limits.backend_idle_secs = v;
        }
        if let Some(v) = opt_parse("HUB_BACKEND_CALL_TIMEOUT_SECS")? {
            limits.backend_call_timeout_secs = v;
        }
        if let Some(v) = opt_parse("HUB_BACKEND_CONNECT_TIMEOUT_SECS")? {
            limits.backend_connect_timeout_secs = v;
        }
        if let Some(v) = opt_parse("HUB_BACKEND_LIST_TIMEOUT_SECS")? {
            limits.backend_list_timeout_secs = v;
        }
        if let Some(v) = opt_parse("HUB_BIND_BUDGET_SECS")? {
            limits.bind_budget_secs = v;
        }
        if let Some(v) = opt_parse("HUB_MAX_RESPONSE_MB")? {
            limits.max_response_mb = v;
        }

        // A value of 0 means "leave this limit untouched", same as unset.
        let nonzero =
            |key| -> Result<Option<u64>> { Ok(opt_parse::<u64>(key)?.filter(|&v| v > 0)) };
        let child_limits = ChildLimits {
            max_procs: nonzero("HUB_CHILD_MAX_PROCS")?,
            max_mem_mb: nonzero("HUB_CHILD_MAX_MEM_MB")?,
            max_cpu_secs: nonzero("HUB_CHILD_MAX_CPU_SECS")?,
            max_file_mb: nonzero("HUB_CHILD_MAX_FILE_MB")?,
        };

        let block_private_backend_ips = opt("HUB_BLOCK_PRIVATE_BACKEND_IPS")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        // Host allowlist for the /mcp endpoint (rmcp DNS-rebinding guard): the
        // base URL's own authority, plus any operator-supplied extras for setups
        // where the reverse proxy forwards a different Host.
        let mut allowed_hosts: Vec<String> = Vec::new();
        if let Some(authority) = authority_of(&base_url) {
            allowed_hosts.push(authority);
        }
        if let Some(extra) = opt("HUB_ALLOWED_HOSTS") {
            allowed_hosts.extend(
                extra
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
        allowed_hosts.dedup();

        // Browser-session timeouts. Absolute is clamped to be at least the idle
        // window, so a misconfigured pair can't make the absolute cap the tighter
        // (and confusing) of the two.
        let session_idle_ttl_secs = opt_parse::<i64>("HUB_SESSION_IDLE_SECS")?
            .filter(|&v| v > 0)
            .unwrap_or(1800);
        let session_absolute_ttl_secs = opt_parse::<i64>("HUB_SESSION_ABSOLUTE_SECS")?
            .filter(|&v| v > 0)
            .unwrap_or(43200)
            .max(session_idle_ttl_secs);

        Ok(Self {
            base_url,
            rp_id,
            listen,
            db_path,
            env_dir,
            master_key,
            bootstrap_admin,
            allow_open_registration,
            sandbox_uid_base,
            keep_warm,
            keep_warm_interval_secs,
            limits,
            child_limits,
            block_private_backend_ips,
            allowed_hosts,
            session_idle_ttl_secs,
            session_absolute_ttl_secs,
        })
    }

    /// The base MCP endpoint URL (also its OAuth resource identifier). Serves
    /// only the hub management tools; backend tools live on group endpoints.
    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url)
    }

    /// A connector group's endpoint URL (also its OAuth resource identifier).
    pub fn group_mcp_url(&self, slug: &str) -> String {
        format!("{}/mcp/{}", self.base_url, slug)
    }

    /// Whether cookies should carry the `Secure` attribute (true behind HTTPS).
    pub fn cookie_secure(&self) -> bool {
        self.base_url.starts_with("https://")
    }
}

fn req(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("required environment variable {key} is not set"))
}

fn opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn opt_parse<T: std::str::FromStr>(key: &str) -> Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match opt(key) {
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|e| anyhow!("{key} is invalid: {e}")),
        None => Ok(None),
    }
}

/// Parse the master key, which is a base64-encoded 32-byte value.
fn parse_master_key(s: &str) -> Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("HUB_MASTER_KEY must be valid base64")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("HUB_MASTER_KEY must decode to exactly 32 bytes"))?;
    Ok(arr)
}

/// Extract the host portion of a URL without pulling in a URL parsing crate.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Extract the authority (`host` or `host:port`) of a URL — what a client sends
/// in the `Host` header. Unlike [`host_of`], the port is retained.
fn authority_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_host() {
        assert_eq!(
            host_of("https://hub.example.com/mcp").as_deref(),
            Some("hub.example.com")
        );
        assert_eq!(
            host_of("http://localhost:8080").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            host_of("hub.example.com").as_deref(),
            Some("hub.example.com")
        );
    }

    #[test]
    fn master_key_must_be_32_bytes() {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(parse_master_key(&key).is_ok());
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        assert!(parse_master_key(&short).is_err());
    }
}
