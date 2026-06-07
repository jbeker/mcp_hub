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
    /// Seed the example catalog on a *fresh* (empty) database. Never overwrites
    /// existing entries. Set false to start with an empty, UI-managed catalog.
    pub seed_catalog: bool,
    /// Backend lifecycle limits.
    pub limits: Limits,
}

/// Limits governing backend MCP server processes/connections.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_backends_per_user: usize,
    pub max_backends_global: usize,
    pub backend_idle_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_backends_per_user: 16,
            max_backends_global: 128,
            backend_idle_secs: 300,
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
        // Default true so a fresh install has example entries to start from; the
        // seed only runs against an empty catalog, so it is harmless thereafter.
        let seed_catalog = opt("HUB_SEED_CATALOG")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);

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

        Ok(Self {
            base_url,
            rp_id,
            listen,
            db_path,
            env_dir,
            master_key,
            bootstrap_admin,
            allow_open_registration,
            seed_catalog,
            limits,
        })
    }

    /// The MCP proxy endpoint URL (also the OAuth resource identifier).
    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_host() {
        assert_eq!(host_of("https://hub.example.com/mcp").as_deref(), Some("hub.example.com"));
        assert_eq!(host_of("http://localhost:8080").as_deref(), Some("localhost"));
        assert_eq!(host_of("hub.example.com").as_deref(), Some("hub.example.com"));
    }

    #[test]
    fn master_key_must_be_32_bytes() {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(parse_master_key(&key).is_ok());
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        assert!(parse_master_key(&short).is_err());
    }
}
