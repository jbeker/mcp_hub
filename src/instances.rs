//! A user's configured server instances and their encrypted secrets.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::crypto::{Sealed, SecretBox};
use crate::util::{new_id, now_unix};

/// A resolved server definition — everything the proxy needs to launch (stdio)
/// or connect (http) a backend. Stored per-instance in `custom_def_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `"stdio"` or `"http"`. (Legacy `"git"` is normalised to `"stdio"`.)
    pub transport: String,
    /// stdio: the program to exec (argv[0]).
    #[serde(default)]
    pub command: Option<String>,
    /// stdio: the remaining argv.
    #[serde(default)]
    pub args: Vec<String>,
    /// http: the remote endpoint URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Informational runtime label (node / python / remote / …).
    #[serde(default)]
    pub runtime: String,
    /// Optional git repository to build a cached venv from (stdio only).
    #[serde(default)]
    pub repo: Option<String>,
    /// Branch or tag to build (defaults to `main`).
    #[serde(default)]
    pub git_ref: Option<String>,
    // ---- Legacy git fields (old data). New servers use `command`/`args`. ----
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
}

impl ServerDef {
    /// Normalise legacy shapes: collapse `transport == "git"` to `"stdio"`, and
    /// derive a command line from a legacy `entry`/`module` when none is set, so
    /// the rest of the code only ever deals with `command` + `args`.
    pub fn normalized(mut self) -> ServerDef {
        if self.transport == "git" {
            self.transport = "stdio".into();
        }
        if self.command.is_none() {
            if let Some(entry) = self.entry.clone() {
                self.command = Some(entry);
            } else if let Some(module) = self.module.clone() {
                self.command = Some("python".into());
                let mut args = vec!["-m".to_string(), module];
                args.append(&mut self.args);
                self.args = args;
            }
        }
        self
    }

    /// True for a git-sourced stdio backend (has a non-empty repo, not http).
    pub fn is_git(&self) -> bool {
        self.transport != "http" && self.repo.as_deref().is_some_and(|r| !r.trim().is_empty())
    }
}

/// What a backend advertised to the hub the last time it was probed (Test
/// connection / Refresh capabilities). Cached as JSON in
/// `user_server_instances.capabilities_json`. Persists rmcp's own wire shapes;
/// if a future rmcp upgrade can no longer parse an old row, the cache simply
/// reads as "never fetched" and one refresh re-captures it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesSnapshot {
    /// When the snapshot was captured (unix seconds).
    pub fetched_at: i64,
    /// The server's `initialize` result: protocol version, capabilities,
    /// serverInfo (name/version), instructions.
    pub server: rmcp::model::InitializeResult,
    /// Tool definitions under their *original* (un-namespaced) names.
    #[serde(default)]
    pub tools: Vec<rmcp::model::Tool>,
    #[serde(default)]
    pub prompts: Vec<rmcp::model::Prompt>,
    #[serde(default)]
    pub resources: Vec<rmcp::model::Resource>,
    #[serde(default)]
    pub resource_templates: Vec<rmcp::model::ResourceTemplate>,
}

/// Namespace reserved for the built-in management interface (see M6).
pub const RESERVED_NAMESPACE: &str = "hub";

/// Reserved per-instance config key that sets/overrides an http backend's
/// remote URL. Lets each user point a shared `http` catalog entry at their own
/// endpoint instead of the catalog's default.
pub const URL_KEY: &str = "MCP_URL";

/// Env var exposing the absolute path of an instance's config file (when one is
/// attached). Referenceable as `${MCP_CONFIG_FILE}` in the command line.
pub const CONFIG_FILE_ENV: &str = "MCP_CONFIG_FILE";

/// Fixed on-disk name the config file is written under, inside the instance's
/// working directory. Tools reach it via [`CONFIG_FILE_ENV`].
pub const CONFIG_FILE_NAME: &str = "config";

/// Validate a user-supplied remote backend URL (http/https only).
pub fn validate_remote_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| anyhow!("'{url}' is not a valid URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("remote URL must be an http(s) URL");
    }
    // A `#fragment` is never sent on the wire and almost always signals a
    // copy-paste mistake; reject it so the stored URL is exactly what connects.
    if parsed.fragment().is_some() {
        bail!("remote URL must not contain a '#' fragment");
    }
    // Plaintext http is only safe to a loopback host (a sidecar on the same
    // machine); anywhere else it would send the bearer credential in the clear.
    if parsed.scheme() == "http" && !host_is_loopback(&parsed) {
        bail!("http is only allowed for loopback addresses; use https");
    }
    Ok(())
}

/// True when the URL's host is a loopback literal (`localhost`, `127.0.0.0/8`,
/// or `::1`). A bare hostname that merely *resolves* to loopback is not treated
/// as loopback here — that DNS-time decision belongs to [`check_backend_host`].
fn host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Validate a backend URL and, when `block_private` is set, refuse one whose
/// host resolves to a loopback/private/link-local/unspecified address — an
/// anti-SSRF guard. Resolution is best-effort: a host that cannot be resolved
/// at validation time is allowed through (it will simply fail to connect),
/// since this also runs at config-save time when the target may be offline.
pub fn check_backend_host(url: &str, block_private: bool) -> Result<()> {
    validate_remote_url(url)?;
    if !block_private {
        return Ok(());
    }
    let parsed = url::Url::parse(url.trim()).map_err(|_| anyhow!("'{url}' is not a valid URL"))?;
    // A loopback literal is the one private target we *do* allow (sidecar use).
    if host_is_loopback(&parsed) {
        return Ok(());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("remote URL has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (host, port).to_socket_addrs() {
        for addr in addrs {
            if ip_is_private(addr.ip()) {
                bail!(
                    "remote URL host resolves to a non-public address ({})",
                    addr.ip()
                );
            }
        }
    }
    Ok(())
}

/// True for addresses that must never be reachable from a user-configured
/// backend when the SSRF guard is on: loopback, RFC1918/ULA private,
/// link-local, and the unspecified address.
fn ip_is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique-local (fc00::/7) and link-local (fe80::/10); checked by
                // segment since the std helpers are unstable.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// A user-configured server instance.
#[derive(Debug, Clone)]
pub struct Instance {
    pub id: String,
    pub user_id: String,
    pub catalog_server_id: Option<String>,
    pub custom_def: Option<ServerDef>,
    pub namespace: String,
    pub display_name: String,
    pub enabled: bool,
    /// Non-secret configuration values (key -> value).
    pub config: BTreeMap<String, String>,
    /// Commit a git-sourced backend was last built from (`None` if never built).
    pub built_commit: Option<String>,
    /// Build state: `unbuilt`, `ready`, or `error`.
    pub build_status: String,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    user_id: String,
    catalog_server_id: Option<String>,
    custom_def_json: Option<String>,
    namespace: String,
    display_name: String,
    enabled: bool,
    config_json: String,
    built_commit: Option<String>,
    build_status: String,
}

impl Row {
    fn into_instance(self) -> Instance {
        Instance {
            id: self.id,
            user_id: self.user_id,
            catalog_server_id: self.catalog_server_id,
            custom_def: self
                .custom_def_json
                .and_then(|j| serde_json::from_str(&j).ok()),
            namespace: self.namespace,
            display_name: self.display_name,
            enabled: self.enabled,
            config: serde_json::from_str(&self.config_json).unwrap_or_default(),
            built_commit: self.built_commit,
            build_status: self.build_status,
        }
    }
}

const SELECT: &str = "SELECT id, user_id, catalog_server_id, custom_def_json, namespace, display_name, enabled, config_json, built_commit, build_status FROM user_server_instances";

pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Instance>> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} WHERE user_id = ? ORDER BY namespace"))
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Row::into_instance).collect())
}

/// Every instance across all users, for the admin runtime-stats view.
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Instance>> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} ORDER BY user_id, namespace"))
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Row::into_instance).collect())
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<Instance>> {
    let row: Option<Row> = sqlx::query_as(&format!("{SELECT} WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Row::into_instance))
}

/// Fetch an instance ensuring it belongs to `user_id`.
pub async fn get_owned(pool: &SqlitePool, id: &str, user_id: &str) -> Result<Option<Instance>> {
    let inst = get(pool, id).await?;
    Ok(inst.filter(|i| i.user_id == user_id))
}

/// Validate a namespace: lowercase alphanumerics/underscores, not reserved.
pub fn validate_namespace(ns: &str) -> Result<()> {
    if ns.is_empty() || ns.len() > 32 {
        bail!("namespace must be 1–32 characters");
    }
    if ns == RESERVED_NAMESPACE {
        bail!("'{RESERVED_NAMESPACE}' is reserved for the management interface");
    }
    if !ns
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        bail!("namespace may only contain lowercase letters, digits and underscores");
    }
    Ok(())
}

/// Create an instance from a catalog entry or an inline custom definition.
pub async fn create(
    pool: &SqlitePool,
    user_id: &str,
    catalog_server_id: Option<&str>,
    custom_def: Option<&ServerDef>,
    namespace: &str,
    display_name: &str,
) -> Result<Instance> {
    validate_namespace(namespace)?;
    if catalog_server_id.is_none() && custom_def.is_none() {
        bail!("an instance needs either a catalog server or a custom definition");
    }
    let id = new_id();
    let custom_json = match custom_def {
        Some(d) => Some(serde_json::to_string(d)?),
        None => None,
    };
    sqlx::query(
        "INSERT INTO user_server_instances (id, user_id, catalog_server_id, custom_def_json, namespace, display_name, enabled, config_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, '{}', ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(catalog_server_id)
    .bind(&custom_json)
    .bind(namespace)
    .bind(display_name)
    .bind(now_unix())
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow!("you already have a server using the namespace '{namespace}'")
        } else {
            anyhow!(e).context("creating instance")
        }
    })?;

    get(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("instance vanished after creation"))
}

pub async fn set_enabled(pool: &SqlitePool, id: &str, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE user_server_instances SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the build state of a git-sourced instance.
pub async fn set_build_state(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    built_commit: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE user_server_instances SET build_status = ?, built_commit = ? WHERE id = ?")
        .bind(status)
        .bind(built_commit)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Store the latest capabilities snapshot for an instance.
pub async fn set_capabilities_snapshot(
    pool: &SqlitePool,
    id: &str,
    snap: &CapabilitiesSnapshot,
) -> Result<()> {
    sqlx::query("UPDATE user_server_instances SET capabilities_json = ? WHERE id = ?")
        .bind(serde_json::to_string(snap)?)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Load the cached capabilities snapshot. A missing value and a JSON shape we
/// can no longer parse both read as `None` — the UI then shows the
/// "never fetched" state and a refresh re-captures it.
pub async fn get_capabilities_snapshot(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<CapabilitiesSnapshot>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT capabilities_json FROM user_server_instances WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .and_then(|(json,)| json)
        .and_then(|json| serde_json::from_str(&json).ok()))
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM user_server_instances WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Resolve the runtime definition. Every instance now carries its own def in
/// `custom_def_json`; the `pool` argument is retained for call-site stability.
pub async fn resolve_def(_pool: &SqlitePool, inst: &Instance) -> Result<ServerDef> {
    inst.custom_def
        .clone()
        .map(ServerDef::normalized)
        .ok_or_else(|| anyhow!("server '{}' has no definition", inst.namespace))
}

/// One-time data migration (idempotent): convert any instance that still points
/// at the retired catalog into a self-contained def. Snapshots the catalog row
/// into `custom_def_json`, folds the instance's non-secret `config_json` (and any
/// `MCP_URL` override) into the encrypted env, and clears the catalog link. The
/// instance's existing encrypted secrets are keyed by instance id and untouched.
pub async fn migrate_catalog_instances(pool: &SqlitePool, secrets: &SecretBox) -> Result<()> {
    type CatRow = (
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let pending: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, catalog_server_id, config_json FROM user_server_instances \
         WHERE custom_def_json IS NULL AND catalog_server_id IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;

    for (inst_id, cat_id, config_json) in pending {
        let cat: Option<CatRow> = sqlx::query_as(
            "SELECT name, description, transport, command, args_json, url, runtime, repo, git_ref, entry, module \
             FROM catalog_servers WHERE id = ?",
        )
        .bind(&cat_id)
        .fetch_optional(pool)
        .await?;
        let Some((
            name,
            description,
            transport,
            command,
            args_json,
            url,
            runtime,
            repo,
            git_ref,
            entry,
            module,
        )) = cat
        else {
            continue; // catalog row already gone; leave the instance as-is
        };
        let args: Vec<String> = serde_json::from_str(&args_json).unwrap_or_default();
        let mut def = ServerDef {
            name,
            description,
            transport,
            command,
            args,
            url,
            runtime,
            repo,
            git_ref,
            entry,
            module,
        }
        .normalized();

        // Preserve the user's per-instance config: MCP_URL became the http URL;
        // everything else becomes an encrypted env var (without overwriting a
        // real secret of the same name).
        let mut config: BTreeMap<String, String> =
            serde_json::from_str(&config_json).unwrap_or_default();
        if def.transport == "http" {
            if let Some(u) = config.remove("MCP_URL").filter(|u| !u.trim().is_empty()) {
                def.url = Some(u);
            }
        }
        for (key, value) in &config {
            let sealed = secrets.seal(value.as_bytes())?;
            sqlx::query(
                "INSERT INTO instance_secrets (id, instance_id, key_name, nonce, ciphertext) \
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT(instance_id, key_name) DO NOTHING",
            )
            .bind(new_id())
            .bind(&inst_id)
            .bind(key)
            .bind(&sealed.nonce)
            .bind(&sealed.ciphertext)
            .execute(pool)
            .await?;
        }

        let json = serde_json::to_string(&def)?;
        sqlx::query(
            "UPDATE user_server_instances \
             SET custom_def_json = ?, catalog_server_id = NULL, config_json = '{}' WHERE id = ?",
        )
        .bind(json)
        .bind(&inst_id)
        .execute(pool)
        .await?;
        tracing::info!(instance = %inst_id, "migrated catalog-backed instance to a self-contained def");
    }
    Ok(())
}

/// Replace an instance's stored definition (after an edit).
pub async fn update_def(pool: &SqlitePool, instance_id: &str, def: &ServerDef) -> Result<()> {
    let json = serde_json::to_string(def)?;
    sqlx::query("UPDATE user_server_instances SET custom_def_json = ?, catalog_server_id = NULL WHERE id = ?")
        .bind(json)
        .bind(instance_id)
        .execute(pool)
        .await
        .context("updating server definition")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration values: non-secret in config_json, secret encrypted in db
// ---------------------------------------------------------------------------

/// Store a non-secret config value.
pub async fn set_config_value(
    pool: &SqlitePool,
    instance_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let inst = get(pool, instance_id)
        .await?
        .ok_or_else(|| anyhow!("no such instance"))?;
    let mut config = inst.config;
    config.insert(key.to_string(), value.to_string());
    sqlx::query("UPDATE user_server_instances SET config_json = ? WHERE id = ?")
        .bind(serde_json::to_string(&config)?)
        .bind(instance_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Store an encrypted secret value (upsert by key name).
pub async fn set_secret(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
    key_name: &str,
    value: &str,
) -> Result<()> {
    let sealed = secrets.seal(value.as_bytes())?;
    sqlx::query(
        "INSERT INTO instance_secrets (id, instance_id, key_name, nonce, ciphertext)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(instance_id, key_name) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext",
    )
    .bind(new_id())
    .bind(instance_id)
    .bind(key_name)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .execute(pool)
    .await
    .context("storing secret")?;
    Ok(())
}

/// Replace an instance's entire environment with `env` (each value encrypted).
/// Keys not in `env` are removed; this is the "save the whole ENV box" path.
pub async fn replace_env(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
    env: &BTreeMap<String, String>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM instance_secrets WHERE instance_id = ?")
        .bind(instance_id)
        .execute(&mut *tx)
        .await?;
    for (key, value) in env {
        let sealed = secrets.seal(value.as_bytes())?;
        sqlx::query(
            "INSERT INTO instance_secrets (id, instance_id, key_name, nonce, ciphertext) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(new_id())
        .bind(instance_id)
        .bind(key)
        .bind(&sealed.nonce)
        .bind(&sealed.ciphertext)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await.context("saving environment")?;
    Ok(())
}

/// Decrypt an instance's environment for display in the edit form.
pub async fn env_for_edit(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
) -> Result<BTreeMap<String, String>> {
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT key_name, nonce, ciphertext FROM instance_secrets WHERE instance_id = ?",
    )
    .bind(instance_id)
    .fetch_all(pool)
    .await?;
    let mut out = BTreeMap::new();
    for (key, nonce, ciphertext) in rows {
        match secrets.open(&Sealed { nonce, ciphertext }) {
            Ok(plain) => {
                out.insert(
                    key,
                    String::from_utf8(plain).context("env value was not UTF-8")?,
                );
            }
            // A row sealed under a key/format this binary can't read is omitted
            // so the edit form still loads; the user simply re-enters its value.
            Err(_) => tracing::warn!(
                instance = %instance_id,
                key = %key,
                "secret could not be decrypted; omitting from the edit form (needs re-entry)"
            ),
        }
    }
    Ok(out)
}

/// Parse a `KEY=VALUE` env block (one per line; blanks and `#` comments skipped).
pub fn parse_env(text: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {}: expected KEY=VALUE", i + 1))?;
        let key = key.trim();
        let valid = !key.is_empty()
            && key.chars().enumerate().all(|(j, c)| {
                if j == 0 {
                    c.is_ascii_alphabetic() || c == '_'
                } else {
                    c.is_ascii_alphanumeric() || c == '_'
                }
            });
        if !valid {
            bail!(
                "line {}: '{key}' is not a valid environment variable name",
                i + 1
            );
        }
        map.insert(key.to_string(), value.trim().to_string());
    }
    Ok(map)
}

/// Render an env map back into a `KEY=VALUE` block for the edit form.
pub fn render_env(env: &BTreeMap<String, String>) -> String {
    env.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse a single command-line string into `(command, args)` (shell tokenised).
pub fn parse_command(line: &str) -> Result<(Option<String>, Vec<String>)> {
    let parts = shlex::split(line.trim())
        .ok_or_else(|| anyhow!("could not parse the command line (check your quoting)"))?;
    let mut it = parts.into_iter();
    let command = it.next();
    Ok((command, it.collect()))
}

/// Render `(command, args)` back into a single shell-quoted command line.
pub fn render_command(command: &Option<String>, args: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = command {
        parts.push(c.clone());
    }
    parts.extend(args.iter().cloned());
    shlex::try_join(parts.iter().map(String::as_str)).unwrap_or_else(|_| parts.join(" "))
}

/// Stored-secret names that are referenced as `${VAR}` on the command line
/// (`command` + `args`), where their value lands in the child's argv and is
/// readable by any process via `/proc/<pid>/cmdline`. Env-var values, by
/// contrast, sit in `/proc/<pid>/environ`, which is UID-locked. The UI uses this
/// to nudge a user to move such a secret out of argv and into the environment.
/// Order-preserving and de-duplicated by first occurrence.
pub fn secret_refs_in_argv(
    command: &Option<String>,
    args: &[String],
    secret_names: &[String],
) -> Vec<String> {
    let secrets: std::collections::HashSet<&str> =
        secret_names.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    let scan = |text: &str, found: &mut Vec<String>| {
        // Mirror `util::expand_vars`: only the braced `${NAME}` form is a
        // reference. An unterminated `${` ends the scan for that token.
        let mut rest = text;
        while let Some(pos) = rest.find("${") {
            let after = &rest[pos + 2..];
            match after.find('}') {
                Some(end) => {
                    let name = &after[..end];
                    if secrets.contains(name) && !found.iter().any(|f: &String| f == name) {
                        found.push(name.to_string());
                    }
                    rest = &after[end + 1..];
                }
                None => break,
            }
        }
    };
    if let Some(c) = command {
        scan(c, &mut found);
    }
    for a in args {
        scan(a, &mut found);
    }
    found
}

/// Names of secret keys that have a stored value (never returns the values).
pub async fn secret_names(pool: &SqlitePool, instance_id: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT key_name FROM instance_secrets WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

/// Decrypt all secrets and merge with non-secret config into the environment
/// map used to launch a backend. Plaintext exists only in memory here.
pub async fn resolved_env(
    pool: &SqlitePool,
    secrets: &SecretBox,
    inst: &Instance,
) -> Result<BTreeMap<String, String>> {
    let mut env = inst.config.clone();
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT key_name, nonce, ciphertext FROM instance_secrets WHERE instance_id = ?",
    )
    .bind(&inst.id)
    .fetch_all(pool)
    .await?;
    let mut undecryptable = Vec::new();
    for (key, nonce, ciphertext) in rows {
        match secrets.open(&Sealed { nonce, ciphertext }) {
            Ok(plain) => {
                let value = String::from_utf8(plain).context("secret was not valid UTF-8")?;
                env.insert(key, value);
            }
            Err(_) => undecryptable.push(key),
        }
    }
    // Fail with an actionable message rather than launching a backend that is
    // missing its credentials (which would surface as a confusing auth error
    // from the backend itself).
    if !undecryptable.is_empty() {
        undecryptable.sort();
        bail!(
            "secret(s) could not be decrypted — re-enter them in this server's \
             configuration: {}",
            undecryptable.join(", ")
        );
    }
    Ok(env)
}

// ---------------------------------------------------------------------------
// Configuration file: a single small file, encrypted at rest, written into the
// instance's working directory at launch (see proxy::backend::stdio_command).
// ---------------------------------------------------------------------------

/// Store (or replace) an instance's encrypted config file contents.
pub async fn set_config_file(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
    content: &str,
) -> Result<()> {
    let sealed = secrets.seal(content.as_bytes())?;
    sqlx::query(
        "INSERT INTO instance_config_files (instance_id, nonce, ciphertext, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(instance_id) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext",
    )
    .bind(instance_id)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .bind(now_unix())
    .execute(pool)
    .await
    .context("storing config file")?;
    Ok(())
}

/// Remove an instance's config file (no-op if none is stored).
pub async fn clear_config_file(pool: &SqlitePool, instance_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM instance_config_files WHERE instance_id = ?")
        .bind(instance_id)
        .execute(pool)
        .await
        .context("clearing config file")?;
    Ok(())
}

/// Decrypt an instance's config file for the edit form, or `None` if unset.
pub async fn config_file_for_edit(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
) -> Result<Option<String>> {
    // On the edit form, an undecryptable file reads as "none" so the page loads
    // and the user can paste a fresh one.
    decrypt_config_file(pool, secrets, instance_id, true).await
}

/// Decrypt an instance's config file for launch, or `None` if unset. Plaintext
/// exists only in memory here until the launcher writes it to disk.
pub async fn resolved_config_file(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
) -> Result<Option<String>> {
    // At launch, an undecryptable file is a hard error with an actionable
    // message rather than silently launching without it.
    decrypt_config_file(pool, secrets, instance_id, false).await
}

async fn decrypt_config_file(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
    tolerate_undecryptable: bool,
) -> Result<Option<String>> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT nonce, ciphertext FROM instance_config_files WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_optional(pool)
            .await?;
    let Some((nonce, ciphertext)) = row else {
        return Ok(None);
    };
    match secrets.open(&Sealed { nonce, ciphertext }) {
        Ok(plain) => Ok(Some(
            String::from_utf8(plain).context("config file was not valid UTF-8")?,
        )),
        Err(_) if tolerate_undecryptable => {
            tracing::warn!(
                instance = %instance_id,
                "config file could not be decrypted; omitting from the edit form (needs re-entry)"
            );
            Ok(None)
        }
        Err(_) => bail!(
            "the attached config file could not be decrypted — re-save it in this \
             server's configuration"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{check_backend_host, ip_is_private, validate_remote_url, CapabilitiesSnapshot};

    #[test]
    fn remote_url_validation() {
        assert!(validate_remote_url("https://memory.example.com/mcp").is_ok());
        // http is allowed only to a loopback host…
        assert!(validate_remote_url("http://localhost:8080/mcp").is_ok());
        assert!(validate_remote_url("http://127.0.0.1:8080/mcp").is_ok());
        // …not to any other host (would leak the bearer token in the clear).
        assert!(validate_remote_url("http://10.0.0.5:8080/mcp").is_err());
        assert!(validate_remote_url("http://example.com/mcp").is_err());
        // Other rejects: non-http scheme, garbage, empty, stray fragment.
        assert!(validate_remote_url("ftp://example.com").is_err());
        assert!(validate_remote_url("not a url").is_err());
        assert!(validate_remote_url("").is_err());
        assert!(validate_remote_url("https://example.com/mcp#frag").is_err());
    }

    #[test]
    fn private_ip_classification() {
        use std::net::IpAddr;
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                ip_is_private(s.parse::<IpAddr>().unwrap()),
                "{s} should be private"
            );
        }
        for s in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                !ip_is_private(s.parse::<IpAddr>().unwrap()),
                "{s} should be public"
            );
        }
    }

    #[test]
    fn ssrf_guard_blocks_private_when_enabled() {
        // Loopback literal is always allowed (sidecar use).
        assert!(check_backend_host("http://127.0.0.1:9000/mcp", true).is_ok());
        // A literal private IP is blocked only when the guard is on.
        assert!(check_backend_host("https://10.0.0.5/mcp", false).is_ok());
        assert!(check_backend_host("https://10.0.0.5/mcp", true).is_err());
    }

    #[test]
    fn flags_secrets_referenced_in_argv_only() {
        use super::secret_refs_in_argv;
        let secrets = vec!["GITHUB_TOKEN".to_string(), "API_KEY".to_string()];

        // A secret referenced on the command line is flagged.
        let got = secret_refs_in_argv(
            &Some("mcp-remote".into()),
            &[
                "--header".into(),
                "Authorization: Bearer ${GITHUB_TOKEN}".into(),
            ],
            &secrets,
        );
        assert_eq!(got, vec!["GITHUB_TOKEN".to_string()]);

        // Flagged in the command token too, and de-duplicated across argv.
        let got = secret_refs_in_argv(
            &Some("${API_KEY}-runner".into()),
            &["--key=${API_KEY}".into()],
            &secrets,
        );
        assert_eq!(got, vec!["API_KEY".to_string()]);

        // A non-secret `${VAR}` and a malformed reference are ignored; a secret
        // that never appears in argv (only in env) produces nothing.
        let got = secret_refs_in_argv(
            &Some("${TOOL_HOME}/bin/server".into()),
            &["--cfg=${NOT_A_SECRET}".into(), "${API_KEY".into()],
            &secrets,
        );
        assert!(got.is_empty(), "got {got:?}");
    }

    /// The snapshot must survive a JSON round-trip (it is cached in SQLite),
    /// and the list fields must tolerate being absent in stored JSON.
    #[test]
    fn capabilities_snapshot_round_trips() {
        let snap = CapabilitiesSnapshot {
            fetched_at: 1_700_000_000,
            server: rmcp::model::InitializeResult::default(),
            tools: vec![rmcp::model::Tool::new(
                "do_thing",
                "Does the thing",
                std::sync::Arc::new(serde_json::Map::new()),
            )],
            prompts: Vec::new(),
            resources: Vec::new(),
            resource_templates: Vec::new(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: CapabilitiesSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.fetched_at, snap.fetched_at);
        assert_eq!(back.tools.len(), 1);
        assert_eq!(back.tools[0].name, "do_thing");

        // Older/partial rows without the list fields still parse.
        let partial = r#"{"fetched_at":1,"server":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}"#;
        let back: CapabilitiesSnapshot = serde_json::from_str(partial).unwrap();
        assert!(back.tools.is_empty());
    }
}
