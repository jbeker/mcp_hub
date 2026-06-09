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
    let parsed =
        url::Url::parse(url.trim()).map_err(|_| anyhow!("'{url}' is not a valid URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("remote URL must be an http(s) URL");
    }
    Ok(())
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
    /// Last connection outcome: `ok`, `error`, `skipped`, `unbuilt`, `unknown`.
    pub runtime_status: String,
    /// Human-readable detail for a non-`ok` runtime status (e.g. an error).
    pub runtime_detail: Option<String>,
    /// When the runtime status was last recorded (unix seconds).
    pub runtime_checked_at: Option<i64>,
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
    runtime_status: String,
    runtime_detail: Option<String>,
    runtime_checked_at: Option<i64>,
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
            runtime_status: self.runtime_status,
            runtime_detail: self.runtime_detail,
            runtime_checked_at: self.runtime_checked_at,
        }
    }
}

const SELECT: &str = "SELECT id, user_id, catalog_server_id, custom_def_json, namespace, display_name, enabled, config_json, built_commit, build_status, runtime_status, runtime_detail, runtime_checked_at FROM user_server_instances";

pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Instance>> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} WHERE user_id = ? ORDER BY namespace"))
        .bind(user_id)
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

    get(pool, &id).await?.ok_or_else(|| anyhow!("instance vanished after creation"))
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

/// Record the outcome of the most recent attempt to connect this backend.
pub async fn set_runtime_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE user_server_instances \
         SET runtime_status = ?, runtime_detail = ?, runtime_checked_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(detail)
    .bind(now_unix())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
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
        let Some((name, description, transport, command, args_json, url, runtime, repo, git_ref, entry, module)) =
            cat
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
pub async fn set_config_value(pool: &SqlitePool, instance_id: &str, key: &str, value: &str) -> Result<()> {
    let inst = get(pool, instance_id).await?.ok_or_else(|| anyhow!("no such instance"))?;
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
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT key_name, nonce, ciphertext FROM instance_secrets WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_all(pool)
            .await?;
    let mut out = BTreeMap::new();
    for (key, nonce, ciphertext) in rows {
        let plain = secrets.open(&Sealed { nonce, ciphertext })?;
        out.insert(key, String::from_utf8(plain).context("env value was not UTF-8")?);
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
            bail!("line {}: '{key}' is not a valid environment variable name", i + 1);
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
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT key_name, nonce, ciphertext FROM instance_secrets WHERE instance_id = ?")
            .bind(&inst.id)
            .fetch_all(pool)
            .await?;
    for (key, nonce, ciphertext) in rows {
        let plain = secrets.open(&Sealed { nonce, ciphertext })?;
        let value = String::from_utf8(plain).context("secret was not valid UTF-8")?;
        env.insert(key, value);
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
    decrypt_config_file(pool, secrets, instance_id).await
}

/// Decrypt an instance's config file for launch, or `None` if unset. Plaintext
/// exists only in memory here until the launcher writes it to disk.
pub async fn resolved_config_file(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
) -> Result<Option<String>> {
    decrypt_config_file(pool, secrets, instance_id).await
}

async fn decrypt_config_file(
    pool: &SqlitePool,
    secrets: &SecretBox,
    instance_id: &str,
) -> Result<Option<String>> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT nonce, ciphertext FROM instance_config_files WHERE instance_id = ?")
            .bind(instance_id)
            .fetch_optional(pool)
            .await?;
    let Some((nonce, ciphertext)) = row else {
        return Ok(None);
    };
    let plain = secrets.open(&Sealed { nonce, ciphertext })?;
    Ok(Some(
        String::from_utf8(plain).context("config file was not valid UTF-8")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::validate_remote_url;

    #[test]
    fn remote_url_validation() {
        assert!(validate_remote_url("https://memory.example.com/mcp").is_ok());
        assert!(validate_remote_url("http://10.0.0.5:8080/mcp").is_ok());
        assert!(validate_remote_url("ftp://example.com").is_err());
        assert!(validate_remote_url("not a url").is_err());
        assert!(validate_remote_url("").is_err());
    }
}
