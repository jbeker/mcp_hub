//! A user's configured server instances and their encrypted secrets.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use sqlx::SqlitePool;

use crate::catalog::{self, ServerDef};
use crate::crypto::{Sealed, SecretBox};
use crate::util::{new_id, now_unix};

/// Namespace reserved for the built-in management interface (see M6).
pub const RESERVED_NAMESPACE: &str = "hub";

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

/// Resolve the runtime definition (from catalog or the inline custom def).
pub async fn resolve_def(pool: &SqlitePool, inst: &Instance) -> Result<ServerDef> {
    if let Some(def) = &inst.custom_def {
        return Ok(def.clone());
    }
    let cid = inst
        .catalog_server_id
        .as_deref()
        .ok_or_else(|| anyhow!("instance has neither catalog reference nor custom def"))?;
    let entry = catalog::get(pool, cid)
        .await?
        .ok_or_else(|| anyhow!("catalog entry no longer exists"))?;
    Ok(entry.to_def())
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
