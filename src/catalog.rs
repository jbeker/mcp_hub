//! The directory of MCP servers: built-in (admin-curated) and user-custom
//! definitions, plus the secret schema that drives configuration forms.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::util::{new_id, now_unix};

fn default_true() -> bool {
    true
}

/// One configurable input a server needs (an environment variable for stdio
/// backends, or a header/token for remote ones).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretField {
    /// Environment variable / config key name, e.g. `ZABBIX_TOKEN`.
    pub name: String,
    /// Human label shown in the UI.
    #[serde(default)]
    pub label: String,
    /// Whether the value is sensitive (encrypted at rest, masked in the UI).
    #[serde(default = "default_true")]
    pub secret: bool,
    /// Whether the field must be provided before the server can run.
    #[serde(default = "default_true")]
    pub required: bool,
}

/// A resolved server definition — what the proxy needs to launch/connect a
/// backend. Produced from either a catalog entry or a user's custom def.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `"stdio"`, `"http"`, or `"git"`.
    pub transport: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub secret_schema: Vec<SecretField>,
    // Git source (transport == "git").
    /// HTTPS git URL of the repository.
    #[serde(default)]
    pub repo: Option<String>,
    /// Branch or tag to track (defaults to `main`).
    #[serde(default)]
    pub git_ref: Option<String>,
    /// Console-script name to run from the built virtualenv.
    #[serde(default)]
    pub entry: Option<String>,
    /// Or a module to run with `python -m`.
    #[serde(default)]
    pub module: Option<String>,
}

/// A catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogServer {
    #[serde(default)]
    pub id: String,
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub transport: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub secret_schema: Vec<SecretField>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default = "default_true")]
    pub supported: bool,
}

impl CatalogServer {
    /// Project to the runtime definition used by the proxy.
    pub fn to_def(&self) -> ServerDef {
        ServerDef {
            name: self.name.clone(),
            description: self.description.clone(),
            transport: self.transport.clone(),
            command: self.command.clone(),
            args: self.args.clone(),
            url: self.url.clone(),
            runtime: self.runtime.clone(),
            secret_schema: self.secret_schema.clone(),
            repo: self.repo.clone(),
            git_ref: self.git_ref.clone(),
            entry: self.entry.clone(),
            module: self.module.clone(),
        }
    }
}

/// Row shape as stored in SQLite.
#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    slug: String,
    name: String,
    description: String,
    transport: String,
    command: Option<String>,
    args_json: String,
    url: Option<String>,
    runtime: String,
    secret_schema_json: String,
    repo: Option<String>,
    git_ref: Option<String>,
    entry: Option<String>,
    module: Option<String>,
    is_builtin: bool,
    supported: bool,
}

impl Row {
    fn into_server(self) -> CatalogServer {
        CatalogServer {
            id: self.id,
            slug: self.slug,
            name: self.name,
            description: self.description,
            transport: self.transport,
            command: self.command,
            args: serde_json::from_str(&self.args_json).unwrap_or_default(),
            url: self.url,
            runtime: self.runtime,
            secret_schema: serde_json::from_str(&self.secret_schema_json).unwrap_or_default(),
            repo: self.repo,
            git_ref: self.git_ref,
            entry: self.entry,
            module: self.module,
            is_builtin: self.is_builtin,
            supported: self.supported,
        }
    }
}

const SELECT: &str = "SELECT id, slug, name, description, transport, command, args_json, url, runtime, secret_schema_json, repo, git_ref, entry, module, is_builtin, supported FROM catalog_servers";

pub async fn list(pool: &SqlitePool) -> Result<Vec<CatalogServer>> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} ORDER BY name"))
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Row::into_server).collect())
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<CatalogServer>> {
    let row: Option<Row> = sqlx::query_as(&format!("{SELECT} WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Row::into_server))
}

pub async fn get_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<CatalogServer>> {
    let row: Option<Row> = sqlx::query_as(&format!("{SELECT} WHERE slug = ?"))
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Row::into_server))
}

/// Insert or update a catalog entry, keyed by slug. Returns the entry id.
pub async fn upsert(
    pool: &SqlitePool,
    server: &CatalogServer,
    created_by: Option<&str>,
) -> Result<String> {
    let existing = get_by_slug(pool, &server.slug).await?;
    let id = existing.as_ref().map(|s| s.id.clone()).unwrap_or_else(new_id);
    let args_json = serde_json::to_string(&server.args)?;
    let schema_json = serde_json::to_string(&server.secret_schema)?;

    if existing.is_some() {
        sqlx::query(
            "UPDATE catalog_servers SET name=?, description=?, transport=?, command=?, args_json=?, url=?, runtime=?, secret_schema_json=?, repo=?, git_ref=?, entry=?, module=?, is_builtin=?, supported=? WHERE id=?",
        )
        .bind(&server.name)
        .bind(&server.description)
        .bind(&server.transport)
        .bind(&server.command)
        .bind(&args_json)
        .bind(&server.url)
        .bind(&server.runtime)
        .bind(&schema_json)
        .bind(&server.repo)
        .bind(&server.git_ref)
        .bind(&server.entry)
        .bind(&server.module)
        .bind(server.is_builtin)
        .bind(server.supported)
        .bind(&id)
        .execute(pool)
        .await
        .context("updating catalog entry")?;
    } else {
        sqlx::query(
            "INSERT INTO catalog_servers (id, slug, name, description, transport, command, args_json, url, runtime, secret_schema_json, repo, git_ref, entry, module, is_builtin, supported, created_by, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&server.slug)
        .bind(&server.name)
        .bind(&server.description)
        .bind(&server.transport)
        .bind(&server.command)
        .bind(&args_json)
        .bind(&server.url)
        .bind(&server.runtime)
        .bind(&schema_json)
        .bind(&server.repo)
        .bind(&server.git_ref)
        .bind(&server.entry)
        .bind(&server.module)
        .bind(server.is_builtin)
        .bind(server.supported)
        .bind(created_by)
        .bind(now_unix())
        .execute(pool)
        .await
        .context("inserting catalog entry")?;
    }
    Ok(id)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM catalog_servers WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Seed the built-in catalog from the embedded definitions. Idempotent.
pub async fn seed_builtins(pool: &SqlitePool) -> Result<()> {
    const BUILTINS: &str = include_str!("../catalog/builtins.json");
    let mut servers: Vec<CatalogServer> =
        serde_json::from_str(BUILTINS).context("parsing embedded builtins.json")?;
    for s in &mut servers {
        s.is_builtin = true;
        if s.id.is_empty() {
            s.id = new_id();
        }
        upsert(pool, s, None).await?;
    }
    tracing::info!(count = servers.len(), "seeded built-in catalog");
    Ok(())
}
