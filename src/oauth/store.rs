//! Persistence for OAuth clients, authorization codes and refresh tokens.

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::util::now_unix;

/// A registered OAuth client (created via Dynamic Client Registration).
#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub metadata: serde_json::Value,
}

pub async fn create_client(
    pool: &SqlitePool,
    client_id: &str,
    client_secret_hash: Option<&str>,
    redirect_uris: &[String],
    metadata: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris_json, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(client_id)
    .bind(client_secret_hash)
    .bind(serde_json::to_string(redirect_uris)?)
    .bind(serde_json::to_string(metadata)?)
    .bind(now_unix())
    .execute(pool)
    .await
    .context("inserting oauth client")?;
    Ok(())
}

pub async fn get_client(pool: &SqlitePool, client_id: &str) -> Result<Option<Client>> {
    let row: Option<(String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT client_id, client_secret_hash, redirect_uris_json, metadata_json
         FROM oauth_clients WHERE client_id = ?",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    let Some((client_id, secret, uris, meta)) = row else {
        return Ok(None);
    };
    Ok(Some(Client {
        client_id,
        client_secret_hash: secret,
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        metadata: serde_json::from_str(&meta).unwrap_or_else(|_| serde_json::json!({})),
    }))
}

/// An issued authorization code awaiting exchange at the token endpoint.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub resource: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_code(
    pool: &SqlitePool,
    code: &str,
    client_id: &str,
    user_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: &str,
    resource: Option<&str>,
    ttl_secs: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_auth_codes
         (code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, 'S256', ?, ?, ?)",
    )
    .bind(code)
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(scope)
    .bind(resource)
    .bind(now_unix() + ttl_secs)
    .execute(pool)
    .await
    .context("inserting auth code")?;
    Ok(())
}

/// Columns selected from `oauth_auth_codes`.
type AuthCodeRow = (String, String, String, String, String, Option<String>, i64);

/// Atomically consume an authorization code (one-time use). Returns the row if
/// it existed and had not expired.
pub async fn take_code(pool: &SqlitePool, code: &str) -> Result<Option<AuthCode>> {
    let mut tx = pool.begin().await?;
    let row: Option<AuthCodeRow> =
        sqlx::query_as(
            "SELECT client_id, user_id, redirect_uri, code_challenge, scope, resource, expires_at
             FROM oauth_auth_codes WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((client_id, user_id, redirect_uri, code_challenge, scope, resource, expires_at)) = row
    else {
        tx.commit().await?;
        return Ok(None);
    };
    // Delete regardless so a replay cannot reuse it.
    sqlx::query("DELETE FROM oauth_auth_codes WHERE code = ?")
        .bind(code)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    if expires_at < now_unix() {
        return Ok(None);
    }
    Ok(Some(AuthCode {
        client_id,
        user_id,
        redirect_uri,
        code_challenge,
        scope,
        resource,
    }))
}

/// A refresh token record (only the hash is stored).
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub resource: Option<String>,
}

pub async fn insert_refresh(
    pool: &SqlitePool,
    token_hash: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    resource: Option<&str>,
    ttl_secs: i64,
) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scope, resource, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(scope)
    .bind(resource)
    .bind(now)
    .bind(now + ttl_secs)
    .execute(pool)
    .await
    .context("inserting refresh token")?;
    Ok(())
}

/// Look up a (valid, unexpired) refresh token by its hash.
pub async fn get_refresh(pool: &SqlitePool, token_hash: &str) -> Result<Option<RefreshToken>> {
    let row: Option<(String, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT client_id, user_id, scope, resource, expires_at
         FROM oauth_refresh_tokens WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    let Some((client_id, user_id, scope, resource, expires_at)) = row else {
        return Ok(None);
    };
    if expires_at < now_unix() {
        let _ = delete_refresh(pool, token_hash).await;
        return Ok(None);
    }
    Ok(Some(RefreshToken {
        client_id,
        user_id,
        scope,
        resource,
    }))
}

pub async fn delete_refresh(pool: &SqlitePool, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}
