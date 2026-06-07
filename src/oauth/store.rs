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
    pub family_id: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_refresh(
    pool: &SqlitePool,
    token_hash: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    resource: Option<&str>,
    family_id: &str,
    ttl_secs: i64,
) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scope, resource, family_id, consumed, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(scope)
    .bind(resource)
    .bind(family_id)
    .bind(now)
    .bind(now + ttl_secs)
    .execute(pool)
    .await
    .context("inserting refresh token")?;
    Ok(())
}

/// The outcome of presenting a refresh token at the token endpoint.
pub enum RefreshOutcome {
    /// Valid first use; the token is now marked consumed.
    Valid(RefreshToken),
    /// An already-consumed token was replayed — the family must be revoked.
    Replayed { family_id: String },
    /// Unknown or expired.
    Missing,
}

/// Columns selected from `oauth_refresh_tokens` when consuming a token.
type RefreshRow = (String, String, String, Option<String>, String, bool, i64);

/// Atomically consume a refresh token, detecting replay of a rotated token.
pub async fn consume_refresh(pool: &SqlitePool, token_hash: &str) -> Result<RefreshOutcome> {
    let mut tx = pool.begin().await?;
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT client_id, user_id, scope, resource, family_id, consumed, expires_at
         FROM oauth_refresh_tokens WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((client_id, user_id, scope, resource, family_id, consumed, expires_at)) = row else {
        tx.commit().await?;
        return Ok(RefreshOutcome::Missing);
    };

    if expires_at < now_unix() {
        sqlx::query("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(RefreshOutcome::Missing);
    }

    if consumed {
        tx.commit().await?;
        return Ok(RefreshOutcome::Replayed { family_id });
    }

    // First use: mark consumed so a later replay is detected.
    sqlx::query("UPDATE oauth_refresh_tokens SET consumed = 1 WHERE token_hash = ?")
        .bind(token_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(RefreshOutcome::Valid(RefreshToken {
        client_id,
        user_id,
        scope,
        resource,
        family_id,
    }))
}

/// Revoke every token in a family (used when reuse is detected).
pub async fn revoke_family(pool: &SqlitePool, family_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE family_id = ?")
        .bind(family_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// One OAuth client a user has connected (an authorized MCP client).
#[derive(Debug, Clone)]
pub struct Connection {
    pub client_id: String,
    pub client_name: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// List the OAuth clients a user has live refresh tokens for — i.e. the MCP
/// clients currently connected to their account.
pub async fn list_user_connections(pool: &SqlitePool, user_id: &str) -> Result<Vec<Connection>> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT client_id, MIN(created_at), MAX(created_at) FROM oauth_refresh_tokens \
         WHERE user_id = ? AND expires_at > ? GROUP BY client_id ORDER BY MAX(created_at) DESC",
    )
    .bind(user_id)
    .bind(now_unix())
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for (client_id, first_seen, last_seen) in rows {
        // The human-friendly name comes from the client's DCR metadata.
        let client_name = get_client(pool, &client_id).await?.and_then(|c| {
            c.metadata
                .get("client_name")
                .and_then(|v| v.as_str().map(String::from))
        });
        out.push(Connection {
            client_id,
            client_name,
            first_seen,
            last_seen,
        });
    }
    Ok(out)
}

/// Revoke a single connection: delete the user's refresh tokens for one client.
/// Outstanding access tokens (short-lived JWTs) expire on their own within the
/// access-token TTL. Returns the number of tokens removed.
pub async fn revoke_user_client(pool: &SqlitePool, user_id: &str, client_id: &str) -> Result<u64> {
    let res = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_id = ? AND client_id = ?")
        .bind(user_id)
        .bind(client_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Revoke every refresh token for a user (used when disabling the account).
pub async fn revoke_all_user_tokens(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
