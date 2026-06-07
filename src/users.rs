//! User accounts and their registered passkey credentials.

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use webauthn_rs::prelude::Passkey;

use crate::util::{new_id, now_unix};

/// A hub user.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub handle: String,
    pub display_name: String,
    pub is_admin: bool,
    pub created_at: i64,
}

/// Number of users currently registered.
pub async fn count(pool: &SqlitePool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn find_by_handle(pool: &SqlitePool, handle: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, handle, display_name, is_admin, created_at FROM users WHERE handle = ?",
    )
    .bind(handle)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn find_by_id(pool: &SqlitePool, id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, handle, display_name, is_admin, created_at FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, handle, display_name, is_admin, created_at FROM users ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(users)
}

/// Create a user with a freshly generated id.
pub async fn create(
    pool: &SqlitePool,
    id: &str,
    handle: &str,
    display_name: &str,
    is_admin: bool,
) -> Result<User> {
    let created_at = now_unix();
    sqlx::query(
        "INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(handle)
    .bind(display_name)
    .bind(is_admin)
    .bind(created_at)
    .execute(pool)
    .await
    .context("inserting user")?;
    Ok(User {
        id: id.to_string(),
        handle: handle.to_string(),
        display_name: display_name.to_string(),
        is_admin,
        created_at,
    })
}

// ---------------------------------------------------------------------------
// Passkey credential storage
// ---------------------------------------------------------------------------

/// Load all passkeys registered to a user (for authentication ceremonies).
pub async fn passkeys_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Passkey>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT passkey_json FROM webauthn_credentials WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (json,) in rows {
        let pk: Passkey = serde_json::from_str(&json).context("deserializing stored passkey")?;
        out.push(pk);
    }
    Ok(out)
}

/// Persist a newly registered passkey for a user.
pub async fn insert_credential(
    pool: &SqlitePool,
    user_id: &str,
    passkey: &Passkey,
    name: &str,
) -> Result<()> {
    let json = serde_json::to_string(passkey).context("serializing passkey")?;
    sqlx::query(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey_json, name, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(passkey.cred_id().as_ref())
    .bind(json)
    .bind(name)
    .bind(now_unix())
    .execute(pool)
    .await
    .context("inserting credential")?;
    Ok(())
}

/// Find the owning user id for a credential id (raw bytes).
pub async fn user_for_credential(pool: &SqlitePool, cred_id: &[u8]) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM webauthn_credentials WHERE credential_id = ?")
            .bind(cred_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(id,)| id))
}

/// Persist an updated passkey (e.g. after the signature counter advances).
pub async fn update_credential(pool: &SqlitePool, passkey: &Passkey) -> Result<()> {
    let json = serde_json::to_string(passkey).context("serializing passkey")?;
    sqlx::query("UPDATE webauthn_credentials SET passkey_json = ? WHERE credential_id = ?")
        .bind(json)
        .bind(passkey.cred_id().as_ref())
        .execute(pool)
        .await
        .context("updating credential")?;
    Ok(())
}
