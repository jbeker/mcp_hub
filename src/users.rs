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

/// Create a user, granting admin only if this is the very first account.
///
/// Uses `BEGIN IMMEDIATE` so the count-and-insert is serialized: under a race
/// between two first registrations, exactly one observes an empty table and
/// becomes admin.
pub async fn create_admin_if_first(
    pool: &SqlitePool,
    id: &str,
    handle: &str,
    display_name: &str,
) -> Result<User> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .context("starting immediate transaction")?;

    let result: Result<User> = async {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *conn)
            .await?;
        let is_admin = n == 0;
        let created_at = now_unix();
        sqlx::query(
            "INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(handle)
        .bind(display_name)
        .bind(is_admin)
        .bind(created_at)
        .execute(&mut *conn)
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
    .await;

    match result {
        Ok(user) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(user)
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
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

/// Delete a user (cascades to credentials and sessions).
///
/// Used to roll back a half-finished registration when an invite turns out to
/// have been consumed concurrently between the challenge and the response.
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .context("deleting user")?;
    Ok(())
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

/// Display metadata for a registered passkey (no key material).
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// List a user's registered passkeys (metadata only), oldest first.
pub async fn list_credentials(pool: &SqlitePool, user_id: &str) -> Result<Vec<CredentialInfo>> {
    let rows = sqlx::query_as::<_, CredentialInfo>(
        "SELECT id, name, created_at FROM webauthn_credentials \
         WHERE user_id = ? ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Count a user's registered passkeys (used to refuse removing the last one).
pub async fn count_credentials(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}

/// Delete one of a user's passkeys by its row id. Scoped to `user_id` so a user
/// can only remove their own credentials. Returns whether a row was deleted.
pub async fn delete_credential(pool: &SqlitePool, user_id: &str, cred_row_id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
        .bind(cred_row_id)
        .bind(user_id)
        .execute(pool)
        .await
        .context("deleting credential")?;
    Ok(res.rows_affected() >= 1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        let path = std::env::temp_dir().join(format!("mcp_hub_users_{}.db", new_id()));
        crate::db::connect(path.to_str().unwrap()).await.unwrap()
    }

    /// Insert a credential row directly (a real Passkey needs a live ceremony).
    async fn add_cred(pool: &SqlitePool, user_id: &str, row_id: &str) {
        sqlx::query(
            "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey_json, name, created_at)
             VALUES (?, ?, ?, '{}', 'passkey', ?)",
        )
        .bind(row_id)
        .bind(user_id)
        .bind(row_id.as_bytes())
        .bind(now_unix())
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn credential_listing_and_scoped_delete() {
        let pool = pool().await;
        let u = create(&pool, "u", "user", "User", false).await.unwrap();
        add_cred(&pool, &u.id, "c1").await;
        add_cred(&pool, &u.id, "c2").await;

        assert_eq!(count_credentials(&pool, &u.id).await.unwrap(), 2);
        assert_eq!(list_credentials(&pool, &u.id).await.unwrap().len(), 2);

        // Delete is scoped to the owner: another user cannot remove it.
        assert!(!delete_credential(&pool, "someone-else", "c1").await.unwrap());
        assert_eq!(count_credentials(&pool, &u.id).await.unwrap(), 2);

        assert!(delete_credential(&pool, &u.id, "c1").await.unwrap());
        assert_eq!(count_credentials(&pool, &u.id).await.unwrap(), 1);
    }
}
