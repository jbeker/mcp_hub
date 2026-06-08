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
    pub disabled: bool,
}

/// Columns selected into [`User`].
const USER_COLS: &str = "id, handle, display_name, is_admin, created_at, disabled";

/// Number of users currently registered.
pub async fn count(pool: &SqlitePool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn find_by_handle(pool: &SqlitePool, handle: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users WHERE handle = ?"
    ))
    .bind(handle)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn find_by_id(pool: &SqlitePool, id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users ORDER BY created_at"
    ))
    .fetch_all(pool)
    .await?;
    Ok(users)
}

/// Number of admin accounts (used to refuse removing the last admin).
pub async fn count_admins(pool: &SqlitePool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// The user's sandbox slot (a small stable per-user integer), if assigned.
pub async fn sandbox_slot(pool: &SqlitePool, user_id: &str) -> Result<Option<i64>> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT sandbox_uid FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(slot,)| slot))
}

/// Assign a sandbox slot to every user that lacks one (startup backfill). Slots
/// are dense and monotonic; new users get one at creation.
pub async fn assign_sandbox_slots(pool: &SqlitePool) -> Result<()> {
    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE sandbox_uid IS NULL ORDER BY created_at, id")
            .fetch_all(pool)
            .await?;
    for (id,) in ids {
        sqlx::query(
            "UPDATE users SET sandbox_uid = (SELECT COALESCE(MAX(sandbox_uid), -1) + 1 FROM users) WHERE id = ?",
        )
        .bind(&id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Enable or disable a user. A disabled user cannot sign in or use the proxy.
pub async fn set_disabled(pool: &SqlitePool, id: &str, disabled: bool) -> Result<()> {
    sqlx::query("UPDATE users SET disabled = ? WHERE id = ?")
        .bind(disabled)
        .bind(id)
        .execute(pool)
        .await
        .context("updating user disabled flag")?;
    Ok(())
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
            "INSERT INTO users (id, handle, display_name, is_admin, created_at, sandbox_uid) \
             VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sandbox_uid), -1) + 1 FROM users))",
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
            disabled: false,
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
        "INSERT INTO users (id, handle, display_name, is_admin, created_at, sandbox_uid) \
         VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sandbox_uid), -1) + 1 FROM users))",
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
        disabled: false,
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
    pub last_used_at: Option<i64>,
    pub last_ip: Option<String>,
    pub last_user_agent: Option<String>,
}

/// List a user's registered passkeys (metadata only), oldest first.
pub async fn list_credentials(pool: &SqlitePool, user_id: &str) -> Result<Vec<CredentialInfo>> {
    let rows = sqlx::query_as::<_, CredentialInfo>(
        "SELECT id, name, created_at, last_used_at, last_ip, last_user_agent \
         FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Record that a passkey just completed an authentication: stamp the time and
/// the request's IP / User-Agent. Looked up by the raw credential id bytes.
pub async fn touch_credential(
    pool: &SqlitePool,
    cred_id: &[u8],
    info: &crate::auth::RequestInfo,
) -> Result<()> {
    sqlx::query(
        "UPDATE webauthn_credentials \
         SET last_used_at = ?, last_ip = ?, last_user_agent = ? WHERE credential_id = ?",
    )
    .bind(now_unix())
    .bind(info.ip.as_deref())
    .bind(info.user_agent.as_deref())
    .bind(cred_id)
    .execute(pool)
    .await
    .context("recording credential use")?;
    Ok(())
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

    #[tokio::test]
    async fn sandbox_slots_are_assigned_and_distinct() {
        let pool = pool().await;
        let a = create(&pool, "a", "alice", "Alice", false).await.unwrap();
        let b = create(&pool, "b", "bob", "Bob", false).await.unwrap();
        let sa = sandbox_slot(&pool, &a.id).await.unwrap();
        let sb = sandbox_slot(&pool, &b.id).await.unwrap();
        assert!(sa.is_some() && sb.is_some());
        assert_ne!(sa, sb);

        // A user inserted without a slot is backfilled.
        sqlx::query(
            "INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES ('c','carol','Carol',0,99)",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(sandbox_slot(&pool, "c").await.unwrap().is_none());
        assign_sandbox_slots(&pool).await.unwrap();
        let sc = sandbox_slot(&pool, "c").await.unwrap();
        assert!(sc.is_some());
        assert_ne!(sc, sa);
        assert_ne!(sc, sb);
    }
}
