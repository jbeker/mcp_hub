//! Single-use invite codes.
//!
//! Registration is invite-only (see `auth::webauthn::register_start`). The very
//! first account bootstraps the admin and needs no code; every later account
//! must redeem an unused invite. Only the SHA-256 of each code is stored, so the
//! plaintext exists only in the admin's browser at creation time and in the
//! registrant's request — a database leak yields no usable codes.

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::oauth::{b64url, token_hash};
use crate::util::now_unix;

/// Invite metadata for admin listing. Never carries the plaintext code.
#[derive(Clone, Debug)]
pub struct Invite {
    pub code_hash: String,
    pub note: String,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
}

impl Invite {
    /// Short, non-secret identifier (hash prefix) for display and revocation.
    pub fn short_id(&self) -> &str {
        &self.code_hash[..self.code_hash.len().min(12)]
    }

    pub fn used(&self) -> bool {
        self.used_at.is_some()
    }
}

/// Generate a fresh invite code (128 bits of entropy, URL-safe).
fn generate_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// Create an invite, returning the one-time plaintext code and its record.
///
/// The plaintext is returned only here; only its hash is persisted, so it can
/// never be recovered from the database and must be copied now.
pub async fn create(pool: &SqlitePool, created_by: &str, note: &str) -> Result<(String, Invite)> {
    let code = generate_code();
    let code_hash = token_hash(&code);
    let created_at = now_unix();
    sqlx::query("INSERT INTO invites (code_hash, note, created_by, created_at) VALUES (?, ?, ?, ?)")
        .bind(&code_hash)
        .bind(note)
        .bind(created_by)
        .bind(created_at)
        .execute(pool)
        .await
        .context("inserting invite")?;
    Ok((
        code,
        Invite {
            code_hash,
            note: note.to_string(),
            created_by: Some(created_by.to_string()),
            created_at,
            used_at: None,
            used_by: None,
        },
    ))
}

/// Whether a code matches an existing, unused invite.
///
/// This is an advisory pre-check (used at the start of registration for a clear
/// error); the authoritative single-use consume happens in [`redeem`].
pub async fn is_redeemable(pool: &SqlitePool, code: &str) -> Result<bool> {
    let hash = token_hash(code.trim());
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM invites WHERE code_hash = ? AND used_at IS NULL")
            .bind(&hash)
            .fetch_one(pool)
            .await?;
    Ok(n == 1)
}

/// Atomically consume an unused invite for `user_id`.
///
/// The single conditional `UPDATE` is the point of serialization: under two
/// concurrent registrations with the same code, exactly one observes
/// `used_at IS NULL` and succeeds; the other gets zero affected rows and errors.
pub async fn redeem(pool: &SqlitePool, code: &str, user_id: &str) -> Result<()> {
    let hash = token_hash(code.trim());
    let res = sqlx::query(
        "UPDATE invites SET used_at = ?, used_by = ? WHERE code_hash = ? AND used_at IS NULL",
    )
    .bind(now_unix())
    .bind(user_id)
    .bind(&hash)
    .execute(pool)
    .await
    .context("redeeming invite")?;
    if res.rows_affected() == 1 {
        Ok(())
    } else {
        anyhow::bail!("invite code is invalid or has already been used")
    }
}

/// List all invites, newest first (metadata only — never the plaintext).
pub async fn list(pool: &SqlitePool) -> Result<Vec<Invite>> {
    type Row = (String, String, Option<String>, i64, Option<i64>, Option<String>);
    let rows = sqlx::query_as::<_, Row>(
        "SELECT code_hash, note, created_by, created_at, used_at, used_by \
         FROM invites ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(code_hash, note, created_by, created_at, used_at, used_by)| Invite {
                code_hash,
                note,
                created_by,
                created_at,
                used_at,
                used_by,
            },
        )
        .collect())
}

/// Revoke an unused invite identified by its short id (hash prefix). Used
/// invites are retained for audit and cannot be revoked. Returns whether one
/// was deleted.
pub async fn revoke(pool: &SqlitePool, short_id: &str) -> Result<bool> {
    // Match on the hash prefix via substr so base64url characters (`-`, `_`)
    // are compared literally rather than as LIKE wildcards.
    let res = sqlx::query(
        "DELETE FROM invites WHERE used_at IS NULL AND substr(code_hash, 1, ?) = ?",
    )
    .bind(short_id.len() as i64)
    .bind(short_id)
    .execute(pool)
    .await
    .context("revoking invite")?;
    Ok(res.rows_affected() >= 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let path =
            std::env::temp_dir().join(format!("mcp_hub_invites_{}.db", uuid::Uuid::new_v4()));
        crate::db::connect(path.to_str().unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn create_then_redeem_is_single_use() {
        let pool = pool().await;
        let admin = crate::users::create(&pool, "a", "admin", "Admin", true)
            .await
            .unwrap();
        let user = crate::users::create(&pool, "u", "user", "User", false)
            .await
            .unwrap();

        let (code, inv) = create(&pool, &admin.id, "for bob").await.unwrap();
        assert!(!inv.used());
        assert!(is_redeemable(&pool, &code).await.unwrap());

        redeem(&pool, &code, &user.id).await.unwrap();
        // A second redemption fails, and the code is no longer redeemable.
        assert!(redeem(&pool, &code, &user.id).await.is_err());
        assert!(!is_redeemable(&pool, &code).await.unwrap());
    }

    #[tokio::test]
    async fn unknown_code_is_rejected() {
        let pool = pool().await;
        assert!(!is_redeemable(&pool, "nope").await.unwrap());
        let user = crate::users::create(&pool, "u", "user", "User", false)
            .await
            .unwrap();
        assert!(redeem(&pool, "nope", &user.id).await.is_err());
    }

    #[tokio::test]
    async fn revoke_removes_only_unused() {
        let pool = pool().await;
        let admin = crate::users::create(&pool, "a", "admin", "Admin", true)
            .await
            .unwrap();
        let user = crate::users::create(&pool, "u", "user", "User", false)
            .await
            .unwrap();

        let (live, live_inv) = create(&pool, &admin.id, "").await.unwrap();
        let (spent, spent_inv) = create(&pool, &admin.id, "").await.unwrap();
        redeem(&pool, &spent, &user.id).await.unwrap();

        // The unused one is revocable; the used one is retained for audit.
        assert!(revoke(&pool, live_inv.short_id()).await.unwrap());
        assert!(!is_redeemable(&pool, &live).await.unwrap());
        assert!(!revoke(&pool, spent_inv.short_id()).await.unwrap());

        let all = list(&pool).await.unwrap();
        assert!(all.iter().any(|i| i.used() && i.code_hash == spent_inv.code_hash));
    }
}
