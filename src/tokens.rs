//! Personal access tokens (PATs).
//!
//! An opaque, long-lived bearer credential a user mints from the
//! passkey-authenticated Account page for MCP clients that cannot run the OAuth
//! flow. The token is `mcphub_pat_<random>`; only its SHA-256 hash is stored
//! (the same scheme refresh tokens use, see [`crate::oauth`]), and the plaintext
//! is shown exactly once at creation. Tokens always carry an expiry; the proxy
//! verifies them in `require_bearer` alongside OAuth JWTs.

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::oauth::{random_token, token_hash};
use crate::util::{new_id, now_unix};

/// Prefix that marks a personal access token, so the bearer check can route it
/// without attempting a JWT decode (and so leaked tokens are recognizable).
pub const PREFIX: &str = "mcphub_pat_";

/// Maximum lifetime a token may be created with (one year).
pub const MAX_TTL_SECS: i64 = 365 * 86_400;

/// Skip rewriting `last_used_at` if it was updated within this window, to avoid
/// a SQLite write on every single MCP request.
const TOUCH_THROTTLE_SECS: i64 = 60;

/// A stored personal access token (never includes the secret).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Pat {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: i64,
}

/// Columns selected into [`Pat`].
const PAT_COLS: &str = "id, name, created_at, last_used_at, expires_at";

/// Whether a presented bearer value has the PAT shape.
pub fn looks_like_pat(token: &str) -> bool {
    token.starts_with(PREFIX)
}

/// Create a token for `user_id` valid for `ttl_secs`. Returns the stored record
/// and the one-time plaintext (the caller must show it and then discard it).
pub async fn create(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    ttl_secs: i64,
) -> Result<(Pat, String)> {
    let plaintext = format!("{PREFIX}{}", random_token());
    let now = now_unix();
    let pat = Pat {
        id: new_id(),
        name: name.to_string(),
        created_at: now,
        last_used_at: None,
        expires_at: now + ttl_secs,
    };
    sqlx::query(
        "INSERT INTO personal_access_tokens (id, user_id, token_hash, name, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&pat.id)
    .bind(user_id)
    .bind(token_hash(&plaintext))
    .bind(&pat.name)
    .bind(pat.created_at)
    .bind(pat.expires_at)
    .execute(pool)
    .await
    .context("inserting personal access token")?;
    Ok((pat, plaintext))
}

/// A user's tokens, newest first.
pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Pat>> {
    let rows = sqlx::query_as::<_, Pat>(&format!(
        "SELECT {PAT_COLS} FROM personal_access_tokens WHERE user_id = ? ORDER BY created_at DESC"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Resolve a token hash to `(user_id, token_id)` if it exists and has not
/// expired. Expired rows never authenticate.
pub async fn resolve_valid(pool: &SqlitePool, hash: &str) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT user_id, id FROM personal_access_tokens WHERE token_hash = ? AND expires_at > ?",
    )
    .bind(hash)
    .bind(now_unix())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record that a token was just used (throttled). Best-effort: callers ignore
/// the result so an auth request never fails on a bookkeeping write.
pub async fn touch(pool: &SqlitePool, token_id: &str) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "UPDATE personal_access_tokens SET last_used_at = ? \
         WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)",
    )
    .bind(now)
    .bind(token_id)
    .bind(now - TOUCH_THROTTLE_SECS)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke one of the user's tokens. Ownership-scoped so a user can only delete
/// their own. Returns whether a row was removed.
pub async fn revoke(pool: &SqlitePool, user_id: &str, token_id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM personal_access_tokens WHERE id = ? AND user_id = ?")
        .bind(token_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke every personal access token for a user. Used when disabling an
/// account so a stolen PAT is dead for good and re-enabling the account cannot
/// resurrect it (mirrors how OAuth refresh tokens are dropped on disable).
/// Returns the number of tokens removed.
pub async fn revoke_all_for_user(pool: &SqlitePool, user_id: &str) -> Result<u64> {
    let res = sqlx::query("DELETE FROM personal_access_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        // A user to own the tokens (FK).
        sqlx::query("INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES ('u1','alice','Alice',0,0)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn create_stores_a_hash_not_the_plaintext() {
        let pool = pool().await;
        let (pat, plaintext) = create(&pool, "u1", "laptop", 3600).await.unwrap();
        assert!(plaintext.starts_with(PREFIX));
        // The plaintext is nowhere in the row; only its hash is stored.
        let (stored,): (String,) =
            sqlx::query_as("SELECT token_hash FROM personal_access_tokens WHERE id = ?")
                .bind(&pat.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(stored, plaintext);
        assert_eq!(stored, token_hash(&plaintext));
    }

    #[tokio::test]
    async fn resolve_honours_expiry_and_revocation() {
        let pool = pool().await;
        let (pat, plaintext) = create(&pool, "u1", "k", 3600).await.unwrap();
        let hash = token_hash(&plaintext);

        let got = resolve_valid(&pool, &hash).await.unwrap();
        assert_eq!(got, Some(("u1".to_string(), pat.id.clone())));

        // Unknown hash → none.
        assert!(resolve_valid(&pool, "nope").await.unwrap().is_none());

        // Expire it in the past → no longer resolves.
        sqlx::query("UPDATE personal_access_tokens SET expires_at = 1 WHERE id = ?")
            .bind(&pat.id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(resolve_valid(&pool, &hash).await.unwrap().is_none());

        // A fresh token can be revoked and then no longer resolves.
        let (pat2, pt2) = create(&pool, "u1", "k2", 3600).await.unwrap();
        let h2 = token_hash(&pt2);
        assert!(resolve_valid(&pool, &h2).await.unwrap().is_some());
        assert!(revoke(&pool, "u1", &pat2.id).await.unwrap());
        assert!(resolve_valid(&pool, &h2).await.unwrap().is_none());
        // Revoking someone else's (or a gone) token reports false.
        assert!(!revoke(&pool, "u1", &pat2.id).await.unwrap());
        assert!(!revoke(&pool, "other", &pat.id).await.unwrap());
    }

    #[tokio::test]
    async fn revoke_all_for_user_kills_every_token() {
        let pool = pool().await;
        // A second user whose tokens must be left untouched.
        sqlx::query("INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES ('u2','bob','Bob',0,0)")
            .execute(&pool)
            .await
            .unwrap();

        let (_, pt_a) = create(&pool, "u1", "a", 3600).await.unwrap();
        let (_, pt_b) = create(&pool, "u1", "b", 3600).await.unwrap();
        let (_, pt_other) = create(&pool, "u2", "c", 3600).await.unwrap();
        let (ha, hb, ho) = (token_hash(&pt_a), token_hash(&pt_b), token_hash(&pt_other));

        // Disabling u1: all of u1's tokens are gone, u2's survives.
        let removed = revoke_all_for_user(&pool, "u1").await.unwrap();
        assert_eq!(removed, 2);
        assert!(resolve_valid(&pool, &ha).await.unwrap().is_none());
        assert!(resolve_valid(&pool, &hb).await.unwrap().is_none());
        assert!(resolve_valid(&pool, &ho).await.unwrap().is_some());

        // Re-enabling the account cannot resurrect the revoked tokens: the rows
        // are gone, so a previously valid PAT stays dead.
        assert!(resolve_valid(&pool, &ha).await.unwrap().is_none());
        assert_eq!(revoke_all_for_user(&pool, "u1").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn touch_sets_last_used() {
        let pool = pool().await;
        let (pat, _) = create(&pool, "u1", "k", 3600).await.unwrap();
        assert!(list_for_user(&pool, "u1").await.unwrap()[0]
            .last_used_at
            .is_none());
        touch(&pool, &pat.id).await.unwrap();
        assert!(list_for_user(&pool, "u1").await.unwrap()[0]
            .last_used_at
            .is_some());
    }
}
