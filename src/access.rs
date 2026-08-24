//! Per-credential backend access control.
//!
//! Each user can stop one of their credentials (an OAuth client or a personal
//! access token) from reaching specific backend MCP servers. The model is a
//! **denylist**: a row in `credential_backend_denials` means "this credential is
//! denied this backend". No row = allowed, so new credentials and newly-added
//! backends are reachable by default. See [`crate::proxy`] for enforcement.

use std::collections::HashSet;

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::util::now_unix;

/// Credential kinds that can be access-restricted.
pub const OAUTH: &str = "oauth";
pub const PAT: &str = "pat";

/// The set of instance ids a credential is denied. Empty = full access.
pub async fn denied_instances(
    pool: &SqlitePool,
    credential_type: &str,
    credential_id: &str,
) -> Result<HashSet<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT instance_id FROM credential_backend_denials \
         WHERE credential_type = ? AND credential_id = ?",
    )
    .bind(credential_type)
    .bind(credential_id)
    .fetch_all(pool)
    .await
    .context("loading credential denials")?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Replace a credential's denied set. Only instance ids actually owned by
/// `user_id` are stored, so a forged id can't create a dangling/foreign denial.
pub async fn set_denials(
    pool: &SqlitePool,
    user_id: &str,
    credential_type: &str,
    credential_id: &str,
    denied: &[String],
) -> Result<()> {
    let now = now_unix();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM credential_backend_denials \
         WHERE credential_type = ? AND credential_id = ?",
    )
    .bind(credential_type)
    .bind(credential_id)
    .execute(&mut *tx)
    .await
    .context("clearing credential denials")?;

    for instance_id in denied {
        // INSERT ... SELECT guards ownership: the row is written only if the
        // instance belongs to this user.
        sqlx::query(
            "INSERT OR IGNORE INTO credential_backend_denials \
             (user_id, credential_type, credential_id, instance_id, created_at) \
             SELECT ?, ?, ?, id, ? FROM user_server_instances WHERE id = ? AND user_id = ?",
        )
        .bind(user_id)
        .bind(credential_type)
        .bind(credential_id)
        .bind(now)
        .bind(instance_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("inserting credential denial")?;
    }
    tx.commit().await?;
    Ok(())
}

/// Drop all denials for a credential (e.g. when a PAT is revoked).
pub async fn clear_for_credential(
    pool: &SqlitePool,
    credential_type: &str,
    credential_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM credential_backend_denials \
         WHERE credential_type = ? AND credential_id = ?",
    )
    .bind(credential_type)
    .bind(credential_id)
    .execute(pool)
    .await
    .context("clearing credential denials")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, instances, users};

    async fn pool() -> SqlitePool {
        let path =
            std::env::temp_dir().join(format!("mcp_hub_access_{}.db", crate::util::new_id()));
        db::connect(path.to_str().unwrap()).await.unwrap()
    }

    async fn make_instance(pool: &SqlitePool, user_id: &str, ns: &str) -> String {
        let def = instances::ServerDef {
            name: ns.into(),
            description: String::new(),
            transport: "stdio".into(),
            command: Some("true".into()),
            args: vec![],
            url: None,
            runtime: String::new(),
            repo: None,
            git_ref: None,
            entry: None,
            module: None,
        };
        instances::create(pool, user_id, None, Some(&def), ns, ns)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn set_get_clear_round_trip() {
        let pool = pool().await;
        let u = users::create(&pool, "u1", "alice", "Alice", false)
            .await
            .unwrap();
        let a = make_instance(&pool, &u.id, "a").await;
        let b = make_instance(&pool, &u.id, "b").await;

        // Default: nothing denied.
        assert!(denied_instances(&pool, OAUTH, "client-1")
            .await
            .unwrap()
            .is_empty());

        set_denials(&pool, &u.id, OAUTH, "client-1", std::slice::from_ref(&a))
            .await
            .unwrap();
        let denied = denied_instances(&pool, OAUTH, "client-1").await.unwrap();
        assert!(denied.contains(&a) && !denied.contains(&b));

        // Replacing overwrites the prior set.
        set_denials(&pool, &u.id, OAUTH, "client-1", std::slice::from_ref(&b))
            .await
            .unwrap();
        let denied = denied_instances(&pool, OAUTH, "client-1").await.unwrap();
        assert!(denied.contains(&b) && !denied.contains(&a));

        clear_for_credential(&pool, OAUTH, "client-1")
            .await
            .unwrap();
        assert!(denied_instances(&pool, OAUTH, "client-1")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn ignores_instances_not_owned_by_user() {
        let pool = pool().await;
        let u1 = users::create(&pool, "u1", "alice", "Alice", false)
            .await
            .unwrap();
        let u2 = users::create(&pool, "u2", "bob", "Bob", false)
            .await
            .unwrap();
        let mine = make_instance(&pool, &u1.id, "mine").await;
        let theirs = make_instance(&pool, &u2.id, "theirs").await;

        // u1 tries to deny their own instance and someone else's; only their own sticks.
        set_denials(&pool, &u1.id, PAT, "tok-1", &[mine.clone(), theirs.clone()])
            .await
            .unwrap();
        let denied = denied_instances(&pool, PAT, "tok-1").await.unwrap();
        assert!(denied.contains(&mine));
        assert!(!denied.contains(&theirs));
    }
}
