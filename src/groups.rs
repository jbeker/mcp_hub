//! Named connector groups.
//!
//! A group is a user-defined subset of their backend servers, exposed as its
//! own MCP endpoint at `/mcp/<slug>` so each connector a client adds stays
//! under client-side tool caps (claude.ai truncates a connector's registry at
//! 256 tools). Groups are per-user: slugs resolve against the authenticated
//! user, so the same slug on two accounts names two disjoint resources. See
//! [`crate::proxy`] for enforcement.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use sqlx::SqlitePool;

use crate::util::{new_id, now_unix};

/// A named connector group. `slug` is the URL path segment; `name` is a free
/// display label.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Group {
    pub id: String,
    pub user_id: String,
    pub slug: String,
    pub name: String,
    pub created_at: i64,
}

/// Whether `s` is usable as a group slug: 1–64 chars of lowercase `[a-z0-9-]`,
/// starting and ending alphanumeric. Slugs live strictly under `/mcp/`, so no
/// reserved-word list is needed.
pub fn valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    alnum(bytes[0]) && alnum(bytes[bytes.len() - 1]) && bytes.iter().all(|&b| alnum(b) || b == b'-')
}

/// All of a user's groups, in slug order.
pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Group>> {
    sqlx::query_as(
        "SELECT id, user_id, slug, name, created_at FROM connector_groups \
         WHERE user_id = ? ORDER BY slug",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("listing connector groups")
}

/// Resolve a slug within one user's groups. This is the per-request hot path
/// for `/mcp/<slug>`; `None` means the endpoint doesn't exist for this user.
pub async fn find_by_slug(pool: &SqlitePool, user_id: &str, slug: &str) -> Result<Option<Group>> {
    sqlx::query_as(
        "SELECT id, user_id, slug, name, created_at FROM connector_groups \
         WHERE user_id = ? AND slug = ?",
    )
    .bind(user_id)
    .bind(slug)
    .fetch_optional(pool)
    .await
    .context("looking up connector group")
}

pub async fn find_by_id(pool: &SqlitePool, user_id: &str, group_id: &str) -> Result<Option<Group>> {
    sqlx::query_as(
        "SELECT id, user_id, slug, name, created_at FROM connector_groups \
         WHERE user_id = ? AND id = ?",
    )
    .bind(user_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("looking up connector group")
}

/// Create a group. The slug is validated here so every caller (management
/// tools, web UI) gets the same rules.
pub async fn create(pool: &SqlitePool, user_id: &str, slug: &str, name: &str) -> Result<Group> {
    if !valid_slug(slug) {
        bail!("invalid slug: use 1-64 lowercase letters, digits, and interior hyphens");
    }
    let group = Group {
        id: new_id(),
        user_id: user_id.to_string(),
        slug: slug.to_string(),
        name: name.to_string(),
        created_at: now_unix(),
    };
    sqlx::query(
        "INSERT INTO connector_groups (id, user_id, slug, name, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&group.id)
    .bind(&group.user_id)
    .bind(&group.slug)
    .bind(&group.name)
    .bind(group.created_at)
    .execute(pool)
    .await
    .map_err(|e| match e.as_database_error() {
        Some(dbe) if dbe.is_unique_violation() => {
            anyhow::anyhow!("a group with slug '{slug}' already exists")
        }
        _ => anyhow::Error::new(e).context("creating connector group"),
    })?;
    Ok(group)
}

/// Rename a group's display name. The slug is immutable: it is baked into the
/// connector URL and outstanding token audiences, so changing it would break
/// every client pointed at the group — delete and recreate instead.
pub async fn rename(pool: &SqlitePool, user_id: &str, group_id: &str, name: &str) -> Result<bool> {
    let res = sqlx::query("UPDATE connector_groups SET name = ? WHERE id = ? AND user_id = ?")
        .bind(name)
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await
        .context("renaming connector group")?;
    Ok(res.rows_affected() > 0)
}

/// Replace a group's member set. Only instance ids actually owned by `user_id`
/// are stored (and the group itself must be theirs), so a forged id can't
/// attach a foreign backend.
pub async fn set_members(
    pool: &SqlitePool,
    user_id: &str,
    group_id: &str,
    instance_ids: &[String],
) -> Result<()> {
    let now = now_unix();
    let mut tx = pool.begin().await?;
    let owned: Option<(String,)> =
        sqlx::query_as("SELECT id FROM connector_groups WHERE id = ? AND user_id = ?")
            .bind(group_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .context("checking group ownership")?;
    if owned.is_none() {
        bail!("no such group");
    }
    sqlx::query("DELETE FROM connector_group_members WHERE group_id = ?")
        .bind(group_id)
        .execute(&mut *tx)
        .await
        .context("clearing group members")?;
    for instance_id in instance_ids {
        // INSERT ... SELECT guards ownership: the row is written only if the
        // instance belongs to this user.
        sqlx::query(
            "INSERT OR IGNORE INTO connector_group_members (group_id, instance_id, created_at) \
             SELECT ?, id, ? FROM user_server_instances WHERE id = ? AND user_id = ?",
        )
        .bind(group_id)
        .bind(now)
        .bind(instance_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("inserting group member")?;
    }
    tx.commit().await?;
    Ok(())
}

/// Delete a group (membership rows cascade). Returns whether a row was removed.
pub async fn delete(pool: &SqlitePool, user_id: &str, group_id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM connector_groups WHERE id = ? AND user_id = ?")
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await
        .context("deleting connector group")?;
    Ok(res.rows_affected() > 0)
}

/// The instance ids belonging to a group. Fetched per request on group
/// endpoints (like credential denials) so membership edits take effect
/// immediately on live sessions.
pub async fn member_instance_ids(pool: &SqlitePool, group_id: &str) -> Result<HashSet<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT instance_id FROM connector_group_members WHERE group_id = ?")
            .bind(group_id)
            .fetch_all(pool)
            .await
            .context("loading group members")?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, instances, users};

    async fn pool() -> SqlitePool {
        let path =
            std::env::temp_dir().join(format!("mcp_hub_groups_{}.db", crate::util::new_id()));
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

    #[test]
    fn slug_validation() {
        for ok in ["a", "zabbix", "my-group-2", "0x", &"a".repeat(64)] {
            assert!(valid_slug(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "A",
            "a_b",
            "a b",
            "a/b",
            "a.b",
            &"a".repeat(65),
        ] {
            assert!(!valid_slug(bad), "{bad} should be invalid");
        }
    }

    #[tokio::test]
    async fn crud_round_trip() {
        let pool = pool().await;
        let u = users::create(&pool, "u1", "alice", "Alice", false)
            .await
            .unwrap();
        let a = make_instance(&pool, &u.id, "a").await;
        let b = make_instance(&pool, &u.id, "b").await;

        let g = create(&pool, &u.id, "monitoring", "Monitoring")
            .await
            .unwrap();
        assert_eq!(
            find_by_slug(&pool, &u.id, "monitoring")
                .await
                .unwrap()
                .unwrap()
                .id,
            g.id
        );
        assert!(create(&pool, &u.id, "monitoring", "dup").await.is_err());
        assert!(create(&pool, &u.id, "Bad Slug", "").await.is_err());

        set_members(&pool, &u.id, &g.id, &[a.clone(), b.clone()])
            .await
            .unwrap();
        let members = member_instance_ids(&pool, &g.id).await.unwrap();
        assert!(members.contains(&a) && members.contains(&b));

        // Replacement semantics.
        set_members(&pool, &u.id, &g.id, std::slice::from_ref(&b))
            .await
            .unwrap();
        let members = member_instance_ids(&pool, &g.id).await.unwrap();
        assert!(!members.contains(&a) && members.contains(&b));

        assert!(rename(&pool, &u.id, &g.id, "Renamed").await.unwrap());
        assert_eq!(
            list_for_user(&pool, &u.id).await.unwrap()[0].name,
            "Renamed"
        );

        assert!(delete(&pool, &u.id, &g.id).await.unwrap());
        assert!(find_by_slug(&pool, &u.id, "monitoring")
            .await
            .unwrap()
            .is_none());
        assert!(member_instance_ids(&pool, &g.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ownership_guards_and_per_user_slugs() {
        let pool = pool().await;
        let u1 = users::create(&pool, "u1", "alice", "Alice", false)
            .await
            .unwrap();
        let u2 = users::create(&pool, "u2", "bob", "Bob", false)
            .await
            .unwrap();
        let mine = make_instance(&pool, &u1.id, "mine").await;
        let theirs = make_instance(&pool, &u2.id, "theirs").await;

        // Same slug for two users is fine and resolves per-user.
        let g1 = create(&pool, &u1.id, "shared", "").await.unwrap();
        let g2 = create(&pool, &u2.id, "shared", "").await.unwrap();
        assert_ne!(g1.id, g2.id);
        assert_eq!(
            find_by_slug(&pool, &u1.id, "shared")
                .await
                .unwrap()
                .unwrap()
                .id,
            g1.id
        );
        assert_eq!(
            find_by_slug(&pool, &u2.id, "shared")
                .await
                .unwrap()
                .unwrap()
                .id,
            g2.id
        );

        // Foreign instance ids are silently dropped; foreign groups are untouchable.
        set_members(&pool, &u1.id, &g1.id, &[mine.clone(), theirs.clone()])
            .await
            .unwrap();
        let members = member_instance_ids(&pool, &g1.id).await.unwrap();
        assert!(members.contains(&mine) && !members.contains(&theirs));
        assert!(
            set_members(&pool, &u2.id, &g1.id, std::slice::from_ref(&theirs))
                .await
                .is_err()
        );
        assert!(!rename(&pool, &u2.id, &g1.id, "hacked").await.unwrap());
        assert!(!delete(&pool, &u2.id, &g1.id).await.unwrap());

        // Deleting an instance cascades out of the membership table.
        instances::delete(&pool, &mine).await.unwrap();
        assert!(member_instance_ids(&pool, &g1.id).await.unwrap().is_empty());
    }
}
