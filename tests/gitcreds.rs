//! Tests for per-user git credentials against a real SQLite database — the
//! encryption at rest, ownership scoping, and the foreign-key cascade that no
//! in-memory unit test exercises.

use mcp_hub::crypto::SecretBox;
use mcp_hub::{db, gitcreds, users};
use sqlx::SqlitePool;

async fn pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!("mcp_hub_gitcreds_{}.db", uuid::Uuid::new_v4()));
    db::connect(path.to_str().unwrap()).await.unwrap()
}

#[tokio::test]
async fn credential_round_trips_and_stores_no_plaintext() {
    let pool = pool().await;
    let secrets = SecretBox::new(&[3u8; 32]);
    let user = users::create(&pool, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let token = "ghp_a_very_secret_pat";

    let cred = gitcreds::upsert(
        &pool,
        &secrets,
        &user.id,
        "https://github.com/owner/private.git",
        "",
        "laptop",
        token,
    )
    .await
    .unwrap();
    // A full repo URL is accepted and stored as the bare host.
    assert_eq!(cred.host, "github.com");

    // The plaintext is nowhere in the row.
    let (ct,): (Vec<u8>,) = sqlx::query_as("SELECT ciphertext FROM git_credentials WHERE id = ?")
        .bind(&cred.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!ct.windows(token.len()).any(|w| w == token.as_bytes()));

    // It resolves for a repo on that host, with the default username applied.
    let resolved = gitcreds::for_repo(&pool, &secrets, &user.id, "https://github.com/owner/other")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.token, token);
    assert_eq!(resolved.username, gitcreds::DEFAULT_USERNAME);

    // Listing exposes metadata only — GitCredential has no token field, so the
    // check that matters is that nothing in its rendering carries the secret.
    let listed = gitcreds::list_for_user(&pool, &user.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!format!("{listed:?}").contains(token));
}

#[tokio::test]
async fn credentials_are_scoped_to_their_owner() {
    let pool = pool().await;
    let secrets = SecretBox::new(&[4u8; 32]);
    let alice = users::create(&pool, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let bob = users::create(&pool, "u2", "bob", "Bob", false)
        .await
        .unwrap();

    gitcreds::upsert(
        &pool,
        &secrets,
        &alice.id,
        "github.com",
        "",
        "",
        "alice-token",
    )
    .await
    .unwrap();
    gitcreds::upsert(&pool, &secrets, &bob.id, "github.com", "", "", "bob-token")
        .await
        .unwrap();

    let repo = "https://github.com/o/r";
    let a = gitcreds::for_repo(&pool, &secrets, &alice.id, repo)
        .await
        .unwrap()
        .unwrap();
    let b = gitcreds::for_repo(&pool, &secrets, &bob.id, repo)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.token, "alice-token");
    assert_eq!(b.token, "bob-token");

    // Deleting is ownership-scoped: Bob's survives.
    assert!(gitcreds::delete(&pool, &alice.id, "github.com")
        .await
        .unwrap());
    assert!(gitcreds::for_repo(&pool, &secrets, &alice.id, repo)
        .await
        .unwrap()
        .is_none());
    assert!(gitcreds::for_repo(&pool, &secrets, &bob.id, repo)
        .await
        .unwrap()
        .is_some());
}

/// Deleting an account must take its git credentials with it. This rides on the
/// table's `ON DELETE CASCADE`, which only the real (foreign-keys-on)
/// connection enforces — so it is worth an integration test.
#[tokio::test]
async fn deleting_a_user_removes_their_credentials() {
    let pool = pool().await;
    let secrets = SecretBox::new(&[6u8; 32]);
    let alice = users::create(&pool, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let bob = users::create(&pool, "u2", "bob", "Bob", false)
        .await
        .unwrap();
    for (u, host) in [
        (&alice, "github.com"),
        (&alice, "gitlab.com"),
        (&bob, "github.com"),
    ] {
        gitcreds::upsert(&pool, &secrets, &u.id, host, "", "", "tok")
            .await
            .unwrap();
    }

    users::delete(&pool, &alice.id).await.unwrap();

    assert!(gitcreds::list_for_user(&pool, &alice.id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        gitcreds::list_for_user(&pool, &bob.id).await.unwrap().len(),
        1
    );
    let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM git_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}
