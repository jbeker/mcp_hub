//! Tests for browser-session idle + absolute timeouts (`auth::session`).

use mcp_hub::auth::session;
use mcp_hub::auth::RequestInfo;
use mcp_hub::{db, users};
use sqlx::SqlitePool;

const IDLE: i64 = 1800; // 30 min
const ABSOLUTE: i64 = 43200; // 12 h

async fn pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!("mcp_hub_sess_{}.db", uuid::Uuid::new_v4()));
    db::connect(path.to_str().unwrap()).await.unwrap()
}

async fn a_user(pool: &SqlitePool) -> String {
    users::create(pool, "u1", "alice", "Alice", false)
        .await
        .unwrap()
        .id
}

fn info() -> RequestInfo {
    RequestInfo {
        ip: None,
        user_agent: None,
    }
}

/// Read a session's `(created_at, expires_at)`.
async fn stamps(pool: &SqlitePool, sid: &str) -> Option<(i64, i64)> {
    sqlx::query_as("SELECT created_at, expires_at FROM web_sessions WHERE id = ?")
        .bind(sid)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn set_stamps(pool: &SqlitePool, sid: &str, created_at: i64, expires_at: i64) {
    sqlx::query("UPDATE web_sessions SET created_at = ?, expires_at = ? WHERE id = ?")
        .bind(created_at)
        .bind(expires_at)
        .bind(sid)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn valid_session_loads_and_slides_the_idle_deadline() {
    let pool = pool().await;
    let uid = a_user(&pool).await;
    let sid = session::create(&pool, &uid, &info(), IDLE).await.unwrap();

    let (created, _) = stamps(&pool, &sid).await.unwrap();
    // Push the idle deadline near the floor so a slide is well past the throttle.
    set_stamps(&pool, &sid, created, created + 5).await;

    let user = session::load_and_touch(&pool, &sid, IDLE, ABSOLUTE)
        .await
        .unwrap();
    assert!(user.is_some(), "valid session should load the user");

    let (_, expires_after) = stamps(&pool, &sid).await.unwrap();
    assert!(
        expires_after >= created + IDLE - 60,
        "idle deadline should slide to ~now+IDLE, got {expires_after} (created {created})"
    );
}

#[tokio::test]
async fn idle_expired_session_is_rejected_and_deleted() {
    let pool = pool().await;
    let uid = a_user(&pool).await;
    let sid = session::create(&pool, &uid, &info(), IDLE).await.unwrap();

    let (created, _) = stamps(&pool, &sid).await.unwrap();
    // Idle deadline in the past → expired.
    set_stamps(&pool, &sid, created, created - 10).await;

    let user = session::load_and_touch(&pool, &sid, IDLE, ABSOLUTE)
        .await
        .unwrap();
    assert!(user.is_none(), "idle-expired session must not authenticate");
    assert!(stamps(&pool, &sid).await.is_none(), "expired row is deleted");
}

#[tokio::test]
async fn absolute_cap_rejects_session_older_than_the_cap() {
    let pool = pool().await;
    let uid = a_user(&pool).await;
    let sid = session::create(&pool, &uid, &info(), IDLE).await.unwrap();

    let (created, _) = stamps(&pool, &sid).await.unwrap();
    // Logged in longer ago than the absolute cap, but the idle deadline is still
    // in the future — the absolute check must reject it immediately.
    set_stamps(&pool, &sid, created - ABSOLUTE - 100, created + IDLE).await;

    let user = session::load_and_touch(&pool, &sid, IDLE, ABSOLUTE)
        .await
        .unwrap();
    assert!(user.is_none(), "session past its absolute cap must not authenticate");
    assert!(stamps(&pool, &sid).await.is_none(), "expired row is deleted");
}

#[tokio::test]
async fn legacy_long_session_is_capped_down_on_first_use() {
    let pool = pool().await;
    let uid = a_user(&pool).await;
    let sid = session::create(&pool, &uid, &info(), IDLE).await.unwrap();

    let (created, _) = stamps(&pool, &sid).await.unwrap();
    // Simulate an old 30-day session: recent login, huge idle deadline.
    set_stamps(&pool, &sid, created, created + 60 * 60 * 24 * 30).await;

    let user = session::load_and_touch(&pool, &sid, IDLE, ABSOLUTE)
        .await
        .unwrap();
    assert!(user.is_some(), "a recent-login legacy session is still valid");

    let (_, expires_after) = stamps(&pool, &sid).await.unwrap();
    assert!(
        expires_after <= created + ABSOLUTE,
        "legacy deadline must be capped to <= created+ABSOLUTE, got {expires_after}"
    );
}

#[tokio::test]
async fn delete_expired_sweeps_only_past_sessions() {
    let pool = pool().await;
    let uid = a_user(&pool).await;
    let fresh = session::create(&pool, &uid, &info(), IDLE).await.unwrap();
    let stale = session::create(&pool, &uid, &info(), IDLE).await.unwrap();

    let (created, _) = stamps(&pool, &stale).await.unwrap();
    set_stamps(&pool, &stale, created, created - 10).await;

    let swept = session::delete_expired(&pool).await.unwrap();
    assert_eq!(swept, 1, "only the one past-deadline session is swept");
    assert!(stamps(&pool, &stale).await.is_none());
    assert!(stamps(&pool, &fresh).await.is_some());
}
