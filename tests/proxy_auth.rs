//! Tests for the `/mcp` proxy endpoint's bearer-token gate.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_hub::config::{Config, Limits};
use mcp_hub::{build_router, db, AppState};
use tower::ServiceExt;

const BASE: &str = "http://localhost:8080";

fn test_config() -> Config {
    Config {
        base_url: BASE.into(),
        rp_id: "localhost".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        db_path: String::new(),
        env_dir: std::env::temp_dir().join(format!("mcp_hub_envs_{}", uuid::Uuid::new_v4())).to_string_lossy().into_owned(),
        master_key: [3u8; 32],
        bootstrap_admin: None,
        allow_open_registration: false,
        sandbox_uid_base: None,
        limits: Limits::default(),
        child_limits: Default::default(),

        block_private_backend_ips: false,
        allowed_hosts: Vec::new(),
        session_idle_ttl_secs: 1800,
        session_absolute_ttl_secs: 43200,
    }
}

async fn test_state() -> AppState {
    let path = std::env::temp_dir().join(format!("mcp_hub_proxy_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    AppState::new(test_config(), pool).await.unwrap()
}

fn app(state: AppState) -> axum::Router {
    build_router(state, "static")
}

#[tokio::test]
async fn mcp_without_token_is_401_with_challenge() {
    let resp = app(test_state().await)
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp.headers()["www-authenticate"].to_str().unwrap();
    assert!(challenge.contains("resource_metadata="));
    assert!(challenge.contains("/.well-known/oauth-protected-resource"));
}

#[tokio::test]
async fn mcp_with_bad_token_is_401() {
    let resp = app(test_state().await)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", "Bearer not-a-real-token")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_with_valid_token_passes_auth() {
    let state = test_state().await;
    // The proxy verifies the token's subject still exists and is enabled, so the
    // user must be present in the database.
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "client", &format!("{BASE}/mcp"), "mcp", false, 3600)
        .unwrap();

    let resp = app(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // The bearer check passed (not a 401); rmcp handles the protocol from here.
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sandbox_disabled_when_not_root_even_with_base_set() {
    // With HUB_SANDBOX_UID_BASE configured but not running as root (as in
    // tests/CI/dev), sandboxing is disabled — Ok(None), never an error — so
    // local runs and the test suite keep working. Failing closed only applies
    // once we are root and sandboxing is genuinely expected.
    let mut cfg = test_config();
    cfg.sandbox_uid_base = Some(20000);
    let path = std::env::temp_dir().join(format!("mcp_hub_sb_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    let state = AppState::new(cfg, pool).await.unwrap();
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    assert!(state.sandbox_or_fail(&user.id).await.unwrap().is_none());
}

/// Build an `/mcp` request carrying `token` as a bearer credential.
fn mcp_request(token: &str) -> Request<Body> {
    Request::post("/mcp")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
        ))
        .unwrap()
}

#[tokio::test]
async fn mcp_with_valid_pat_passes_auth() {
    let state = test_state().await;
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (_, token) = mcp_hub::tokens::create(&state.db, &user.id, "laptop", 3600)
        .await
        .unwrap();
    assert!(token.starts_with(mcp_hub::tokens::PREFIX));

    let resp = app(state).oneshot(mcp_request(&token)).await.unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_with_expired_pat_is_401() {
    let state = test_state().await;
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    // ttl in the past → already expired.
    let (_, token) = mcp_hub::tokens::create(&state.db, &user.id, "old", -10)
        .await
        .unwrap();

    let resp = app(state).oneshot(mcp_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_with_revoked_pat_is_401() {
    let state = test_state().await;
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (pat, token) = mcp_hub::tokens::create(&state.db, &user.id, "k", 3600)
        .await
        .unwrap();
    assert!(mcp_hub::tokens::revoke(&state.db, &user.id, &pat.id)
        .await
        .unwrap());

    let resp = app(state).oneshot(mcp_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_with_pat_for_disabled_user_is_401() {
    let state = test_state().await;
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (_, token) = mcp_hub::tokens::create(&state.db, &user.id, "k", 3600)
        .await
        .unwrap();
    mcp_hub::users::set_disabled(&state.db, &user.id, true)
        .await
        .unwrap();

    let resp = app(state).oneshot(mcp_request(&token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_with_unknown_session_is_404_not_401() {
    // After a hub restart the in-memory sessions are gone. A client still sending
    // its old Mcp-Session-Id must get 404 (session expired → re-initialize), not
    // 401 (which a client may treat as an auth failure and fail to recover from).
    let state = test_state().await;
    let user = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "client", &format!("{BASE}/mcp"), "mcp", false, 3600)
        .unwrap();

    let resp = app(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                // rmcp 2.x validates the Host header (DNS-rebinding guard); with
                // an empty allowlist it keeps the loopback default, so a request
                // that reaches the service must carry an allowed Host. A raw
                // `oneshot` request has none, so set one explicitly.
                .header("host", "localhost")
                .header("mcp-session-id", "stale-session-that-no-longer-exists")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_with_token_for_unknown_user_is_401() {
    // A correctly-signed token whose subject has no account (e.g. deleted) is
    // rejected, since the proxy re-checks the user on every request.
    let state = test_state().await;
    let (token, _) = state
        .signer
        .issue_access_token("ghost", "client", &format!("{BASE}/mcp"), "mcp", false, 3600)
        .unwrap();

    let resp = app(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
