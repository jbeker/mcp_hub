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
        limits: Limits::default(),
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
