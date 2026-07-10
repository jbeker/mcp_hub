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
        keep_warm: false,
        keep_warm_interval_secs: 0,
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

/// An unauthenticated hit on a group endpoint gets a challenge pointing at
/// that endpoint's own protected-resource metadata — this is how a client
/// learns to request the group's `resource` during the OAuth flow.
#[tokio::test]
async fn group_endpoint_challenge_names_its_own_metadata() {
    let resp = app(test_state().await)
        .oneshot(
            Request::post("/mcp/zabbix")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp.headers()["www-authenticate"].to_str().unwrap();
    assert!(
        challenge.contains("/.well-known/oauth-protected-resource/mcp/zabbix"),
        "got {challenge}"
    );
}

/// Paths under /mcp that are not a valid endpoint 404 before any auth work.
#[tokio::test]
async fn malformed_mcp_paths_are_404() {
    let state = test_state().await;
    for path in ["/mcp/a/b", "/mcp/Bad!", "/mcp/-nope", "/mcp/UPPER"] {
        let resp = app(state.clone())
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

/// Token audience is the endpoint's own URL: a base-endpoint token is rejected
/// on a group endpoint and vice versa; a group token only works on its own
/// slug — and only for the user who owns that slug (foreign slug → 404).
#[tokio::test]
async fn group_token_audience_and_ownership() {
    let state = test_state().await;
    let alice = mcp_hub::users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let bob = mcp_hub::users::create(&state.db, "u2", "bob", "Bob", false)
        .await
        .unwrap();
    mcp_hub::groups::create(&state.db, &alice.id, "g", "").await.unwrap();

    let issue = |user_id: &str, aud: &str| {
        state
            .signer
            .issue_access_token(user_id, "c", &format!("{BASE}{aud}"), "mcp", false, 3600)
            .unwrap()
            .0
    };
    let request = |path: &str, token: &str| {
        Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("host", "localhost")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            ))
            .unwrap()
    };

    // Base token: fine on /mcp, rejected on the group.
    let base_token = issue(&alice.id, "/mcp");
    let ok = app(state.clone()).oneshot(request("/mcp", &base_token)).await.unwrap();
    assert_ne!(ok.status(), StatusCode::UNAUTHORIZED);
    let cross = app(state.clone()).oneshot(request("/mcp/g", &base_token)).await.unwrap();
    assert_eq!(cross.status(), StatusCode::UNAUTHORIZED);

    // Group token: fine on its slug, rejected on /mcp and on a sibling slug.
    let g_token = issue(&alice.id, "/mcp/g");
    let ok = app(state.clone()).oneshot(request("/mcp/g", &g_token)).await.unwrap();
    assert_ne!(ok.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(ok.status(), StatusCode::NOT_FOUND);
    let cross = app(state.clone()).oneshot(request("/mcp", &g_token)).await.unwrap();
    assert_eq!(cross.status(), StatusCode::UNAUTHORIZED);
    let sibling = app(state.clone()).oneshot(request("/mcp/other", &g_token)).await.unwrap();
    assert_eq!(sibling.status(), StatusCode::UNAUTHORIZED);

    // Bob's token with the right audience still 404s: the slug is Alice's.
    let bob_token = issue(&bob.id, "/mcp/g");
    let foreign = app(state.clone()).oneshot(request("/mcp/g", &bob_token)).await.unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
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
