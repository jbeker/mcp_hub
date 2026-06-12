//! Integration tests for the web/auth surface.
//!
//! The full passkey ceremony needs a real authenticator, so these tests cover
//! everything up to and around challenge issuance: page rendering, the
//! auth-required redirect, the registration policy, and that `start` returns a
//! well-formed WebAuthn challenge. The end-to-end passkey round-trip is
//! exercised manually with a browser in the M7 e2e step.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mcp_hub::config::{Config, Limits};
use mcp_hub::{build_router, db, users, AppState};
use tower::ServiceExt; // for `oneshot`

fn test_config() -> Config {
    Config {
        base_url: "http://localhost:8080".into(),
        rp_id: "localhost".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        db_path: String::new(),
        env_dir: std::env::temp_dir().join(format!("mcp_hub_envs_{}", uuid::Uuid::new_v4())).to_string_lossy().into_owned(),
        master_key: [7u8; 32],
        bootstrap_admin: None,
        allow_open_registration: false,
        sandbox_uid_base: None,
        limits: Limits::default(),
        child_limits: Default::default(),

        block_private_backend_ips: false,
    }
}

async fn test_state() -> AppState {
    // Unique temp DB file per test invocation.
    let path = std::env::temp_dir().join(format!("mcp_hub_test_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    AppState::new(test_config(), pool).await.unwrap()
}

fn app(state: AppState) -> axum::Router {
    build_router(state, "static")
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn healthz_ok() {
    let resp = app(test_state().await)
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "ok");
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let resp = app(test_state().await)
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let h = resp.headers();
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    assert!(h["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("script-src 'self'"));
}

#[tokio::test]
async fn login_page_renders() {
    let resp = app(test_state().await)
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Sign in"));
}

#[tokio::test]
async fn dashboard_redirects_when_anonymous() {
    let resp = app(test_state().await)
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()["location"], "/login");
}

#[tokio::test]
async fn first_user_registration_issues_challenge() {
    let resp = app(test_state().await)
        .oneshot(
            Request::post("/auth/register/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"handle":"alice","display_name":"Alice"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // A short-lived ceremony cookie must be set.
    assert!(resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("hub_ceremony=")));
    let body = body_string(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["publicKey"]["challenge"].is_string());
    assert!(json["publicKey"]["user"]["name"] == "alice");
}

#[tokio::test]
async fn login_start_does_not_enumerate_users() {
    let state = test_state().await;
    // An existing account with no passkeys, and a nonexistent handle, must
    // produce the identical response so handles cannot be probed.
    users::create(&state.db, "u1", "realuser", "Real", false)
        .await
        .unwrap();

    let call = |app: axum::Router, handle: &str| {
        let body = format!(r#"{{"handle":"{handle}"}}"#);
        app.oneshot(
            Request::post("/auth/login/start")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
    };

    let r1 = call(app(state.clone()), "realuser").await.unwrap();
    let s1 = r1.status();
    let b1 = body_string(r1).await;
    let r2 = call(app(state), "ghost").await.unwrap();
    let s2 = r2.status();
    let b2 = body_string(r2).await;

    assert_eq!(s1, StatusCode::UNAUTHORIZED);
    assert_eq!(s1, s2);
    assert_eq!(b1, b2, "responses must be indistinguishable");
}

#[tokio::test]
async fn registration_closed_after_first_user() {
    let state = test_state().await;
    // Simulate an existing account; open registration is off by default.
    users::create(&state.db, "u1", "existing", "Existing", true)
        .await
        .unwrap();

    let resp = app(state)
        .oneshot(
            Request::post("/auth/register/start")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"handle":"bob","display_name":"Bob"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bootstrap_admin_handle_is_enforced() {
    let mut cfg = test_config();
    cfg.bootstrap_admin = Some("rootadmin".into());
    let path = std::env::temp_dir().join(format!("mcp_hub_test_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    let state = AppState::new(cfg, pool).await.unwrap();

    // Wrong handle for the very first account is rejected.
    let resp = app(state)
        .oneshot(
            Request::post("/auth/register/start")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"handle":"intruder","display_name":"X"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
