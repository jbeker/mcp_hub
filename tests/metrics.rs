//! Tests for the `/metrics` Prometheus endpoint and its API-key gate.

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
    let path = std::env::temp_dir().join(format!("mcp_hub_metrics_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    AppState::new(test_config(), pool).await.unwrap()
}

fn get_metrics(bearer: Option<&str>) -> Request<Body> {
    let req = Request::get("/metrics");
    let req = match bearer {
        Some(t) => req.header("authorization", format!("Bearer {t}")),
        None => req,
    };
    req.body(Body::empty()).unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn metrics_without_key_is_401() {
    let resp = app(test_state().await).oneshot(get_metrics(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_with_wrong_key_is_401() {
    let resp = app(test_state().await)
        .oneshot(get_metrics(Some("mcphub_metrics_not-the-key")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

fn app(state: AppState) -> axum::Router {
    build_router(state, "static")
}

#[tokio::test]
async fn metrics_with_key_serves_gauges_and_counters() {
    let state = test_state().await;
    let key = state.metrics_key.read().unwrap().clone();
    assert!(key.starts_with("mcphub_metrics_"), "auto-generated on first start");

    state.metrics.record_call(
        "alice",
        "github",
        "get_me",
        std::time::Duration::from_millis(250),
        None,
    );

    let resp = app(state).oneshot(get_metrics(Some(&key))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = body_string(resp).await;
    assert!(body.contains("mcp_hub_backend_slots_total"));
    assert!(body.contains("mcp_hub_active_sessions"));
    assert!(body.contains(
        r#"mcp_hub_tool_calls_total{user="alice",server="github",tool="get_me"} 1"#
    ));
    assert!(body.contains(
        r#"mcp_hub_tool_call_duration_seconds_total{user="alice",server="github",tool="get_me"} 0.250000"#
    ));
}

#[tokio::test]
async fn key_survives_restart_and_regenerate_invalidates_old() {
    let path = std::env::temp_dir().join(format!("mcp_hub_metrics_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    let state = AppState::new(test_config(), pool.clone()).await.unwrap();
    let key = state.metrics_key.read().unwrap().clone();

    // A second AppState over the same DB (a hub restart) loads the same key.
    let state2 = AppState::new(test_config(), pool).await.unwrap();
    assert_eq!(key, state2.metrics_key.read().unwrap().clone());

    let new_key = mcp_hub::metrics::regenerate_key(&state).await.unwrap();
    assert_ne!(key, new_key);

    let resp = app(state.clone()).oneshot(get_metrics(Some(&key))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "old key must stop working");
    let resp = app(state).oneshot(get_metrics(Some(&new_key))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
