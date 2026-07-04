//! Integration tests for the OAuth 2.1 Authorization Server.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mcp_hub::config::{Config, Limits};
use mcp_hub::oauth::{b64url, sha256, store};
use mcp_hub::{auth::session, build_router, db, users, AppState};
use tower::ServiceExt;

const BASE: &str = "http://localhost:8080";

fn test_config() -> Config {
    Config {
        base_url: BASE.into(),
        rp_id: "localhost".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        db_path: String::new(),
        env_dir: std::env::temp_dir().join(format!("mcp_hub_envs_{}", uuid::Uuid::new_v4())).to_string_lossy().into_owned(),
        master_key: [9u8; 32],
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
    let path = std::env::temp_dir().join(format!("mcp_hub_oauth_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    AppState::new(test_config(), pool).await.unwrap()
}

fn app(state: AppState) -> axum::Router {
    build_router(state, "static")
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn text_body(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Forge a valid signed session cookie header value for an existing session id.
fn signed_session_cookie(state: &AppState, sid: &str) -> String {
    use cookie::{Cookie, CookieJar};
    let key: cookie::Key = state.cookie_key.clone();
    let mut jar = CookieJar::new();
    jar.signed_mut(&key)
        .add(Cookie::new(session::SESSION_COOKIE.to_string(), sid.to_string()));
    let c = jar.get(session::SESSION_COOKIE).unwrap();
    format!("{}={}", session::SESSION_COOKIE, c.value())
}

/// Pull a single `name=value` cookie pair out of a response's Set-Cookie headers.
fn set_cookie(resp: &axum::response::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|s| {
            let first = s.split(';').next()?;
            first.starts_with(&format!("{name}=")).then(|| first.to_string())
        })
}

#[tokio::test]
async fn metadata_documents() {
    let app = app(test_state().await);

    let as_meta = json_body(
        app.clone()
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(as_meta["issuer"], BASE);
    assert_eq!(as_meta["authorization_endpoint"], format!("{BASE}/authorize"));
    assert_eq!(as_meta["code_challenge_methods_supported"][0], "S256");

    let pr_meta = json_body(
        app.clone()
            .oneshot(
                Request::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(pr_meta["resource"], format!("{BASE}/mcp"));
    assert_eq!(pr_meta["authorization_servers"][0], BASE);

    let jwks = json_body(
        app.oneshot(
            Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(jwks["keys"][0]["kty"], "EC");
    assert_eq!(jwks["keys"][0]["alg"], "ES256");
}

#[tokio::test]
async fn dynamic_client_registration() {
    let resp = app(test_state().await)
        .oneshot(
            Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"redirect_uris":["http://127.0.0.1:9999/cb"],"client_name":"Test","token_endpoint_auth_method":"none"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert!(body["client_id"].as_str().unwrap().starts_with("hub_"));
    assert_eq!(body["token_endpoint_auth_method"], "none");
    // Public client: no secret issued.
    assert!(body["client_secret"].is_null());
}

#[tokio::test]
async fn authorize_redirects_anonymous_to_login() {
    let state = test_state().await;
    store::create_client(
        &state.db,
        "client-x",
        None,
        &["http://127.0.0.1:9999/cb".into()],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let uri = "/authorize?response_type=code&client_id=client-x&redirect_uri=http://127.0.0.1:9999/cb&code_challenge=abc&code_challenge_method=S256&state=xyz";
    let resp = app(state)
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with("/login?next="));
}

#[tokio::test]
async fn authorize_rejects_unknown_client() {
    let resp = app(test_state().await)
        .oneshot(
            Request::get("/authorize?response_type=code&client_id=nope&redirect_uri=http://x/cb&code_challenge=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(text_body(resp).await.contains("unknown client_id"));
}

#[tokio::test]
async fn token_authorization_code_pkce_happy_path() {
    let state = test_state().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", true)
        .await
        .unwrap();
    store::create_client(
        &state.db,
        "client-x",
        None,
        &["http://127.0.0.1:9999/cb".into()],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let verifier = "abc123_verifier-with-enough-entropy-padding-xxxxxxxxxxxxxxxx";
    let challenge = b64url(&sha256(verifier.as_bytes()));
    store::insert_code(
        &state.db,
        "thecode",
        "client-x",
        &user.id,
        "http://127.0.0.1:9999/cb",
        &challenge,
        "mcp",
        Some(&format!("{BASE}/mcp")),
        600,
    )
    .await
    .unwrap();

    let body = format!(
        "grant_type=authorization_code&code=thecode&client_id=client-x&redirect_uri={}&code_verifier={}",
        urlencoding("http://127.0.0.1:9999/cb"),
        verifier
    );
    let resp = app(state.clone())
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let access = json["access_token"].as_str().unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["refresh_token"].is_string());

    // The issued token verifies against our signer with the right audience.
    let claims = state
        .signer
        .verify_access_token(access, &format!("{BASE}/mcp"))
        .unwrap();
    assert_eq!(claims.sub, "u1");
    assert!(claims.admin);
}

#[tokio::test]
async fn token_rejects_wrong_pkce_verifier() {
    let state = test_state().await;
    users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    store::create_client(&state.db, "c", None, &["http://x/cb".into()], &serde_json::json!({}))
        .await
        .unwrap();
    let challenge = b64url(&sha256(b"the-real-verifier"));
    store::insert_code(&state.db, "code2", "c", "u1", "http://x/cb", &challenge, "mcp", None, 600)
        .await
        .unwrap();

    let body = "grant_type=authorization_code&code=code2&client_id=c&redirect_uri=http://x/cb&code_verifier=WRONG";
    let resp = app(state)
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn authorization_code_is_single_use() {
    let state = test_state().await;
    users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    store::create_client(&state.db, "c", None, &["http://x/cb".into()], &serde_json::json!({}))
        .await
        .unwrap();
    let verifier = "verifier-value-with-sufficient-length-aaaaaaaaaaaaaaaaaaaa";
    let challenge = b64url(&sha256(verifier.as_bytes()));
    store::insert_code(&state.db, "once", "c", "u1", "http://x/cb", &challenge, "mcp", None, 600)
        .await
        .unwrap();

    let mk = || {
        Request::post("/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code=once&client_id=c&redirect_uri=http://x/cb&code_verifier={verifier}"
            )))
            .unwrap()
    };

    let first = app(state.clone()).oneshot(mk()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app(state).oneshot(mk()).await.unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_consent_flow_issues_and_exchanges_code() {
    let state = test_state().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let sid = session::create(&state.db, &user.id, &Default::default(), state.config.session_idle_ttl_secs).await.unwrap();
    let session_header = signed_session_cookie(&state, &sid);
    store::create_client(
        &state.db,
        "client-x",
        None,
        &["http://127.0.0.1:9999/cb".into()],
        &serde_json::json!({ "client_name": "My Client" }),
    )
    .await
    .unwrap();

    let verifier = "consent-flow-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let challenge = b64url(&sha256(verifier.as_bytes()));
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id=client-x&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=st123&resource={}",
        urlencoding("http://127.0.0.1:9999/cb"),
        challenge,
        urlencoding(&format!("{BASE}/mcp")),
    );

    // GET /authorize while logged in -> consent page + an authreq cookie.
    let get = app(state.clone())
        .oneshot(
            Request::get(&authorize_uri)
                .header("cookie", &session_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let authreq = set_cookie(&get, "hub_authreq").expect("authreq cookie set");
    let consent_html = text_body(get).await;
    assert!(consent_html.contains("My Client"));
    let csrf = extract_csrf(&consent_html).expect("consent page carries a CSRF token");

    // POST the approval, carrying session + authreq cookies and the CSRF token.
    let decision = app(state.clone())
        .oneshot(
            Request::post("/authorize/decision")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("{session_header}; {authreq}"))
                .body(Body::from(format!("decision=approve&csrf={}", urlencoding(&csrf))))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decision.status(), StatusCode::SEE_OTHER);
    let location = decision.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains("state=st123"));
    let code = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("code in redirect");

    // Exchange the code at the token endpoint.
    let token = app(state.clone())
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id=client-x&redirect_uri={}&code_verifier={verifier}",
                    urlencoding("http://127.0.0.1:9999/cb"),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let tj = json_body(token).await;
    let refresh = tj["refresh_token"].as_str().unwrap().to_string();
    state
        .signer
        .verify_access_token(tj["access_token"].as_str().unwrap(), &format!("{BASE}/mcp"))
        .unwrap();

    // The refresh token mints a new access token.
    let refreshed = app(state)
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id=client-x",
                    urlencoding(&refresh)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert!(json_body(refreshed).await["access_token"].is_string());
}

#[tokio::test]
async fn refresh_token_reuse_revokes_the_family() {
    let state = test_state().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    store::create_client(&state.db, "c", None, &["http://x/cb".into()], &serde_json::json!({}))
        .await
        .unwrap();

    // Mint an initial refresh token via the authorization_code grant.
    let verifier = "reuse-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let challenge = b64url(&sha256(verifier.as_bytes()));
    store::insert_code(&state.db, "rc", "c", "u1", "http://x/cb", &challenge, "mcp", None, 600)
        .await
        .unwrap();
    let _ = user;
    let tok = app(state.clone())
        .oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code=rc&client_id=c&redirect_uri=http://x/cb&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let r1 = json_body(tok).await["refresh_token"].as_str().unwrap().to_string();

    // First rotation succeeds and yields r2.
    let refresh = |rt: String| {
        app(state.clone()).oneshot(
            Request::post("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}&client_id=c",
                    urlencoding(&rt)
                )))
                .unwrap(),
        )
    };
    let resp1 = refresh(r1.clone()).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let r2 = json_body(resp1).await["refresh_token"].as_str().unwrap().to_string();

    // Replaying the now-consumed r1 must be rejected (reuse detected)...
    let replay = refresh(r1).await.unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(replay).await["error"], "invalid_grant");

    // ...and it revokes the whole family, so the legitimate r2 also stops working.
    let after = refresh(r2).await.unwrap();
    assert_eq!(after.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consent_without_csrf_is_rejected() {
    let state = test_state().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let sid = session::create(&state.db, &user.id, &Default::default(), state.config.session_idle_ttl_secs).await.unwrap();
    let session_header = signed_session_cookie(&state, &sid);
    store::create_client(
        &state.db,
        "client-x",
        None,
        &["http://127.0.0.1:9999/cb".into()],
        &serde_json::json!({}),
    )
    .await
    .unwrap();

    let challenge = b64url(&sha256(b"verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    let uri = format!(
        "/authorize?response_type=code&client_id=client-x&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
        urlencoding("http://127.0.0.1:9999/cb"),
        challenge,
    );
    let get = app(state.clone())
        .oneshot(
            Request::get(&uri)
                .header("cookie", &session_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let authreq = set_cookie(&get, "hub_authreq").unwrap();

    // Approve with a forged/missing CSRF token: must not issue a code.
    let decision = app(state)
        .oneshot(
            Request::post("/authorize/decision")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("{session_header}; {authreq}"))
                .body(Body::from("decision=approve&csrf=forged"))
                .unwrap(),
        )
        .await
        .unwrap();
    // No redirect to the client (no code leaked); an error page is shown instead.
    assert_ne!(decision.status(), StatusCode::SEE_OTHER);
}

/// Pull the hidden CSRF token value out of a rendered HTML form.
fn extract_csrf(html: &str) -> Option<String> {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

/// Minimal percent-encoding for test request bodies.
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
