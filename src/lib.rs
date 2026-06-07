//! MCP Hub library: shared modules and the HTTP router.

pub mod auth;
pub mod catalog;
pub mod config;
pub mod crypto;
pub mod db;
pub mod gitsrc;
pub mod instances;
pub mod invites;
pub mod oauth;
pub mod proxy;
pub mod users;
pub mod util;
pub mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::Key;
use tokio::sync::Semaphore;
use tower_http::services::ServeDir;
use webauthn_rs::Webauthn;

use crate::auth::webauthn::{self as wa, AuthStore, RegStore};
use crate::config::Config;
use crate::oauth::{authorize, metadata, register, token};
use crate::crypto::SecretBox;
use crate::oauth::keys::Signer;

/// Shared application state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub secrets: SecretBox,
    pub webauthn: Arc<Webauthn>,
    pub signer: Arc<Signer>,
    pub reg_states: RegStore,
    pub auth_states: AuthStore,
    pub cookie_key: Key,
    /// Caps the total number of concurrently running backend connections.
    pub backend_slots: Arc<Semaphore>,
    /// Serializes git-source builds (they are slow and disk-bound).
    pub build_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    /// Build application state from a loaded config and an open database pool.
    pub async fn new(config: Config, db: sqlx::SqlitePool) -> anyhow::Result<Self> {
        let secrets = SecretBox::new(&config.master_key);
        let webauthn = Arc::new(wa::build(&config.base_url, &config.rp_id)?);
        let signer = Arc::new(Signer::load_or_create(&db, &secrets, &config.base_url).await?);
        if config.seed_catalog {
            crate::catalog::seed_builtins_if_empty(&db).await?;
        }
        let cookie_key = derive_cookie_key(&config.master_key);
        let backend_slots = Arc::new(Semaphore::new(config.limits.max_backends_global));
        Ok(Self {
            secrets,
            webauthn,
            signer,
            reg_states: Arc::new(Mutex::new(HashMap::new())),
            auth_states: Arc::new(Mutex::new(HashMap::new())),
            cookie_key,
            backend_slots,
            build_lock: Arc::new(tokio::sync::Mutex::new(())),
            config: Arc::new(config),
            db,
        })
    }
}

// Allows `SignedCookieJar` to extract the signing key from app state.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

/// Build the application router. `static_dir` is the path to served assets.
pub fn build_router(state: AppState, static_dir: &str) -> Router {
    let router = Router::new()
        .route("/healthz", get(healthz))
        // Web UI
        .route("/", get(web::dashboard))
        .route("/login", get(web::login_page))
        .route("/register", get(web::register_page))
        .route("/recover", get(web::recover_page))
        .route("/logout", get(web::logout_get).post(wa::logout))
        // Account / passkey management
        .route("/account", get(web::account_page))
        .route("/account/passkeys/add/start", post(wa::add_passkey_start))
        .route("/account/passkeys/remove", post(web::remove_passkey))
        .route("/account/sessions/revoke-others", post(web::revoke_other_sessions))
        .route("/account/connections/revoke", post(web::revoke_connection))
        // Catalog administration (admin)
        .route("/catalog", get(web::catalog_admin))
        .route("/catalog/new", get(web::catalog_new))
        .route("/catalog/save", post(web::catalog_save))
        .route("/catalog/{id}/edit", get(web::catalog_edit))
        .route("/catalog/{id}/delete", post(web::catalog_delete))
        // User administration (admin)
        .route("/users", get(web::users_page))
        .route("/users/disable", post(web::disable_user))
        .route("/users/enable", post(web::enable_user))
        .route("/users/delete", post(web::delete_user))
        // Server management UI
        .route("/servers/catalog", get(web::catalog_page))
        .route("/servers/add", post(web::add_server))
        .route("/servers/{id}", get(web::server_detail))
        .route("/servers/{id}/config", post(web::save_config))
        .route("/servers/{id}/enable", post(web::enable_server))
        .route("/servers/{id}/disable", post(web::disable_server))
        .route("/servers/{id}/update", post(web::update_server))
        .route("/servers/{id}/delete", post(web::delete_server))
        // Invite management (admin)
        .route("/invites", get(web::invites_page))
        .route("/invites/create", post(web::create_invite))
        .route("/invites/recovery", post(web::create_recovery))
        .route("/invites/revoke", post(web::revoke_invite))
        // WebAuthn ceremonies
        .route("/auth/register/start", post(wa::register_start))
        .route("/auth/register/finish", post(wa::register_finish))
        .route("/auth/login/start", post(wa::login_start))
        .route("/auth/login/finish", post(wa::login_finish))
        .route("/auth/recover/start", post(wa::recover_start))
        // OAuth 2.1 discovery metadata
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        // Some clients append the resource path to the well-known URL.
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(metadata::protected_resource),
        )
        .route("/.well-known/jwks.json", get(metadata::jwks))
        // OAuth 2.1 endpoints
        .route("/register", post(register::register))
        .route("/authorize", get(authorize::authorize))
        .route("/authorize/decision", post(authorize::decision))
        .route("/token", post(token::token))
        // MCP proxy endpoint (bearer-authenticated, aggregates user backends)
        .nest_service("/mcp", crate::proxy::mcp_router(state.clone()))
        // Static assets
        .nest_service("/static", ServeDir::new(static_dir))
        .with_state(state);

    // Conservative security headers on every response. TLS/HSTS is the reverse
    // proxy's job; these cover framing, MIME sniffing, referrer leakage, and a
    // CSP that forbids inline scripts.
    const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
        img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
    use axum::http::{header, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;
    router
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
}

async fn healthz() -> &'static str {
    "ok"
}

/// Expand the 32-byte master key into a 64-byte cookie-signing key.
pub fn derive_cookie_key(master: &[u8; 32]) -> Key {
    use sha2::{Digest, Sha256};
    let mut material = Vec::with_capacity(64);
    for label in [b"hub-cookie-1".as_slice(), b"hub-cookie-2".as_slice()] {
        let mut h = Sha256::new();
        h.update(label);
        h.update(master);
        material.extend_from_slice(&h.finalize());
    }
    Key::from(&material)
}
