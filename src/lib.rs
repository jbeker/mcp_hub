//! MCP Hub library: shared modules and the HTTP router.

pub mod access;
pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod gitsrc;
pub mod groups;
pub mod instances;
pub mod invites;
pub mod metrics;
pub mod oauth;
pub mod proxy;
pub mod sandbox;
pub mod stats;
pub mod tokens;
pub mod users;
pub mod util;
pub mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::Key;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::{Peer, RoleServer};
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
    /// OAuth authorization codes awaiting exchange. In-memory: codes are
    /// 10-minute single-use handshake state; a restart just voids in-flight
    /// logins.
    pub auth_codes: crate::oauth::store::AuthCodeStore,
    pub cookie_key: Key,
    /// Caps the total number of concurrently running backend connections.
    pub backend_slots: Arc<Semaphore>,
    /// The per-user pool of live backend connections, shared across each
    /// user's MCP sessions and retired by the idle reaper
    /// (`HUB_BACKEND_IDLE_SECS`).
    pub backend_pool: Arc<crate::proxy::pool::BackendPool>,
    /// Serializes git-source builds (they are slow and disk-bound).
    pub build_lock: Arc<tokio::sync::Mutex<()>>,
    /// The `/mcp` endpoint's session store. Shared with the proxy router so the
    /// admin stats page can read the live active-session count.
    pub session_manager: Arc<LocalSessionManager>,
    /// Per-instance "reload epoch". The web Restart button bumps an instance's
    /// counter; each live proxy session compares it against the epoch it last
    /// acted on and respawns that backend when it advances. In-memory only —
    /// a hub restart re-binds every session from scratch anyway.
    pub reload_epochs: Arc<Mutex<HashMap<String, u64>>>,
    /// Live MCP client peers, keyed by an opaque per-session id. Lets the hub
    /// push `notifications/tools/list_changed` to a connected (even idle) client
    /// when its backend set changes (e.g. the web Restart button), so it
    /// re-fetches without a manual refresh. In-memory; entries are removed when
    /// the session's `HubProxy` is dropped.
    pub client_peers: Arc<Mutex<HashMap<uuid::Uuid, ClientPeer>>>,
    /// In-memory usage counters served by `/metrics`; reset on restart.
    pub metrics: Arc<crate::metrics::Metrics>,
    /// The API key gating `/metrics`, sealed at rest in the `settings` table
    /// and swapped in place when an admin regenerates it.
    pub metrics_key: Arc<std::sync::RwLock<String>>,
}

/// A registered client session's notification channel.
pub struct ClientPeer {
    pub user_id: String,
    pub peer: Peer<RoleServer>,
}

impl AppState {
    /// Build application state from a loaded config and an open database pool.
    pub async fn new(config: Config, db: sqlx::SqlitePool) -> anyhow::Result<Self> {
        let secrets = SecretBox::new(&config.master_key);
        let webauthn = Arc::new(wa::build(&config.base_url, &config.rp_id)?);
        let signer = Arc::new(Signer::load_or_create(&db, &secrets, &config.base_url).await?);
        // Convert any legacy catalog-backed instances into self-contained defs.
        crate::instances::migrate_catalog_instances(&db, &secrets).await?;
        // Give every existing user a sandbox slot, and lock the DB to root when
        // sandboxing stdio (so dropped subprocesses can't read the secrets DB).
        crate::users::assign_sandbox_slots(&db).await?;
        if config.sandbox_uid_base.is_some() && crate::sandbox::is_root() {
            crate::sandbox::lock_database(&config.db_path);
        }
        let cookie_key = derive_cookie_key(&config.master_key);
        let backend_slots = Arc::new(Semaphore::new(config.limits.max_backends_global));
        let metrics_key = crate::metrics::load_or_create_key(&db, &secrets).await?;
        Ok(Self {
            metrics: Arc::new(crate::metrics::Metrics::default()),
            metrics_key: Arc::new(std::sync::RwLock::new(metrics_key)),
            secrets,
            webauthn,
            signer,
            reg_states: Arc::new(Mutex::new(HashMap::new())),
            auth_states: Arc::new(Mutex::new(HashMap::new())),
            auth_codes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            cookie_key,
            backend_slots,
            backend_pool: Arc::new(crate::proxy::pool::BackendPool::default()),
            build_lock: Arc::new(tokio::sync::Mutex::new(())),
            session_manager: Arc::new(LocalSessionManager::default()),
            reload_epochs: Arc::new(Mutex::new(HashMap::new())),
            client_peers: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
            db,
        })
    }

    /// Register a live client session's notification peer under an opaque key,
    /// so [`notify_tools_changed`](Self::notify_tools_changed) can later push to
    /// it. Idempotent: re-registering the same key replaces the entry.
    pub fn register_client_peer(&self, key: uuid::Uuid, user_id: &str, peer: Peer<RoleServer>) {
        self.client_peers.lock().unwrap().insert(
            key,
            ClientPeer {
                user_id: user_id.to_string(),
                peer,
            },
        );
    }

    /// Drop a client session's notification peer (its `HubProxy` went away).
    pub fn unregister_client_peer(&self, key: uuid::Uuid) {
        self.client_peers.lock().unwrap().remove(&key);
    }

    /// Push `notifications/tools/list_changed` to every live session belonging to
    /// `user_id`, so a connected (even idle) client re-fetches its tool list. The
    /// hub advertises `tools.listChanged`, so this is the honest fulfilment of
    /// that capability. Best-effort and non-blocking: peers are cloned out under
    /// the lock and notified from a spawned task; a peer whose transport has
    /// closed is pruned.
    pub fn notify_tools_changed(&self, user_id: &str) {
        let targets: Vec<(uuid::Uuid, Peer<RoleServer>)> = self
            .client_peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, cp)| cp.user_id == user_id)
            .map(|(k, cp)| (*k, cp.peer.clone()))
            .collect();
        if targets.is_empty() {
            return;
        }
        let registry = self.client_peers.clone();
        tokio::spawn(async move {
            for (key, peer) in targets {
                if let Err(e) = peer.notify_tool_list_changed().await {
                    tracing::debug!(error = %e, "tools/list_changed send failed; pruning peer");
                    registry.lock().unwrap().remove(&key);
                }
            }
        });
    }

    /// Bump an instance's reload epoch so every live proxy session relaunches
    /// that backend on its next request (the web Restart button).
    pub fn bump_reload(&self, instance_id: &str) {
        *self
            .reload_epochs
            .lock()
            .unwrap()
            .entry(instance_id.to_string())
            .or_insert(0) += 1;
    }

    /// The current reload epoch for an instance (0 if it has never been bumped).
    pub fn reload_epoch(&self, instance_id: &str) -> u64 {
        self.reload_epochs
            .lock()
            .unwrap()
            .get(instance_id)
            .copied()
            .unwrap_or(0)
    }

    /// The absolute sandbox UID a given user's stdio subprocesses run as, or
    /// `None` if sandboxing is off (no base, not root, or no slot).
    pub async fn sandbox_uid(&self, user_id: &str) -> Option<u32> {
        let slot = crate::users::sandbox_slot(&self.db, user_id).await.ok().flatten();
        crate::sandbox::uid_for(self.config.sandbox_uid_base, slot)
    }

    /// Resolve the sandbox identity for a user's subprocesses and git builds,
    /// **failing closed**. Returns `Ok(None)` only when sandboxing is genuinely
    /// disabled — no `HUB_SANDBOX_UID_BASE` configured, or not running as root
    /// (dev/test). When sandboxing *is* configured, a missing UID slot or a
    /// failure to prepare the per-UID cache dir is an error, never a silent drop
    /// to running user-controlled code as root.
    pub async fn sandbox_or_fail(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Option<crate::sandbox::Sandbox>> {
        if self.config.sandbox_uid_base.is_none() || !crate::sandbox::is_root() {
            return Ok(None);
        }
        let slot = crate::users::sandbox_slot(&self.db, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("sandbox is required but the user has no UID slot"))?;
        let uid = crate::sandbox::uid_for(self.config.sandbox_uid_base, Some(slot))
            .ok_or_else(|| anyhow::anyhow!("sandbox is required but its UID could not be derived"))?;
        crate::sandbox::prepare(uid, &self.config.env_dir)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("sandbox is required but could not be prepared: {e}"))
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
        // Prometheus exposition for Zabbix scraping (metrics-API-key gated).
        .route("/metrics", get(metrics::endpoint))
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
        .route("/account/connections/label", post(web::update_connection_label))
        .route("/account/connections/access", post(web::update_connection_access))
        .route("/account/tokens/create", post(web::create_token))
        .route("/account/tokens/revoke", post(web::revoke_token))
        .route("/account/tokens/access", post(web::update_token_access))
        // User administration (admin)
        .route("/users", get(web::users_page))
        .route("/stats", get(web::stats_page))
        .route("/stats/metrics-key/regenerate", post(web::regenerate_metrics_key))
        .route("/users/disable", post(web::disable_user))
        .route("/users/enable", post(web::enable_user))
        .route("/users/delete", post(web::delete_user))
        // Server management UI (every user manages their own)
        .route("/servers/new", get(web::new_server))
        .route("/servers/create", post(web::create_server))
        .route("/servers/{id}", get(web::server_detail))
        .route("/servers/{id}/capabilities", get(web::server_capabilities))
        .route("/servers/{id}/capabilities/refresh", post(web::refresh_capabilities))
        .route("/servers/{id}/config", post(web::save_config))
        .route("/servers/{id}/test", post(web::test_server))
        .route("/servers/{id}/enable", post(web::enable_server))
        .route("/servers/{id}/disable", post(web::disable_server))
        .route("/servers/{id}/restart", post(web::restart_server))
        .route("/servers/{id}/update", post(web::update_server))
        .route("/servers/{id}/delete", post(web::delete_server))
        // Connector group management (every user manages their own)
        .route("/groups/create", post(web::create_group))
        .route("/groups/{id}/update", post(web::update_group))
        .route("/groups/{id}/delete", post(web::delete_group))
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
        // Connector-group endpoints each have their own resource metadata.
        .route(
            "/.well-known/oauth-protected-resource/mcp/{slug}",
            get(metadata::protected_resource_group),
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
