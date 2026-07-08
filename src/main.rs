//! MCP Hub — multi-user MCP management and proxy server (binary entrypoint).

use anyhow::Result;
use mcp_hub::{build_router, config::Config, db, AppState};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;
    tracing::info!(base_url = %config.base_url, rp_id = %config.rp_id, "starting mcp_hub");

    let db = db::connect(&config.db_path).await?;
    let listen = config.listen;
    let state = AppState::new(config, db).await?;

    spawn_session_sweeper(state.db.clone());
    spawn_backend_reaper(state.clone());
    spawn_backend_warmer(state.clone());

    let app = build_router(state, "static");

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(addr = %listen, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Periodically sweep expired browser sessions from the database. Expired rows
/// never authenticate, so this is only housekeeping to stop the table growing
/// with dead sessions from one-off logins.
fn spawn_session_sweeper(db: sqlx::SqlitePool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            match mcp_hub::auth::session::delete_expired(&db).await {
                Ok(n) if n > 0 => tracing::debug!(swept = n, "expired sessions removed"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "session sweep failed"),
            }
        }
    });
}

/// Keep every enabled user's pooled backends hot (`HUB_KEEP_WARM`, default
/// on): bind them all at startup and re-touch each minute so a new connection
/// never pays a cold start and a crashed backend is respawned without waiting
/// for a request. The touch counts as use, so warmed pools are never idle
/// enough for [`spawn_backend_reaper`] to retire.
fn spawn_backend_warmer(state: AppState) {
    if !state.config.keep_warm {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        // Log the startup pass at info and later passes only when the counts
        // moved (a backend appeared/disappeared) — a steady-state tick is pure
        // no-op housekeeping and logs at trace so the default `mcp_hub=debug`
        // filter stays quiet. The pool itself already logs any actual respawn.
        let mut last: Option<(usize, usize)> = None;
        loop {
            ticker.tick().await;
            let (users, backends) = mcp_hub::proxy::pool::warm_all(&state).await;
            match last {
                None => tracing::info!(users, backends, "warmed user backends"),
                Some(prev) if prev != (users, backends) => {
                    tracing::debug!(users, backends, "re-warmed user backends")
                }
                _ => tracing::trace!(users, backends, "re-warmed user backends"),
            }
            last = Some((users, backends));
        }
    });
}

/// Periodically retire pooled backends whose owner has made no MCP request for
/// `HUB_BACKEND_IDLE_SECS` (0 disables reaping — backends then live until the
/// hub restarts). This is what frees global backend slots between sessions.
fn spawn_backend_reaper(state: AppState) {
    let idle_secs = state.config.limits.backend_idle_secs;
    if idle_secs == 0 {
        return;
    }
    tokio::spawn(async move {
        let period = (idle_secs / 4).clamp(30, 300);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(period));
        loop {
            ticker.tick().await;
            let (users, backends) = state
                .backend_pool
                .reap_idle(std::time::Duration::from_secs(idle_secs));
            if users > 0 {
                tracing::info!(users, backends, idle_secs, "reaped idle backends");
            }
        }
    });
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,mcp_hub=debug"));
    let registry = tracing_subscriber::registry().with(filter);
    // `HUB_LOG_FORMAT=json` emits one JSON object per event so a log aggregator
    // (Datadog, …) can index the structured audit fields directly. Anything else
    // (the default) keeps the human-readable text format for local development.
    let json = std::env::var("HUB_LOG_FORMAT").as_deref() == Ok("json");
    if json {
        registry.with(tracing_subscriber::fmt::layer().json()).init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}
