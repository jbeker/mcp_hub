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
