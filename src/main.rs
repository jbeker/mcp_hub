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

    let app = build_router(state, "static");

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(addr = %listen, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mcp_hub=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
