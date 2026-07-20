//! SQLite connection pool and migrations.

use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Migrations embedded at compile time from the `migrations/` directory.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Open (creating if necessary) the SQLite database and run migrations.
pub async fn connect(db_path: &str) -> Result<SqlitePool> {
    // Ensure the parent directory exists for file-backed databases.
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
    }

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))
        .context("invalid sqlite path")?
        .create_if_missing(true)
        .foreign_keys(true)
        // Generous: claude.ai refreshes every connector group's token in one
        // burst, and a writer queueing behind that burst should wait, not 500.
        // Only covers plain SQLITE_BUSY — write transactions must still BEGIN
        // IMMEDIATE to avoid SQLITE_BUSY_SNAPSHOT, which fails instantly.
        .busy_timeout(std::time::Duration::from_secs(10))
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .context("connecting to sqlite")?;

    MIGRATOR
        .run(&pool)
        .await
        .context("running database migrations")?;

    Ok(pool)
}
