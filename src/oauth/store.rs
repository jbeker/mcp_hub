//! Persistence for OAuth clients, authorization codes and refresh tokens.

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::util::now_unix;

/// True when an error chain bottoms out in SQLite's transient "database is
/// locked" (SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT).
fn is_busy(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.to_string().contains("database is locked"))
}

/// Retry a store operation a few times when SQLite reports the database
/// locked. claude.ai refreshes every connector group's token in one burst, so
/// the token endpoint sees concurrent writers; a brief retry turns a lock
/// stall into a served request instead of a 500.
async fn retry_busy<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    const BACKOFF_MS: [u64; 3] = [50, 150, 300];
    for delay in BACKOFF_MS {
        match op().await {
            Err(e) if is_busy(&e) => {
                crate::metrics::note_db_busy_retry();
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            other => return other,
        }
    }
    op().await
}

/// A registered OAuth client (created via Dynamic Client Registration).
#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub metadata: serde_json::Value,
}

pub async fn create_client(
    pool: &SqlitePool,
    client_id: &str,
    client_secret_hash: Option<&str>,
    redirect_uris: &[String],
    metadata: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris_json, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(client_id)
    .bind(client_secret_hash)
    .bind(serde_json::to_string(redirect_uris)?)
    .bind(serde_json::to_string(metadata)?)
    .bind(now_unix())
    .execute(pool)
    .await
    .context("inserting oauth client")?;
    Ok(())
}

pub async fn get_client(pool: &SqlitePool, client_id: &str) -> Result<Option<Client>> {
    let row: Option<(String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT client_id, client_secret_hash, redirect_uris_json, metadata_json
         FROM oauth_clients WHERE client_id = ?",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    let Some((client_id, secret, uris, meta)) = row else {
        return Ok(None);
    };
    Ok(Some(Client {
        client_id,
        client_secret_hash: secret,
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        metadata: serde_json::from_str(&meta).unwrap_or_else(|_| serde_json::json!({})),
    }))
}

/// An issued authorization code awaiting exchange at the token endpoint.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub resource: Option<String>,
}

/// A pending authorization code with its expiry. Codes are 10-minute,
/// single-use handshake state, worthless across a restart, so they live in
/// process memory (the hub is single-process by design — the backend pool,
/// reload epochs and sessions already assume it).
pub struct PendingCode {
    auth: AuthCode,
    expires_at: i64,
}

/// In-memory store of authorization codes awaiting exchange, on
/// [`crate::AppState`]. Follows the webauthn ceremony-store pattern
/// (`auth::webauthn::insert_ceremony`): expired entries are evicted on
/// insert, and a capacity bound keeps an authorize-spammer from growing
/// memory unboundedly.
pub type AuthCodeStore =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, PendingCode>>>;

/// Bound on codes awaiting exchange; far above any legitimate number of
/// simultaneously in-flight logins.
const AUTH_CODE_CAP: usize = 512;

#[allow(clippy::too_many_arguments)]
pub fn insert_code(
    store: &AuthCodeStore,
    code: &str,
    client_id: &str,
    user_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: &str,
    resource: Option<&str>,
    ttl_secs: i64,
) -> Result<()> {
    let now = now_unix();
    let mut map = store
        .lock()
        .map_err(|_| anyhow::anyhow!("auth code store poisoned"))?;
    map.retain(|_, c| c.expires_at > now);
    if map.len() >= AUTH_CODE_CAP {
        anyhow::bail!("too many authorizations in progress");
    }
    map.insert(
        code.to_string(),
        PendingCode {
            auth: AuthCode {
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                code_challenge: code_challenge.to_string(),
                scope: scope.to_string(),
                resource: resource.map(str::to_string),
            },
            expires_at: now + ttl_secs,
        },
    );
    Ok(())
}

/// Atomically consume an authorization code (one-time use). Returns the code
/// if it existed and had not expired. The remove happens regardless of
/// expiry so a replay cannot reuse it; single-use is guaranteed by
/// `HashMap::remove` under the store's mutex.
pub fn take_code(store: &AuthCodeStore, code: &str) -> Result<Option<AuthCode>> {
    let mut map = store
        .lock()
        .map_err(|_| anyhow::anyhow!("auth code store poisoned"))?;
    Ok(map
        .remove(code)
        .filter(|c| c.expires_at >= now_unix())
        .map(|c| c.auth))
}

/// A refresh token record (only the hash is stored).
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub resource: Option<String>,
    pub family_id: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_refresh(
    pool: &SqlitePool,
    token_hash: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    resource: Option<&str>,
    family_id: &str,
    ttl_secs: i64,
    info: &crate::auth::RequestInfo,
) -> Result<()> {
    let now = now_unix();
    retry_busy(|| async {
        sqlx::query(
            "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scope, resource, family_id, consumed, created_at, expires_at, last_ip, last_user_agent)
             VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
        )
        .bind(token_hash)
        .bind(client_id)
        .bind(user_id)
        .bind(scope)
        .bind(resource)
        .bind(family_id)
        .bind(now)
        .bind(now + ttl_secs)
        .bind(info.ip.as_deref())
        .bind(info.user_agent.as_deref())
        .execute(pool)
        .await
        .context("inserting refresh token")?;
        Ok(())
    })
    .await
}

/// The outcome of presenting a refresh token at the token endpoint.
pub enum RefreshOutcome {
    /// Valid first use; the token is now marked consumed.
    Valid(RefreshToken),
    /// An already-consumed token was replayed — the family must be revoked.
    Replayed { family_id: String },
    /// Unknown or expired.
    Missing,
}

/// Columns selected from `oauth_refresh_tokens` when consuming a token.
type RefreshRow = (String, String, String, Option<String>, String, bool, i64);

/// Atomically consume a refresh token, detecting replay of a rotated token.
pub async fn consume_refresh(pool: &SqlitePool, token_hash: &str) -> Result<RefreshOutcome> {
    retry_busy(|| consume_refresh_once(pool, token_hash)).await
}

/// One attempt at [`consume_refresh`]. `BEGIN IMMEDIATE` for the same reason
/// as [`take_code_once`]: this SELECT-then-UPDATE is exactly the deferred
/// reader-to-writer upgrade that fails with SQLITE_BUSY_SNAPSHOT when the
/// connector groups all refresh at once.
async fn consume_refresh_once(pool: &SqlitePool, token_hash: &str) -> Result<RefreshOutcome> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .context("starting immediate transaction")?;

    let result: Result<RefreshOutcome> = async {
        let row: Option<RefreshRow> = sqlx::query_as(
            "SELECT client_id, user_id, scope, resource, family_id, consumed, expires_at
             FROM oauth_refresh_tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&mut *conn)
        .await?;

        let Some((client_id, user_id, scope, resource, family_id, consumed, expires_at)) = row
        else {
            return Ok(RefreshOutcome::Missing);
        };

        if expires_at < now_unix() {
            sqlx::query("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?")
                .bind(token_hash)
                .execute(&mut *conn)
                .await?;
            return Ok(RefreshOutcome::Missing);
        }

        if consumed {
            return Ok(RefreshOutcome::Replayed { family_id });
        }

        // First use: mark consumed so a later replay is detected.
        sqlx::query("UPDATE oauth_refresh_tokens SET consumed = 1 WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *conn)
            .await?;
        Ok(RefreshOutcome::Valid(RefreshToken {
            client_id,
            user_id,
            scope,
            resource,
            family_id,
        }))
    }
    .await;

    match result {
        Ok(outcome) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(outcome)
        }
        Err(e) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

/// Revoke every token in a family (used when reuse is detected).
pub async fn revoke_family(pool: &SqlitePool, family_id: &str) -> Result<()> {
    retry_busy(|| async {
        sqlx::query("DELETE FROM oauth_refresh_tokens WHERE family_id = ?")
            .bind(family_id)
            .execute(pool)
            .await?;
        Ok(())
    })
    .await
}

/// One OAuth client a user has connected (an authorized MCP client).
#[derive(Debug, Clone)]
pub struct Connection {
    pub client_id: String,
    /// The name the client declared at registration (DCR metadata); often a
    /// generic default shared across installs.
    pub client_name: Option<String>,
    /// The redirect URIs registered for this client — useful for telling
    /// otherwise-identical clients apart (Desktop vs Code vs claude.ai vs iOS).
    pub redirect_uris: Vec<String>,
    /// User-set custom name (empty if none).
    pub custom_name: String,
    /// User-set freeform note (empty if none).
    pub note: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// IP / User-Agent of the most recent (non-expired) refresh — the client's
    /// last-seen origin.
    pub last_ip: Option<String>,
    pub last_user_agent: Option<String>,
}

/// List the OAuth clients a user has live refresh tokens for — i.e. the MCP
/// clients currently connected to their account.
pub async fn list_user_connections(pool: &SqlitePool, user_id: &str) -> Result<Vec<Connection>> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT client_id, MIN(created_at), MAX(created_at) FROM oauth_refresh_tokens \
         WHERE user_id = ? AND expires_at > ? GROUP BY client_id ORDER BY MAX(created_at) DESC",
    )
    .bind(user_id)
    .bind(now_unix())
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for (client_id, first_seen, last_seen) in rows {
        // The human-friendly name + redirect URIs come from the client's DCR record.
        let client = get_client(pool, &client_id).await?;
        let client_name = client.as_ref().and_then(|c| {
            c.metadata
                .get("client_name")
                .and_then(|v| v.as_str().map(String::from))
        });
        let redirect_uris = client.map(|c| c.redirect_uris).unwrap_or_default();
        let (custom_name, note) = get_client_label(pool, user_id, &client_id).await?;
        // The IP/UA of the newest live refresh token = the connection's last-seen origin.
        let (last_ip, last_user_agent): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT last_ip, last_user_agent FROM oauth_refresh_tokens \
             WHERE user_id = ? AND client_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_id)
        .bind(&client_id)
        .bind(now_unix())
        .fetch_optional(pool)
        .await?
        .unwrap_or((None, None));
        out.push(Connection {
            client_id,
            client_name,
            redirect_uris,
            custom_name,
            note,
            first_seen,
            last_seen,
            last_ip,
            last_user_agent,
        });
    }
    Ok(out)
}

/// Fetch a user's custom name + note for one client. Returns empty strings when
/// no label has been set.
pub async fn get_client_label(
    pool: &SqlitePool,
    user_id: &str,
    client_id: &str,
) -> Result<(String, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT name, note FROM oauth_client_labels WHERE user_id = ? AND client_id = ?",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.unwrap_or_default())
}

/// Set (upsert) a user's custom name + note for one client.
pub async fn set_client_label(
    pool: &SqlitePool,
    user_id: &str,
    client_id: &str,
    name: &str,
    note: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oauth_client_labels (user_id, client_id, name, note, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id, client_id) DO UPDATE SET name = ?, note = ?, updated_at = ?",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(name)
    .bind(note)
    .bind(now_unix())
    .bind(name)
    .bind(note)
    .bind(now_unix())
    .execute(pool)
    .await
    .context("upserting oauth client label")?;
    Ok(())
}

/// Whether the user currently has a live connection (non-expired refresh token)
/// to a given client — guards label edits against arbitrary client IDs.
pub async fn user_has_connection(
    pool: &SqlitePool,
    user_id: &str,
    client_id: &str,
) -> Result<bool> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM oauth_refresh_tokens WHERE user_id = ? AND client_id = ? AND expires_at > ? LIMIT 1",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(now_unix())
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Revoke a single connection: delete the user's refresh tokens for one client.
/// Outstanding access tokens (short-lived JWTs) expire on their own within the
/// access-token TTL. Returns the number of tokens removed.
pub async fn revoke_user_client(pool: &SqlitePool, user_id: &str, client_id: &str) -> Result<u64> {
    let res = sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_id = ? AND client_id = ?")
        .bind(user_id)
        .bind(client_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Revoke every refresh token for a user (used when disabling the account).
pub async fn revoke_all_user_tokens(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM oauth_refresh_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file-backed pool via [`crate::db::connect`] so the test runs under
    /// the production journal mode (WAL) and busy_timeout — an in-memory
    /// database cannot reproduce write-lock contention.
    async fn pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("mcphub-oauth-{name}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let pool = crate::db::connect(path.to_str().unwrap()).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES ('u1','alice','Alice',0,0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        create_client(&pool, "c1", None, &[], &serde_json::json!({}))
            .await
            .unwrap();
        (pool, path)
    }

    fn cleanup(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }

    /// claude.ai refreshes every connector group's token in a single burst;
    /// each rotation is a consume (SELECT+UPDATE transaction) racing the
    /// others' inserts. Before the BEGIN IMMEDIATE + retry fix this failed
    /// intermittently with "database is locked" (SQLITE_BUSY_SNAPSHOT).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_refresh_burst_survives_lock_contention() {
        let (pool, path) = pool("burst").await;
        let info = crate::auth::RequestInfo::default();
        for i in 0..12 {
            insert_refresh(
                &pool,
                &format!("h{i}"),
                "c1",
                "u1",
                "",
                None,
                &format!("f{i}"),
                3600,
                &info,
            )
            .await
            .unwrap();
        }

        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..12 {
            let pool = pool.clone();
            tasks.spawn(async move {
                let info = crate::auth::RequestInfo::default();
                let out = consume_refresh(&pool, &format!("h{i}")).await?;
                anyhow::ensure!(
                    matches!(out, RefreshOutcome::Valid(_)),
                    "token h{i} not valid on first use"
                );
                insert_refresh(
                    &pool,
                    &format!("h{i}-next"),
                    "c1",
                    "u1",
                    "",
                    None,
                    &format!("f{i}"),
                    3600,
                    &info,
                )
                .await
            });
        }
        while let Some(res) = tasks.join_next().await {
            res.expect("task panicked").expect("refresh cycle errored");
        }

        // Every rotation landed: an old token replays as consumed.
        let replay = consume_refresh(&pool, "h0").await.unwrap();
        assert!(matches!(replay, RefreshOutcome::Replayed { .. }));

        pool.close().await;
        cleanup(&path);
    }

    fn code_store() -> AuthCodeStore {
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
    }

    fn seed_code(store: &AuthCodeStore, code: &str, ttl_secs: i64) {
        insert_code(
            store,
            code,
            "c1",
            "u1",
            "https://x/cb",
            "chal",
            "",
            None,
            ttl_secs,
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_take_code_hands_out_each_code_once() {
        let store = code_store();
        for i in 0..8 {
            seed_code(&store, &format!("code{i}"), 300);
        }

        // All codes exchanged concurrently, each twice — exactly one winner per code.
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..8 {
            for _ in 0..2 {
                let store = store.clone();
                tasks.spawn(async move { take_code(&store, &format!("code{i}")) });
            }
        }
        let mut won = 0;
        while let Some(res) = tasks.join_next().await {
            if res
                .expect("task panicked")
                .expect("take_code errored")
                .is_some()
            {
                won += 1;
            }
        }
        assert_eq!(won, 8, "each code must be exchangeable exactly once");
    }

    #[test]
    fn expired_code_is_not_exchangeable_and_is_consumed() {
        let store = code_store();
        seed_code(&store, "old", -1);
        assert!(take_code(&store, "old").unwrap().is_none());
        // The remove-regardless-of-expiry rule: the entry is gone either way.
        assert!(store.lock().unwrap().is_empty());
    }

    #[test]
    fn insert_evicts_expired_and_enforces_the_cap() {
        let store = code_store();
        // Fill to the cap with live codes; the next insert must be refused.
        for i in 0..512 {
            seed_code(&store, &format!("live{i}"), 300);
        }
        assert!(
            insert_code(
                &store,
                "overflow",
                "c1",
                "u1",
                "https://x/cb",
                "chal",
                "",
                None,
                300
            )
            .is_err(),
            "insert past the cap must be refused"
        );
        // But expired entries are evicted on insert, making room again.
        store.lock().unwrap().retain(|k, _| k == "live0");
        seed_code(&store, "expired", -1);
        seed_code(&store, "fresh", 300);
        assert!(take_code(&store, "fresh").unwrap().is_some());
        assert!(take_code(&store, "expired").unwrap().is_none());
    }
}
