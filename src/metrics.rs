//! In-memory usage metrics with Prometheus text exposition.
//!
//! [`Metrics`] counts proxied tool calls per (user, server, tool) — call
//! totals, errors by kind, and cumulative duration — and `GET /metrics`
//! renders them in the Prometheus text format alongside scrape-time health
//! gauges from [`crate::stats`]. Counters live in memory only and reset on
//! restart; scrapers handle that with rate/delta preprocessing.
//!
//! The endpoint is gated by a hub-managed API key, sealed in the `settings`
//! table and shown (and regenerable) on the admin `/stats` page.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::AppState;

/// Why a tool call failed. A fixed taxonomy — the `error_kind` label never
/// grows with user input.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The hub's own call timeout (`HUB_BACKEND_CALL_TIMEOUT_SECS`) fired.
    Timeout,
    /// The backend transport/RPC call failed.
    Error,
    /// The backend answered, but the result carried `is_error: true`.
    ToolError,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Timeout => "timeout",
            ErrorKind::Error => "error",
            ErrorKind::ToolError => "tool_error",
        }
    }

    const ALL: [ErrorKind; 3] = [ErrorKind::Timeout, ErrorKind::Error, ErrorKind::ToolError];
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct CallKey {
    user: String,
    server: String,
    tool: String,
}

#[derive(Default)]
struct CallStats {
    calls: u64,
    /// Indexed by `ErrorKind as usize`.
    errors: [u64; 3],
    /// Integer accumulation; rendered as seconds.
    duration_micros: u64,
}

/// Bound on distinct label sets. Overflow folds into an `_other` sentinel so a
/// client inventing tool names can't grow memory unboundedly.
const MAX_SERIES: usize = 10_000;

/// The usage-counter registry. One per hub, on [`AppState`].
#[derive(Default)]
pub struct Metrics {
    calls: Mutex<HashMap<CallKey, CallStats>>,
}

impl Metrics {
    /// Record one tool call. Infallible: a poisoned lock skips the sample
    /// rather than panic — instrumentation must never fail the request path.
    pub fn record_call(
        &self,
        user: &str,
        server: &str,
        tool: &str,
        duration: Duration,
        error: Option<ErrorKind>,
    ) {
        let Ok(mut map) = self.calls.lock() else { return };
        let key = CallKey {
            user: user.to_string(),
            server: server.to_string(),
            tool: tool.to_string(),
        };
        let stats = if map.contains_key(&key) || map.len() < MAX_SERIES {
            map.entry(key).or_default()
        } else {
            map.entry(CallKey {
                user: "_other".into(),
                server: "_other".into(),
                tool: "_other".into(),
            })
            .or_default()
        };
        stats.calls += 1;
        stats.duration_micros += duration.as_micros() as u64;
        if let Some(kind) = error {
            stats.errors[kind as usize] += 1;
        }
    }

    /// Append the counter families in Prometheus text exposition format.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write;
        let Ok(map) = self.calls.lock() else { return };
        // Sorted for stable output (nice for humans and tests alike).
        let mut entries: Vec<(&CallKey, &CallStats)> = map.iter().collect();
        entries.sort_by(|(a, _), (b, _)| {
            (&a.user, &a.server, &a.tool).cmp(&(&b.user, &b.server, &b.tool))
        });

        out.push_str("# TYPE mcp_hub_tool_calls_total counter\n");
        for (k, s) in &entries {
            let _ = writeln!(out, "mcp_hub_tool_calls_total{} {}", labels(k), s.calls);
        }
        out.push_str("# TYPE mcp_hub_tool_call_errors_total counter\n");
        for (k, s) in &entries {
            for kind in ErrorKind::ALL {
                let n = s.errors[kind as usize];
                if n > 0 {
                    let _ = writeln!(
                        out,
                        "mcp_hub_tool_call_errors_total{{user=\"{}\",server=\"{}\",tool=\"{}\",error_kind=\"{}\"}} {}",
                        escape_label(&k.user),
                        escape_label(&k.server),
                        escape_label(&k.tool),
                        kind.as_str(),
                        n
                    );
                }
            }
        }
        out.push_str("# TYPE mcp_hub_tool_call_duration_seconds_total counter\n");
        for (k, s) in &entries {
            let _ = writeln!(
                out,
                "mcp_hub_tool_call_duration_seconds_total{} {:.6}",
                labels(k),
                s.duration_micros as f64 / 1e6
            );
        }
    }
}

fn labels(k: &CallKey) -> String {
    format!(
        "{{user=\"{}\",server=\"{}\",tool=\"{}\"}}",
        escape_label(&k.user),
        escape_label(&k.server),
        escape_label(&k.tool)
    )
}

/// Escape a label value per the exposition format: backslash, double quote and
/// newline must be escaped.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// API key management
// ---------------------------------------------------------------------------

const KEY_SETTING: &str = "metrics_api_key";
const KEY_PREFIX: &str = "mcphub_metrics_";

/// Load the metrics API key from the `settings` table, generating and storing
/// one on first startup. Called once when [`AppState`] is built.
pub async fn load_or_create_key(
    db: &sqlx::SqlitePool,
    secrets: &crate::crypto::SecretBox,
) -> anyhow::Result<String> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT nonce, ciphertext FROM settings WHERE key = ?")
            .bind(KEY_SETTING)
            .fetch_optional(db)
            .await?;
    if let Some((nonce, ciphertext)) = row {
        let plain = secrets.open(&crate::crypto::Sealed { nonce, ciphertext })?;
        return Ok(String::from_utf8(plain)?);
    }
    let key = format!("{KEY_PREFIX}{}", crate::oauth::random_token());
    store_key(db, secrets, &key).await?;
    tracing::info!("generated metrics API key (see the admin /stats page)");
    Ok(key)
}

/// Generate a fresh metrics API key, persist it and swap the in-memory copy.
/// The old key stops working immediately. Returns the new key.
pub async fn regenerate_key(state: &AppState) -> anyhow::Result<String> {
    let key = format!("{KEY_PREFIX}{}", crate::oauth::random_token());
    store_key(&state.db, &state.secrets, &key).await?;
    if let Ok(mut guard) = state.metrics_key.write() {
        *guard = key.clone();
    }
    Ok(key)
}

async fn store_key(
    db: &sqlx::SqlitePool,
    secrets: &crate::crypto::SecretBox,
    key: &str,
) -> anyhow::Result<()> {
    let sealed = secrets.seal(key.as_bytes())?;
    sqlx::query(
        "INSERT INTO settings (key, nonce, ciphertext, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET nonce = excluded.nonce,
             ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
    )
    .bind(KEY_SETTING)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .bind(crate::util::now_unix())
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The /metrics endpoint
// ---------------------------------------------------------------------------

/// `GET /metrics` — Prometheus text exposition, gated by the metrics API key
/// (`Authorization: Bearer <key>`). Designed for a Zabbix HTTP-agent master
/// item; usage counters come from [`Metrics`] and health gauges are read live
/// from [`crate::stats::gather`].
pub async fn endpoint(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    let authorized = state
        .metrics_key
        .read()
        .map(|k| !k.is_empty() && crate::oauth::ct_eq(presented.as_bytes(), k.as_bytes()))
        .unwrap_or(false);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
    }

    let mut out = String::with_capacity(4096);
    state.metrics.render(&mut out);

    use std::fmt::Write;
    let s = crate::stats::gather(&state).await;
    let _ = write!(
        out,
        "# TYPE mcp_hub_backend_slots_used gauge\n\
         mcp_hub_backend_slots_used {}\n\
         # TYPE mcp_hub_backend_slots_total gauge\n\
         mcp_hub_backend_slots_total {}\n\
         # TYPE mcp_hub_active_sessions gauge\n\
         mcp_hub_active_sessions {}\n\
         # TYPE mcp_hub_pool_users gauge\n\
         mcp_hub_pool_users {}\n\
         # TYPE mcp_hub_pool_backends gauge\n\
         mcp_hub_pool_backends {}\n",
        s.slots.used, s.slots.total, s.active_sessions, s.pool.users, s.pool.backends
    );
    out.push_str("# TYPE mcp_hub_instance_up gauge\n");
    for i in &s.instances {
        let _ = writeln!(
            out,
            "mcp_hub_instance_up{{owner=\"{}\",server=\"{}\"}} {}",
            escape_label(&i.owner),
            escape_label(&i.namespace),
            u8::from(i.runtime_status == "ok")
        );
    }
    out.push_str("# TYPE mcp_hub_instance_enabled gauge\n");
    for i in &s.instances {
        let _ = writeln!(
            out,
            "mcp_hub_instance_enabled{{owner=\"{}\",server=\"{}\"}} {}",
            escape_label(&i.owner),
            escape_label(&i.namespace),
            u8::from(i.enabled)
        );
    }

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn record_and_render_round_trip() {
        let m = Metrics::default();
        m.record_call("alice", "github", "get_me", ms(250), None);
        m.record_call("alice", "github", "get_me", ms(750), None);
        m.record_call("bob", "zabbix", "host_get", ms(100), Some(ErrorKind::Timeout));

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(
            r#"mcp_hub_tool_calls_total{user="alice",server="github",tool="get_me"} 2"#
        ));
        assert!(out.contains(
            r#"mcp_hub_tool_calls_total{user="bob",server="zabbix",tool="host_get"} 1"#
        ));
        assert!(out.contains(
            r#"mcp_hub_tool_call_duration_seconds_total{user="alice",server="github",tool="get_me"} 1.000000"#
        ));
        assert!(out.contains("# TYPE mcp_hub_tool_calls_total counter"));
    }

    #[test]
    fn error_kinds_are_bucketed_and_zero_kinds_omitted() {
        let m = Metrics::default();
        m.record_call("a", "s", "t", ms(1), Some(ErrorKind::Timeout));
        m.record_call("a", "s", "t", ms(1), Some(ErrorKind::ToolError));
        m.record_call("a", "s", "t", ms(1), Some(ErrorKind::ToolError));
        m.record_call("a", "s", "t", ms(1), None);

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(
            r#"mcp_hub_tool_call_errors_total{user="a",server="s",tool="t",error_kind="timeout"} 1"#
        ));
        assert!(out.contains(
            r#"mcp_hub_tool_call_errors_total{user="a",server="s",tool="t",error_kind="tool_error"} 2"#
        ));
        // No transport errors recorded, so that series must not appear.
        assert!(!out.contains(r#"error_kind="error""#));
        assert!(out.contains(r#"mcp_hub_tool_calls_total{user="a",server="s",tool="t"} 4"#));
    }

    #[test]
    fn label_values_are_escaped() {
        let m = Metrics::default();
        m.record_call("a\"b", "s\\1", "t\nx", ms(1), None);
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(r#"user="a\"b",server="s\\1",tool="t\nx""#));
    }

    #[test]
    fn series_cap_folds_into_other() {
        let m = Metrics::default();
        for i in 0..MAX_SERIES {
            m.record_call("u", "s", &format!("tool{i}"), ms(1), None);
        }
        // Past the cap: new label sets fold into the sentinel...
        m.record_call("u", "s", "one-too-many", ms(1), Some(ErrorKind::Error));
        m.record_call("u", "s", "and-another", ms(1), None);
        // ...but existing series still increment normally.
        m.record_call("u", "s", "tool0", ms(1), None);

        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(
            r#"mcp_hub_tool_calls_total{user="_other",server="_other",tool="_other"} 2"#
        ));
        assert!(!out.contains("one-too-many"));
        assert!(out.contains(r#"mcp_hub_tool_calls_total{user="u",server="s",tool="tool0"} 2"#));
    }

    #[test]
    fn duration_accumulates_in_seconds() {
        let m = Metrics::default();
        m.record_call("u", "s", "t", Duration::from_micros(1500), None);
        m.record_call("u", "s", "t", Duration::from_micros(500), None);
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(
            r#"mcp_hub_tool_call_duration_seconds_total{user="u",server="s",tool="t"} 0.002000"#
        ));
    }
}
