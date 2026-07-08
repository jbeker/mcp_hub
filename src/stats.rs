//! Admin runtime statistics. A single gatherer feeds both the `/stats` web page
//! and the `hub__runtime_stats` MCP tool, so the two views never drift.
//!
//! The slot usage and active-session count are **live** (read straight from the
//! shared semaphore and session manager); the per-instance status is a
//! best-effort **snapshot** of each backend's last-recorded connection outcome.

use std::collections::HashMap;

use serde::Serialize;

use crate::{instances, users, AppState};

/// A complete runtime-stats reading.
#[derive(Serialize)]
pub struct RuntimeStats {
    /// Live global backend-slot usage.
    pub slots: SlotUsage,
    /// Live count of active `/mcp` Streamable-HTTP sessions.
    pub active_sessions: usize,
    /// Live pooled-backend usage (backends are shared across a user's
    /// sessions, so `active_sessions` can exceed `pool.users`).
    pub pool: PoolUsage,
    /// Configured ceilings.
    pub limits: Limits,
    /// Aggregate counts over all instances (from the last-known status).
    pub totals: Totals,
    /// Per-instance status snapshot across all users.
    pub instances: Vec<InstanceStat>,
}

/// Used vs. total global backend slots (the capacity that "global backend
/// capacity reached" exhausts).
#[derive(Serialize)]
pub struct SlotUsage {
    pub used: usize,
    pub total: usize,
}

/// Users with live pooled backends, and the backend total across them.
#[derive(Serialize)]
pub struct PoolUsage {
    pub users: usize,
    pub backends: usize,
}

/// The configured limits, surfaced alongside their environment-variable names.
#[derive(Serialize)]
pub struct Limits {
    pub max_backends_per_user: usize,
    pub max_backends_global: usize,
    pub backend_idle_secs: u64,
    pub backend_call_timeout_secs: u64,
    pub backend_connect_timeout_secs: u64,
    pub backend_list_timeout_secs: u64,
    pub bind_budget_secs: u64,
    pub max_response_mb: u64,
}

/// Aggregate counts, mirroring the `runtime_status` vocabulary.
#[derive(Serialize, Default)]
pub struct Totals {
    pub users: usize,
    pub instances: usize,
    pub enabled_instances: usize,
    /// `runtime_status == "ok"` — a backend that started on its last bind.
    pub running: usize,
    pub error: usize,
    /// `runtime_status == "skipped"` — a capacity/cap ceiling was hit.
    pub skipped: usize,
    pub unbuilt: usize,
    pub unknown: usize,
}

/// One instance's last-known runtime status, labelled with its owner's handle.
#[derive(Serialize)]
pub struct InstanceStat {
    pub owner: String,
    pub namespace: String,
    pub display_name: String,
    pub enabled: bool,
    pub runtime_status: String,
    pub runtime_detail: Option<String>,
    pub runtime_checked_at: Option<i64>,
}

/// Read the current runtime statistics. Live counters are exact; the instance
/// list reflects each backend's last recorded connection outcome.
pub async fn gather(state: &AppState) -> RuntimeStats {
    let total = state.config.limits.max_backends_global;
    // available_permits() never exceeds total, but saturate defensively.
    let used = total.saturating_sub(state.backend_slots.available_permits());
    let active_sessions = state.session_manager.sessions.read().await.len();
    let (pool_users, pool_backends) = state.backend_pool.counts();

    let users = users::list(&state.db).await.unwrap_or_default();
    let handle_by_id: HashMap<String, String> = users
        .iter()
        .map(|u| (u.id.clone(), u.handle.clone()))
        .collect();

    let all = instances::list_all(&state.db).await.unwrap_or_default();
    let mut totals = Totals {
        users: users.len(),
        instances: all.len(),
        ..Default::default()
    };
    let mut rows = Vec::with_capacity(all.len());
    for i in &all {
        if i.enabled {
            totals.enabled_instances += 1;
        }
        match i.runtime_status.as_str() {
            "ok" => totals.running += 1,
            "error" => totals.error += 1,
            "skipped" => totals.skipped += 1,
            "unbuilt" => totals.unbuilt += 1,
            _ => totals.unknown += 1,
        }
        rows.push(InstanceStat {
            owner: handle_by_id
                .get(&i.user_id)
                .cloned()
                .unwrap_or_else(|| i.user_id.clone()),
            namespace: i.namespace.clone(),
            display_name: i.display_name.clone(),
            enabled: i.enabled,
            runtime_status: i.runtime_status.clone(),
            runtime_detail: i.runtime_detail.clone(),
            runtime_checked_at: i.runtime_checked_at,
        });
    }

    RuntimeStats {
        slots: SlotUsage { used, total },
        active_sessions,
        pool: PoolUsage {
            users: pool_users,
            backends: pool_backends,
        },
        limits: Limits {
            max_backends_per_user: state.config.limits.max_backends_per_user,
            max_backends_global: state.config.limits.max_backends_global,
            backend_idle_secs: state.config.limits.backend_idle_secs,
            backend_call_timeout_secs: state.config.limits.backend_call_timeout_secs,
            backend_connect_timeout_secs: state.config.limits.backend_connect_timeout_secs,
            backend_list_timeout_secs: state.config.limits.backend_list_timeout_secs,
            bind_budget_secs: state.config.limits.bind_budget_secs,
            max_response_mb: state.config.limits.max_response_mb,
        },
        totals,
        instances: rows,
    }
}
