//! In-memory registry of each backend instance's last connection outcome.
//!
//! Runtime status is ephemeral observability state: it is rewritten on every
//! spawn attempt and is stale the moment the hub restarts (keep-warm rebuilds
//! the real picture within a minute). Keeping it here instead of SQLite takes
//! the pool's status churn off the database's single write lock — status
//! writes were the main contender in the OAuth "database is locked" incident.
//!
//! The registry lives on [`crate::AppState`] rather than inside the backend
//! pool because readers (`/stats`, `/metrics`, `hub__list_my_servers`) span
//! all users, while the pool only holds entries for warmed, non-reaped users.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::util::now_unix;

/// A backend's last connection outcome. Closed vocabulary; [`as_str`] values
/// match the strings previously persisted in `user_server_instances`, so all
/// JSON and HTML output is unchanged.
///
/// [`as_str`]: RuntimeState::as_str
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuntimeState {
    Ok,
    Error,
    Skipped,
    Unbuilt,
    Unknown,
}

impl RuntimeState {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeState::Ok => "ok",
            RuntimeState::Error => "error",
            RuntimeState::Skipped => "skipped",
            RuntimeState::Unbuilt => "unbuilt",
            RuntimeState::Unknown => "unknown",
        }
    }
}

/// The outcome of the most recent attempt to connect one instance.
#[derive(Clone, Debug)]
pub struct RuntimeStatus {
    pub state: RuntimeState,
    pub detail: Option<String>,
    /// When the outcome was recorded (unix seconds).
    pub checked_at: i64,
}

/// Registry keyed by instance id. All operations are short synchronous
/// critical sections; a poisoned lock degrades to "unknown" rather than
/// panicking — status is observability, never worth failing a request over.
#[derive(Default)]
pub struct StatusRegistry(Mutex<HashMap<String, RuntimeStatus>>);

impl StatusRegistry {
    /// Record the outcome of the most recent connection attempt.
    pub fn set(&self, instance_id: &str, state: RuntimeState, detail: Option<&str>) {
        let Ok(mut map) = self.0.lock() else { return };
        map.insert(
            instance_id.to_string(),
            RuntimeStatus {
                state,
                detail: detail.map(str::to_string),
                checked_at: now_unix(),
            },
        );
    }

    pub fn get(&self, instance_id: &str) -> Option<RuntimeStatus> {
        self.0.lock().ok()?.get(instance_id).cloned()
    }

    /// One-lock copy of the whole registry, for joins across many instances
    /// (`stats::gather`).
    pub fn snapshot(&self) -> HashMap<String, RuntimeStatus> {
        self.0.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Forget an instance (deleted or disabled — its status is meaningless).
    pub fn remove(&self, instance_id: &str) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(instance_id);
        }
    }

    /// Drop entries for instances that no longer exist. Closes the bounded
    /// leak from a spawn task's `set` racing a delete's `remove`; called from
    /// the keep-warm pass, which already has the live instance list in hand.
    pub fn retain(&self, live_ids: &HashSet<String>) {
        if let Ok(mut map) = self.0.lock() {
            map.retain(|id, _| live_ids.contains(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_remove_round_trip() {
        let reg = StatusRegistry::default();
        assert!(reg.get("i1").is_none());
        reg.set("i1", RuntimeState::Error, Some("boom"));
        let s = reg.get("i1").unwrap();
        assert_eq!(s.state, RuntimeState::Error);
        assert_eq!(s.detail.as_deref(), Some("boom"));
        assert!(s.checked_at > 0);
        reg.set("i1", RuntimeState::Ok, None);
        assert_eq!(reg.get("i1").unwrap().state, RuntimeState::Ok);
        reg.remove("i1");
        assert!(reg.get("i1").is_none());
    }

    #[test]
    fn retain_prunes_dead_instances() {
        let reg = StatusRegistry::default();
        reg.set("live", RuntimeState::Ok, None);
        reg.set("dead", RuntimeState::Error, None);
        reg.retain(&HashSet::from(["live".to_string()]));
        assert!(reg.get("live").is_some());
        assert!(reg.get("dead").is_none());
    }
}
