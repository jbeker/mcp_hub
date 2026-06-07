//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh random UUIDv4 string, used for primary keys.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
