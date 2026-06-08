//! Authentication: WebAuthn passkeys and browser sessions.

use axum::http::HeaderMap;

pub mod session;
pub mod webauthn;

pub use session::{AuthUser, MaybeUser};

/// Identifying details about the request that performed an action, recorded so
/// the Account page can show where a credential / session / connection was last
/// used.
#[derive(Clone, Debug, Default)]
pub struct RequestInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestInfo {
    /// Extract the client IP and User-Agent from request headers.
    ///
    /// The hub always sits behind a TLS-terminating reverse proxy, so the real
    /// client address comes from `X-Forwarded-For` (the first, client-most hop),
    /// falling back to `X-Real-IP`. The socket peer would only ever be the proxy.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        RequestInfo {
            ip: client_ip(headers),
            user_agent: header_str(headers, "user-agent"),
        }
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    header_str(headers, "x-real-ip")
}
