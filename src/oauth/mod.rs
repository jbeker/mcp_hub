//! OAuth 2.1 Authorization Server.
//!
//! The hub authenticates humans with passkeys (see [`crate::auth`]) and issues
//! OAuth tokens to MCP clients. This module implements the small, well-specified
//! AS surface: metadata discovery, dynamic client registration, the authorize +
//! consent flow, and the token endpoint. Access tokens are ES256 JWTs (see
//! [`keys`]); refresh tokens are random and stored hashed.

pub mod authorize;
pub mod keys;
pub mod metadata;
pub mod register;
pub mod store;
pub mod token;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use sha2::{Digest, Sha256};

/// URL-safe base64 without padding (the encoding WebAuthn/OAuth use).
pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 digest.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Stable hash used to store bearer/refresh tokens without keeping the secret.
pub fn token_hash(token: &str) -> String {
    b64url(&sha256(token.as_bytes()))
}

/// Generate a fresh high-entropy opaque token.
pub fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// Verify a PKCE `code_verifier` against the stored S256 `code_challenge`.
pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    ct_eq(
        b64url(&sha256(verifier.as_bytes())).as_bytes(),
        challenge.as_bytes(),
    )
}

/// Constant-time byte comparison (lengths are not secret here).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A standards-shaped OAuth error (`{ "error", "error_description" }`).
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    pub fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error,
            description: description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "oauth internal error");
        crate::metrics::note_oauth_internal_error();
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.error,
            "error_description": self.description,
        }));
        (self.status, body).into_response()
    }
}
