//! OAuth/MCP discovery metadata documents.

use axum::extract::State;
use axum::Json;

use crate::AppState;

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub async fn authorization_server(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = &state.config.base_url;
    Json(serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "scopes_supported": ["mcp"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
    }))
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728).
///
/// MCP clients fetch this from the resource server to discover which
/// authorization server protects the `/mcp` endpoint.
pub async fn protected_resource(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = &state.config.base_url;
    Json(serde_json::json!({
        "resource": state.config.mcp_url(),
        "authorization_servers": [base],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }))
}

/// `GET /.well-known/jwks.json` — the access-token verification keys.
pub async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.signer.jwks())
}
