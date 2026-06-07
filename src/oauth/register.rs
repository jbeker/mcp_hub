//! Dynamic Client Registration (RFC 7591).
//!
//! MCP clients (Claude Desktop/Code/iOS) register themselves automatically.
//! They are public clients using PKCE (`token_endpoint_auth_method: "none"`),
//! though we also support confidential clients with a generated secret.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::oauth::{random_token, store, token_hash, OAuthError};
use crate::util::now_unix;
use crate::AppState;

#[derive(Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// `POST /register`
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegistrationRequest>,
) -> Result<impl IntoResponse, OAuthError> {
    // Open DCR is unauthenticated; cap total clients so it cannot fill the DB.
    const MAX_CLIENTS: i64 = 10_000;
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(&state.db)
        .await
        .map_err(|e| OAuthError::from(anyhow::Error::from(e)))?;
    if count >= MAX_CLIENTS {
        return Err(OAuthError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "client registration is temporarily unavailable",
        ));
    }

    if req.redirect_uris.is_empty() {
        return Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        ));
    }
    for uri in &req.redirect_uris {
        if url::Url::parse(uri).is_err() {
            return Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                format!("invalid redirect_uri: {uri}"),
            ));
        }
    }

    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let grant_types = req
        .grant_types
        .clone()
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    let response_types = req
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".into()]);

    let client_id = format!("hub_{}", random_token());
    // Confidential clients get a secret; public clients (PKCE) do not.
    let client_secret = if auth_method == "none" {
        None
    } else {
        Some(random_token())
    };

    let metadata = serde_json::json!({
        "client_name": req.client_name,
        "scope": req.scope,
        "token_endpoint_auth_method": auth_method,
        "grant_types": grant_types,
        "response_types": response_types,
    });

    store::create_client(
        &state.db,
        &client_id,
        client_secret.as_deref().map(token_hash).as_deref(),
        &req.redirect_uris,
        &metadata,
    )
    .await?;

    tracing::info!(client_id = %client_id, auth_method = %auth_method, "registered oauth client");

    let mut body = serde_json::json!({
        "client_id": client_id,
        "client_id_issued_at": now_unix(),
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": auth_method,
        "grant_types": grant_types,
        "response_types": response_types,
        "client_name": req.client_name,
        "scope": req.scope,
    });
    if let Some(secret) = client_secret {
        body["client_secret"] = serde_json::Value::String(secret);
        body["client_secret_expires_at"] = serde_json::Value::from(0); // never expires
    }

    Ok((StatusCode::CREATED, Json(body)))
}
