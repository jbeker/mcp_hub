//! The token endpoint: authorization_code (with PKCE) and refresh_token grants.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::{Form, Json};
use serde::Deserialize;

use crate::oauth::{store, token_hash, verify_pkce_s256, OAuthError};
use crate::users;
use crate::AppState;

const ACCESS_TTL_SECS: i64 = 3600;
const REFRESH_TTL_SECS: i64 = 60 * 60 * 24 * 30;

#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// `POST /token`
pub async fn token(
    State(state): State<AppState>,
    Form(form): Form<TokenForm>,
) -> Result<impl IntoResponse, OAuthError> {
    let body = match form.grant_type.as_str() {
        "authorization_code" => authorization_code(&state, &form).await?,
        "refresh_token" => refresh_token(&state, &form).await?,
        other => {
            return Err(OAuthError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                format!("unsupported grant_type: {other}"),
            ))
        }
    };
    // Token responses must not be cached.
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(body)))
}

/// Authenticate the client. Public clients (PKCE) need only a known client_id;
/// confidential clients must present the registered secret.
async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<store::Client, OAuthError> {
    let client = store::get_client(&state.db, client_id)
        .await?
        .ok_or_else(|| {
            OAuthError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client",
            )
        })?;
    if let Some(expected) = &client.client_secret_hash {
        let ok = client_secret
            .map(|s| &token_hash(s) == expected)
            .unwrap_or(false);
        if !ok {
            return Err(OAuthError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid_client",
                "invalid client credentials",
            ));
        }
    }
    Ok(client)
}

async fn authorization_code(
    state: &AppState,
    form: &TokenForm,
) -> Result<serde_json::Value, OAuthError> {
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let client_id = form
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;
    let verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code_verifier is required (PKCE)"))?;

    authenticate_client(state, client_id, form.client_secret.as_deref()).await?;

    let row = store::take_code(&state.db, code)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("authorization code is invalid or expired"))?;

    if row.client_id != client_id {
        return Err(OAuthError::invalid_grant("code was issued to another client"));
    }
    if let Some(redirect_uri) = &form.redirect_uri {
        if redirect_uri != &row.redirect_uri {
            return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
        }
    }
    if !verify_pkce_s256(verifier, &row.code_challenge) {
        return Err(OAuthError::invalid_grant("PKCE verification failed"));
    }

    let user = users::find_by_id(&state.db, &row.user_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("user no longer exists"))?;

    let audience = row
        .resource
        .clone()
        .unwrap_or_else(|| state.config.mcp_url());

    issue_tokens(state, &user, client_id, &audience, &row.scope, row.resource.as_deref()).await
}

async fn refresh_token(
    state: &AppState,
    form: &TokenForm,
) -> Result<serde_json::Value, OAuthError> {
    let token = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let client_id = form
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;

    authenticate_client(state, client_id, form.client_secret.as_deref()).await?;

    let hash = token_hash(token);
    let row = store::get_refresh(&state.db, &hash)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("refresh token is invalid or expired"))?;
    if row.client_id != client_id {
        return Err(OAuthError::invalid_grant("refresh token was issued to another client"));
    }

    let user = users::find_by_id(&state.db, &row.user_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("user no longer exists"))?;

    // Rotate: invalidate the presented refresh token before issuing a new one.
    store::delete_refresh(&state.db, &hash).await?;

    let audience = row
        .resource
        .clone()
        .unwrap_or_else(|| state.config.mcp_url());
    issue_tokens(state, &user, client_id, &audience, &row.scope, row.resource.as_deref()).await
}

/// Mint an access token + a fresh (rotated) refresh token.
async fn issue_tokens(
    state: &AppState,
    user: &users::User,
    client_id: &str,
    audience: &str,
    scope: &str,
    resource: Option<&str>,
) -> Result<serde_json::Value, OAuthError> {
    let (access, ttl) = state
        .signer
        .issue_access_token(&user.id, client_id, audience, scope, user.is_admin, ACCESS_TTL_SECS)?;

    let refresh = crate::oauth::random_token();
    store::insert_refresh(
        &state.db,
        &token_hash(&refresh),
        client_id,
        &user.id,
        scope,
        resource,
        REFRESH_TTL_SECS,
    )
    .await?;

    Ok(serde_json::json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ttl,
        "refresh_token": refresh,
        "scope": scope,
    }))
}
