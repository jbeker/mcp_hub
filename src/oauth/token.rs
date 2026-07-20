//! The token endpoint: authorization_code (with PKCE) and refresh_token grants.

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth::RequestInfo;
use crate::oauth::{store, token_hash, verify_pkce_s256, OAuthError};
use crate::users;
use crate::AppState;

// Short access-token lifetime bounds the window in which a revoked admin or a
// stolen bearer token remains usable; rotation keeps long-lived sessions alive.
const ACCESS_TTL_SECS: i64 = 60 * 15;
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
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<impl IntoResponse, OAuthError> {
    let info = RequestInfo::from_headers(&headers);
    let body = match form.grant_type.as_str() {
        "authorization_code" => authorization_code(&state, &form, &info).await?,
        "refresh_token" => refresh_token(&state, &form, &info).await?,
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
            .map(|s| crate::oauth::ct_eq(token_hash(s).as_bytes(), expected.as_bytes()))
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
    info: &RequestInfo,
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

    let row = store::take_code(&state.auth_codes, code)?
        .ok_or_else(|| OAuthError::invalid_grant("authorization code is invalid or expired"))?;

    if row.client_id != client_id {
        return Err(OAuthError::invalid_grant("code was issued to another client"));
    }
    // redirect_uri was required at authorization, so it must be supplied here
    // and match exactly (RFC 6749 §4.1.3).
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
    if redirect_uri != row.redirect_uri {
        return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
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

    // A new authorization starts a fresh refresh-token family.
    let family_id = crate::util::new_id();
    issue_tokens(state, &user, client_id, &audience, &row.scope, row.resource.as_deref(), &family_id, info).await
}

async fn refresh_token(
    state: &AppState,
    form: &TokenForm,
    info: &RequestInfo,
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
    let row = match store::consume_refresh(&state.db, &hash).await? {
        store::RefreshOutcome::Valid(row) => row,
        store::RefreshOutcome::Replayed { family_id } => {
            // A rotated-out token was replayed: revoke the entire family so a
            // thief who raced the legitimate client cannot keep refreshing.
            store::revoke_family(&state.db, &family_id).await?;
            crate::audit::event("oauth.refresh_reuse")
                .client_id(Some(client_id))
                .request(info)
                .object(client_id)
                .denied("reuse");
            return Err(OAuthError::invalid_grant(
                "refresh token reuse detected; the session has been revoked",
            ));
        }
        store::RefreshOutcome::Missing => {
            return Err(OAuthError::invalid_grant("refresh token is invalid or expired"))
        }
    };
    if row.client_id != client_id {
        return Err(OAuthError::invalid_grant("refresh token was issued to another client"));
    }

    let user = users::find_by_id(&state.db, &row.user_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("user no longer exists"))?;

    let audience = row
        .resource
        .clone()
        .unwrap_or_else(|| state.config.mcp_url());
    // Stay in the same family so the rotation chain is tracked.
    issue_tokens(state, &user, client_id, &audience, &row.scope, row.resource.as_deref(), &row.family_id, info).await
}

/// Mint an access token + a fresh (rotated) refresh token within `family_id`.
#[allow(clippy::too_many_arguments)]
async fn issue_tokens(
    state: &AppState,
    user: &users::User,
    client_id: &str,
    audience: &str,
    scope: &str,
    resource: Option<&str>,
    family_id: &str,
    info: &RequestInfo,
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
        family_id,
        REFRESH_TTL_SECS,
        info,
    )
    .await?;

    crate::audit::event("oauth.token")
        .actor(&user.handle)
        .actor_id(&user.id)
        .client_id(Some(client_id))
        .request(info)
        .object(client_id)
        .ok();

    Ok(serde_json::json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ttl,
        "refresh_token": refresh,
        "scope": scope,
    }))
}
