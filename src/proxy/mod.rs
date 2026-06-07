//! The MCP proxy: a Streamable HTTP endpoint at `/mcp` that authenticates with
//! OAuth bearer tokens and aggregates each user's configured backends.

pub mod backend;
pub mod management;
pub mod server;

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{StreamableHttpServerConfig, StreamableHttpService};

use crate::proxy::server::HubProxy;
use crate::AppState;

/// The authenticated user, derived from a verified access token and forwarded
/// into the MCP handler via request extensions.
#[derive(Clone, Debug)]
pub struct AuthedUser {
    pub user_id: String,
    pub admin: bool,
}

/// Build the router serving the `/mcp` Streamable HTTP endpoint, gated by an
/// OAuth bearer-token check.
pub fn mcp_router(state: AppState) -> Router {
    let session_manager = Arc::new(LocalSessionManager::default());
    let config = StreamableHttpServerConfig::default();

    let factory_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(HubProxy::new(factory_state.clone())),
        session_manager,
        config,
    );

    Router::new()
        .fallback_service(service)
        .layer(from_fn_with_state(state, require_bearer))
}

/// Reject requests without a valid credential, attaching the resolved user to
/// the request extensions on success. Two credential types are accepted on the
/// `Authorization: Bearer` header: a personal access token (opaque, prefixed —
/// for clients that can't do OAuth) or an OAuth access token (ES256 JWT).
async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")));

    let Some(token) = token else {
        return unauthorized(&state);
    };

    // A personal access token is opaque; the prefix lets us route it without a
    // JWT decode. `admin` comes from the live user row rather than a baked claim.
    if crate::tokens::looks_like_pat(token) {
        let hash = crate::oauth::token_hash(token);
        return match crate::tokens::resolve_valid(&state.db, &hash).await {
            Ok(Some((user_id, token_id))) => {
                // Best-effort usage bookkeeping; never fail auth on this write.
                let _ = crate::tokens::touch(&state.db, &token_id).await;
                authorize(&state, req, next, &user_id, None).await
            }
            _ => unauthorized(&state),
        };
    }

    // Otherwise treat it as an OAuth access token (stateless ES256 JWT).
    let claims = match state
        .signer
        .verify_access_token(token, &state.config.mcp_url())
    {
        Ok(c) => c,
        Err(_) => return unauthorized(&state),
    };
    authorize(&state, req, next, &claims.sub, Some(claims.admin)).await
}

/// Confirm the account still exists and is enabled, then forward the request
/// with the resolved [`AuthedUser`] attached. Re-checking on every request makes
/// account deletion/disabling take effect within seconds (rather than waiting
/// out a JWT's lifetime or a PAT's expiry). `admin_claim` carries an OAuth
/// token's baked admin flag; for PATs it is `None` and the live row is used.
async fn authorize(
    state: &AppState,
    mut req: Request,
    next: Next,
    user_id: &str,
    admin_claim: Option<bool>,
) -> Response {
    match crate::users::find_by_id(&state.db, user_id).await {
        Ok(Some(user)) if !user.disabled => {
            req.extensions_mut().insert(AuthedUser {
                user_id: user.id,
                admin: admin_claim.unwrap_or(user.is_admin),
            });
            next.run(req).await
        }
        _ => unauthorized(state),
    }
}

/// A 401 that points clients at the protected-resource metadata (RFC 9728), so
/// MCP clients can discover the authorization server and start the OAuth flow.
fn unauthorized(state: &AppState) -> Response {
    let challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
        state.config.base_url
    );
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        "authentication required",
    )
        .into_response()
}
