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

/// Reject requests without a valid access token, attaching the resolved user to
/// the request extensions on success.
async fn require_bearer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")));

    let Some(token) = token else {
        return unauthorized(&state);
    };
    match state
        .signer
        .verify_access_token(token, &state.config.mcp_url())
    {
        Ok(claims) => {
            req.extensions_mut().insert(AuthedUser {
                user_id: claims.sub,
                admin: claims.admin,
            });
            next.run(req).await
        }
        Err(_) => unauthorized(&state),
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
