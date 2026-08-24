//! The MCP proxy: Streamable HTTP endpoints under `/mcp` that authenticate
//! with OAuth bearer tokens. The base `/mcp` endpoint serves only the built-in
//! `hub__*` management tools; each named connector group a user defines is its
//! own endpoint at `/mcp/<slug>` aggregating that group's backends (see
//! [`crate::groups`]). Splitting the catalog across endpoints keeps every
//! connector under client-side tool caps (claude.ai truncates at 256 tools).

pub mod backend;
pub mod management;
pub mod pool;
pub mod server;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};

use crate::proxy::server::HubProxy;
use crate::AppState;

/// The authenticated user, derived from a verified access token and forwarded
/// into the MCP handler via request extensions.
#[derive(Clone, Debug)]
pub struct AuthedUser {
    pub user_id: String,
    pub admin: bool,
    /// The OAuth client this request authenticated as, or `None` for a personal
    /// access token (which is not tied to a registered client). Lets a client
    /// manage its own connection label and nothing else.
    pub client_id: Option<String>,
    /// The personal access token id this request authenticated with, or `None`
    /// for an OAuth token. Mutually exclusive with `client_id`.
    pub pat_id: Option<String>,
    /// Where the request came from, for audit logging.
    pub request: crate::auth::RequestInfo,
}

impl AuthedUser {
    /// The credential this request used, as `(type, id)` for backend access
    /// control: `("oauth", client_id)` or `("pat", token_id)`. `None` only if
    /// neither is set (which shouldn't happen for an authenticated request).
    pub fn credential(&self) -> Option<(&str, &str)> {
        if let Some(c) = self.client_id.as_deref() {
            Some((crate::access::OAUTH, c))
        } else {
            self.pat_id.as_deref().map(|p| (crate::access::PAT, p))
        }
    }
}

/// Which MCP endpoint a request arrived at, resolved from the URL path and (for
/// groups) the authenticated user. Forwarded via request extensions alongside
/// [`AuthedUser`]. Sessions are shared across paths by the session manager, so
/// this is resolved **per request** and must never be cached in session state.
#[derive(Clone, Debug)]
pub enum McpEndpoint {
    /// The base `/mcp` endpoint: management (`hub__*`) tools only.
    Management,
    /// A `/mcp/<slug>` endpoint serving one of the user's connector groups.
    Group { group_id: String, slug: String },
}

/// The endpoint a request's path names, before the group slug (if any) has
/// been resolved against the authenticated user.
enum EndpointCandidate {
    Management,
    GroupSlug(String),
}

/// Parse the (nest-stripped) request path into an endpoint candidate. `None`
/// means the path is not a valid MCP endpoint (deeper nesting, bad slug) and
/// should 404 before any auth work.
fn endpoint_candidate(path: &str) -> Option<EndpointCandidate> {
    match path.trim_start_matches('/') {
        "" => Some(EndpointCandidate::Management),
        slug if crate::groups::valid_slug(slug) => Some(EndpointCandidate::GroupSlug(slug.into())),
        _ => None,
    }
}

/// Build the router serving the `/mcp` Streamable HTTP endpoint, gated by an
/// OAuth bearer-token check.
pub fn mcp_router(state: AppState) -> Router {
    // Use the shared session manager held in AppState so the admin stats page
    // can observe the same live session count this router maintains.
    let session_manager = state.session_manager.clone();
    // rmcp defaults to a loopback-only Host allowlist (its DNS-rebinding guard).
    // The hub is reached at HUB_BASE_URL behind a reverse proxy, so replace the
    // default with the configured authorities. Empty → keep rmcp's loopback
    // default (dev/test, where clients hit 127.0.0.1 directly).
    let mut config = StreamableHttpServerConfig::default();
    if !state.config.allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(state.config.allowed_hosts.clone());
    }

    let factory_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(HubProxy::new(factory_state.clone())),
        session_manager,
        config,
    );

    Router::new()
        .fallback_service(service)
        // Inner: rewrite the service's session-expiry 401 to 404 (see
        // `session_expiry_to_404`). Outer: the bearer-auth check, whose own 401
        // short-circuits before reaching the mapper.
        .layer(from_fn(session_expiry_to_404))
        .layer(from_fn_with_state(state, require_bearer))
}

/// rmcp's `StreamableHttpService` returns **401** for an unknown/expired
/// Streamable-HTTP session. The MCP spec says that must be **404** so the client
/// transparently re-initializes a new session instead of treating it as an auth
/// failure (which is why a stale Claude session wouldn't self-heal after a hub
/// restart). Within that service every 401 is session-related — real
/// authentication is handled by the outer [`require_bearer`] layer, whose 401
/// short-circuits before `next` and so never reaches here — so remapping any 401
/// seen at this layer to 404 is correct.
async fn session_expiry_to_404(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        let (mut parts, body) = resp.into_parts();
        parts.status = StatusCode::NOT_FOUND;
        return Response::from_parts(parts, body);
    }
    resp
}

/// Reject requests without a valid credential, attaching the resolved user to
/// the request extensions on success. Two credential types are accepted on the
/// `Authorization: Bearer` header: a personal access token (opaque, prefixed —
/// for clients that can't do OAuth) or an OAuth access token (ES256 JWT).
async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let info = crate::auth::RequestInfo::from_headers(req.headers());
    // The nest at `/mcp` strips the prefix, so the path seen here is `/` for
    // the base endpoint and `/<slug>` for a group endpoint. Anything else is
    // not an MCP endpoint at all — 404 before any auth work.
    let Some(candidate) = endpoint_candidate(req.uri().path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        });

    let Some(token) = token else {
        return reject(&state, &info, "no_bearer", &candidate);
    };

    // A personal access token is opaque; the prefix lets us route it without a
    // JWT decode. `admin` comes from the live user row rather than a baked
    // claim. PATs carry no audience, so they are valid on every endpoint.
    if crate::tokens::looks_like_pat(token) {
        let hash = crate::oauth::token_hash(token);
        return match crate::tokens::resolve_valid(&state.db, &hash).await {
            Ok(Some((user_id, token_id))) => {
                // Best-effort usage bookkeeping; never fail auth on this write.
                let _ = crate::tokens::touch(&state.db, &token_id).await;
                authorize(
                    &state,
                    req,
                    next,
                    &user_id,
                    None,
                    None,
                    Some(token_id),
                    info,
                    candidate,
                )
                .await
            }
            _ => reject(&state, &info, "bad_token", &candidate),
        };
    }

    // Otherwise treat it as an OAuth access token (stateless ES256 JWT). The
    // audience is the endpoint's own resource URL, so a token minted for one
    // endpoint cannot be replayed against another.
    let expected_audience = match &candidate {
        EndpointCandidate::Management => state.config.mcp_url(),
        EndpointCandidate::GroupSlug(slug) => state.config.group_mcp_url(slug),
    };
    let claims = match state.signer.verify_access_token(token, &expected_audience) {
        Ok(c) => c,
        Err(_) => return reject(&state, &info, "bad_token", &candidate),
    };
    authorize(
        &state,
        req,
        next,
        &claims.sub,
        Some(claims.admin),
        Some(claims.client_id),
        None,
        info,
        candidate,
    )
    .await
}

/// Log an `auth.unauthorized` audit event and return the 401 challenge.
fn reject(
    state: &AppState,
    info: &crate::auth::RequestInfo,
    reason: &str,
    candidate: &EndpointCandidate,
) -> Response {
    crate::audit::event("auth.unauthorized")
        .request(info)
        .denied(reason);
    unauthorized(state, candidate)
}

/// Confirm the account still exists and is enabled, then forward the request
/// with the resolved [`AuthedUser`] attached. Re-checking on every request makes
/// account deletion/disabling take effect within seconds (rather than waiting
/// out a JWT's lifetime or a PAT's expiry). `admin_claim` carries an OAuth
/// token's baked admin flag; for PATs it is `None` and the live row is used.
#[allow(clippy::too_many_arguments)]
async fn authorize(
    state: &AppState,
    mut req: Request,
    next: Next,
    user_id: &str,
    admin_claim: Option<bool>,
    client_id: Option<String>,
    pat_id: Option<String>,
    info: crate::auth::RequestInfo,
    candidate: EndpointCandidate,
) -> Response {
    match crate::users::find_by_id(&state.db, user_id).await {
        Ok(Some(user)) if !user.disabled => {
            // A group slug resolves against this user's groups. A slug that
            // doesn't exist for them is a 404, not a 401 — the credential was
            // fine; the resource isn't there. Looked up per request so group
            // deletion cuts access immediately.
            let endpoint = match candidate {
                EndpointCandidate::Management => McpEndpoint::Management,
                EndpointCandidate::GroupSlug(slug) => {
                    match crate::groups::find_by_slug(&state.db, &user.id, &slug).await {
                        Ok(Some(group)) => McpEndpoint::Group {
                            group_id: group.id,
                            slug,
                        },
                        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                        Err(e) => {
                            tracing::error!(error = %format!("{e:#}"), "group lookup failed");
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    }
                }
            };
            req.extensions_mut().insert(endpoint);
            req.extensions_mut().insert(AuthedUser {
                user_id: user.id,
                admin: admin_claim.unwrap_or(user.is_admin),
                client_id,
                pat_id,
                request: info,
            });
            next.run(req).await
        }
        _ => reject(state, &info, "user_unavailable", &candidate),
    }
}

/// A 401 that points clients at the protected-resource metadata (RFC 9728), so
/// MCP clients can discover the authorization server and start the OAuth flow.
/// The metadata URL carries the endpoint path, which is how a client learns to
/// request that endpoint's `resource` during authorization — and hence how its
/// token ends up with the right audience.
fn unauthorized(state: &AppState, candidate: &EndpointCandidate) -> Response {
    let resource_suffix = match candidate {
        EndpointCandidate::Management => "/mcp".to_string(),
        EndpointCandidate::GroupSlug(slug) => format!("/mcp/{slug}"),
    };
    let challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource{}\"",
        state.config.base_url, resource_suffix
    );
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        "authentication required",
    )
        .into_response()
}
