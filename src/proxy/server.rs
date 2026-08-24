//! The aggregating MCP server handler. One instance per client session; it
//! lazily binds to the authenticated user and fans requests out to that user's
//! enabled backends, namespacing everything as `<server>__<tool>`. The
//! backends themselves are owned by the shared per-user pool
//! ([`crate::proxy::pool::BackendPool`]) — sessions only borrow snapshots, so
//! a reconnecting client reuses warm backends instead of cold-starting them.

use rmcp::model::{
    CallToolRequestParams, CallToolResult, GetPromptRequestParams, GetPromptResult, Icon,
    Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams,
    ReadResourceResult, ServerCapabilities, ServerInfo,
};
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// The hub's icon advertised in `serverInfo.icons`: a robot face from the
/// OpenMoji set (CC BY-SA 4.0), embedded as a base64 `data:` URI so it needs
/// no external hosting. See ATTRIBUTION.md.
static HUB_ICON_DATA_URI: LazyLock<String> = LazyLock::new(|| {
    let png = include_bytes!("../../assets/hub-icon.png");
    format!("data:image/png;base64,{}", BASE64.encode(png))
});

use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::sync::Mutex;

use crate::proxy::backend::{unwrap_uri, Backend};
use crate::proxy::{management, AuthedUser, McpEndpoint};
use crate::AppState;

/// One aggregating proxy session.
pub struct HubProxy {
    state: AppState,
    bound: Mutex<Option<Bound>>,
    /// Opaque id for this session, used to register/unregister its client
    /// notification peer in `AppState::client_peers`.
    session_key: uuid::Uuid,
}

impl Drop for HubProxy {
    fn drop(&mut self) {
        self.state.unregister_client_peer(self.session_key);
    }
}

/// The user-specific state, established on the first authenticated request.
/// Backends are NOT here — they live in the shared per-user pool.
struct Bound {
    user_id: String,
    /// Resolved once at bind time so per-call audit events can name the actor.
    handle: String,
    admin: bool,
}

impl HubProxy {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            bound: Mutex::new(None),
            session_key: uuid::Uuid::new_v4(),
        }
    }

    /// Pull the authenticated user out of the forwarded HTTP request parts.
    fn authed(ctx: &RequestContext<RoleServer>) -> Result<AuthedUser, McpError> {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<AuthedUser>().cloned())
            .ok_or_else(|| McpError::invalid_request("missing authentication", None))
    }

    /// Pull the resolved endpoint (base `/mcp` vs a group `/mcp/<slug>`) out of
    /// the forwarded HTTP request parts. Per request, never cached: the session
    /// manager is shared across endpoint paths, so a session id minted on one
    /// path could be replayed on another.
    fn endpoint(ctx: &RequestContext<RoleServer>) -> Result<McpEndpoint, McpError> {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<McpEndpoint>().cloned())
            .ok_or_else(|| McpError::invalid_request("missing endpoint context", None))
    }

    /// The instance ids the request's credential (OAuth client or PAT) is denied,
    /// for per-credential backend access control. Empty = full access (the default
    /// and the case for any request without a recognizable credential). Looked up
    /// per request so a user's toggle on the Account page takes effect immediately.
    async fn denied_instances(&self, ctx: &RequestContext<RoleServer>) -> HashSet<String> {
        let cred = Self::authed(ctx).ok().and_then(|a| {
            a.credential()
                .map(|(t, id)| (t.to_string(), id.to_string()))
        });
        match cred {
            Some((t, id)) => crate::access::denied_instances(&self.state.db, &t, &id)
                .await
                .unwrap_or_default(),
            None => HashSet::new(),
        }
    }

    /// Bind this session to the request's user (lazy, once). Deliberately does
    /// NOT touch the backend pool: the base `/mcp` endpoint serves only
    /// management tools and must never spawn backends.
    async fn bind(&self, ctx: &RequestContext<RoleServer>) -> Result<AuthedUser, McpError> {
        let authed = Self::authed(ctx)?;
        let mut guard = self.bound.lock().await;
        if guard.as_ref().is_none_or(|b| b.user_id != authed.user_id) {
            // Resolve the handle once so per-call audit events can name the actor.
            let handle = crate::users::find_by_id(&self.state.db, &authed.user_id)
                .await
                .ok()
                .flatten()
                .map(|u| u.handle)
                .unwrap_or_default();
            *guard = Some(Bound {
                user_id: authed.user_id.clone(),
                handle: handle.clone(),
                admin: authed.admin,
            });
            // Register this session's notification peer before touching the
            // pool, so a backend that finishes connecting after the bind
            // budget can push tools/list_changed to this client too.
            self.state
                .register_client_peer(self.session_key, &authed.user_id, ctx.peer.clone());
            crate::audit::event("mcp.bind")
                .actor(&handle)
                .actor_id(&authed.user_id)
                .client_id(authed.client_id.as_deref())
                .request(&authed.request)
                .ok();
        }
        Ok(authed)
    }

    /// Bind, then return the group's slice of the user's live backends from the
    /// shared pool — which spawns/reconciles them as needed. The snapshot's
    /// `Arc`s keep the backends alive for the duration of this request even if
    /// the pool retires them concurrently. Membership is fetched per request
    /// (like credential denials) so group edits take effect immediately; a
    /// lookup failure yields an empty set, failing closed.
    async fn group_backends(
        &self,
        ctx: &RequestContext<RoleServer>,
        group_id: &str,
    ) -> Result<Vec<Arc<Backend>>, McpError> {
        let authed = self.bind(ctx).await?;
        let members = crate::groups::member_instance_ids(&self.state.db, group_id)
            .await
            .unwrap_or_default();
        let backends = self
            .state
            .backend_pool
            .backends_for(&self.state, &authed.user_id)
            .await;
        Ok(backends
            .into_iter()
            .filter(|b| members.contains(&b.instance_id))
            .collect())
    }

    /// Run one backend's list call (tools/resources/prompts) under the
    /// configured wall-clock cap (`HUB_BACKEND_LIST_TIMEOUT_SECS`; 0 = none),
    /// so a backend that hangs mid-list is skipped from the aggregate instead
    /// of stalling the client into an empty view.
    async fn with_list_timeout<T, F>(&self, fut: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        let secs = self.state.config.limits.backend_list_timeout_secs;
        if secs == 0 {
            return fut.await;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!("list timed out after {secs}s")),
        }
    }

    /// Run a proxied backend call under the configured wall-clock timeout
    /// (`HUB_BACKEND_CALL_TIMEOUT_SECS`; 0 = no timeout). A timeout maps to an
    /// MCP internal error rather than hanging the client, and is logged loudly
    /// (with `label` naming the offending call) since a wedged backend otherwise
    /// leaves no server-side trace.
    async fn with_call_timeout<F, T>(&self, label: &str, fut: F) -> Result<T, McpError>
    where
        F: std::future::Future<Output = T>,
    {
        let secs = self.state.config.limits.backend_call_timeout_secs;
        if secs == 0 {
            return Ok(fut.await);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
            Ok(v) => Ok(v),
            Err(_) => {
                tracing::warn!(call = %label, secs, "proxied backend call timed out");
                Err(McpError::internal_error(
                    format!("backend call timed out after {secs}s"),
                    None,
                ))
            }
        }
    }

    /// Reject a backend response whose serialized size exceeds
    /// `HUB_MAX_RESPONSE_MB` (0 = uncapped), bounding memory blow-up from a
    /// backend returning an enormous payload.
    fn check_response_size<T: serde::Serialize>(&self, value: &T) -> Result<(), McpError> {
        let mb = self.state.config.limits.max_response_mb;
        if mb == 0 {
            return Ok(());
        }
        let cap = mb as usize * 1024 * 1024;
        if let Ok(bytes) = serde_json::to_vec(value) {
            if bytes.len() > cap {
                return Err(McpError::internal_error(
                    format!(
                        "backend response of {} bytes exceeds the {mb} MB limit",
                        bytes.len()
                    ),
                    None,
                ));
            }
        }
        Ok(())
    }
}

impl ServerHandler for HubProxy {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo / Implementation / Icon are #[non_exhaustive] in rmcp 2.x,
        // so build from constructors + public-field assignment rather than a
        // struct literal.
        let icon = Icon::new(HUB_ICON_DATA_URI.clone())
            .with_mime_type("image/png")
            .with_sizes(vec!["96x96".into()]);
        let mut server_info = Implementation::new("mcp-hub", env!("CARGO_PKG_VERSION"));
        server_info.title = Some("MCP Hub".into());
        server_info.icons = Some(vec![icon]);

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_resources()
            .enable_resources_list_changed()
            .enable_prompts()
            .enable_prompts_list_changed()
            .build();
        info.server_info = server_info;
        info.instructions = Some(
            "Aggregating MCP proxy. Tools and prompts are namespaced as \
             <server>__<name>, and resource URIs as hub://<server>/<uri>. \
             The base /mcp endpoint serves the hub__ management tools; each \
             connector group you define serves its servers' tools at \
             /mcp/<group> (see hub__list_groups)."
                .into(),
        );
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let t0 = std::time::Instant::now();
        // The base endpoint serves only the management tools; group endpoints
        // serve only their member backends' tools. Keeping the sets disjoint is
        // what lets every connector stay under client-side tool caps.
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                let authed = self.bind(&context).await?;
                return Ok(ListToolsResult {
                    tools: management::tools(authed.admin),
                    next_cursor: None,
                    meta: None,
                });
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let denied = self.denied_instances(&context).await;

        let mut tools = Vec::new();
        // Fan the per-backend tools/list out concurrently so the warm-refresh
        // latency is the slowest single backend, not the sum. Results are
        // collected in backend order, so the aggregate list stays deterministic.
        let backends: Vec<&Arc<Backend>> = backends
            .iter()
            .filter(|b| !denied.contains(&b.instance_id))
            .collect();
        let lists = futures::future::join_all(backends.iter().map(|b| async move {
            let bt0 = std::time::Instant::now();
            let r = self.with_list_timeout(b.list_namespaced_tools()).await;
            (&b.namespace, bt0.elapsed().as_millis() as u64, r)
        }))
        .await;
        for (namespace, elapsed_ms, r) in lists {
            match r {
                Ok(mut t) => {
                    tracing::debug!(namespace = %namespace, elapsed_ms, count = t.len(), "listed backend tools");
                    tools.append(&mut t);
                }
                Err(e) => {
                    tracing::warn!(namespace = %namespace, error = %e, "list_tools failed")
                }
            }
        }
        tracing::info!(
            backends = backends.len(),
            tools = tools.len(),
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "served tools/list"
        );
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                // The base endpoint handles management tools in-process and
                // nothing else — backend tools live on the group endpoints.
                if !management::is_management_tool(&request.name) {
                    return Err(McpError::invalid_params(
                        "backend tools are served on your connector group endpoints \
                         (/mcp/<group>), not on /mcp; see hub__list_groups",
                        None,
                    ));
                }
                let authed = self.bind(&context).await?;
                let (user_id, handle, admin) = {
                    let guard = self.bound.lock().await;
                    let bound = guard.as_ref().expect("bound after bind");
                    (bound.user_id.clone(), bound.handle.clone(), bound.admin)
                };
                // The calling client + origin come from the live request token (a
                // client may only manage its own connection label), not bound state.
                let caller = management::Caller {
                    user_id: &user_id,
                    handle: &handle,
                    admin,
                    client_id: authed.client_id.as_deref(),
                    request: &authed.request,
                };
                let op = request.name.strip_prefix("hub__").unwrap_or_default();
                let t0 = std::time::Instant::now();
                let result =
                    management::dispatch(&self.state, &caller, op, request.arguments).await;
                let kind = match &result {
                    Err(_) => Some(crate::metrics::ErrorKind::Error),
                    Ok(r) if r.is_error == Some(true) => Some(crate::metrics::ErrorKind::ToolError),
                    Ok(_) => None,
                };
                let user = if handle.is_empty() { &user_id } else { &handle };
                self.state
                    .metrics
                    .record_call(user, "hub", op, t0.elapsed(), kind);
                return result;
            }
            McpEndpoint::Group { group_id, .. } => {
                if management::is_management_tool(&request.name) {
                    return Err(McpError::invalid_params(
                        "hub management tools are only available on the base /mcp endpoint",
                        None,
                    ));
                }
                group_id
            }
        };
        let backends = self.group_backends(&context, &group_id).await?;

        let (ns, original) = request.name.split_once("__").ok_or_else(|| {
            McpError::invalid_params("tool name must be namespaced as <server>__<tool>", None)
        })?;

        let denied = self.denied_instances(&context).await;
        // Proxied backend tool calls are high-volume; keep them out of the
        // info-level audit stream and log them at debug instead.
        tracing::debug!(tool = %request.name, "proxied tool call");
        // A backend the credential is denied is treated as if it doesn't exist.
        let backend = backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;

        // The usage-metrics user label: the bound handle (bound is set — the
        // group_backends call above binds), falling back to the raw user id.
        let user = {
            let guard = self.bound.lock().await;
            guard
                .as_ref()
                .map(|b| {
                    if b.handle.is_empty() {
                        b.user_id.clone()
                    } else {
                        b.handle.clone()
                    }
                })
                .unwrap_or_default()
        };
        let t0 = std::time::Instant::now();
        let outcome = self
            .with_call_timeout(
                &request.name,
                backend.call_tool(original.to_string(), request.arguments),
            )
            .await;
        let elapsed = t0.elapsed();
        let record = |kind| {
            self.state
                .metrics
                .record_call(&user, ns, original, elapsed, kind)
        };
        let result = match outcome {
            // with_call_timeout's own error is always the call timeout.
            Err(e) => {
                record(Some(crate::metrics::ErrorKind::Timeout));
                return Err(e);
            }
            Ok(Err(e)) => {
                record(Some(crate::metrics::ErrorKind::Error));
                tracing::warn!(
                    namespace = %ns,
                    tool = %request.name,
                    elapsed_ms = elapsed.as_millis() as u64,
                    error = %format!("{e:#}"),
                    "proxied tool call failed"
                );
                return Err(McpError::internal_error(format!("{e:#}"), None));
            }
            Ok(Ok(result)) => {
                record(if result.is_error == Some(true) {
                    Some(crate::metrics::ErrorKind::ToolError)
                } else {
                    None
                });
                result
            }
        };
        tracing::debug!(
            namespace = %ns,
            tool = %request.name,
            elapsed_ms = elapsed.as_millis() as u64,
            "proxied tool call done"
        );
        self.check_response_size(&result)?;
        Ok(result)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                self.bind(&context).await?;
                return Ok(ListResourcesResult {
                    resources: Vec::new(),
                    next_cursor: None,
                    meta: None,
                });
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let denied = self.denied_instances(&context).await;
        let lists = futures::future::join_all(
            backends
                .iter()
                .filter(|b| !denied.contains(&b.instance_id))
                .map(|b| async move {
                    (
                        &b.namespace,
                        self.with_list_timeout(b.list_namespaced_resources()).await,
                    )
                }),
        )
        .await;
        let mut resources = Vec::new();
        for (namespace, r) in lists {
            match r {
                Ok(mut r) => resources.append(&mut r),
                // A backend without the resources capability errors here; that
                // is expected, so log at debug and move on.
                Err(e) => tracing::debug!(namespace = %namespace, error = %e, "no resources"),
            }
        }
        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                self.bind(&context).await?;
                return Ok(ListResourceTemplatesResult {
                    resource_templates: Vec::new(),
                    next_cursor: None,
                    meta: None,
                });
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let denied = self.denied_instances(&context).await;
        let lists = futures::future::join_all(
            backends
                .iter()
                .filter(|b| !denied.contains(&b.instance_id))
                .map(|b| async move {
                    (
                        &b.namespace,
                        self.with_list_timeout(b.list_namespaced_resource_templates())
                            .await,
                    )
                }),
        )
        .await;
        let mut resource_templates = Vec::new();
        for (namespace, r) in lists {
            match r {
                Ok(mut t) => resource_templates.append(&mut t),
                Err(e) => tracing::debug!(namespace = %namespace, error = %e, "no templates"),
            }
        }
        Ok(ListResourceTemplatesResult {
            resource_templates,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                return Err(McpError::invalid_params(
                    "resources are served on your connector group endpoints (/mcp/<group>)",
                    None,
                ));
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let (ns, original) = unwrap_uri(&request.uri).ok_or_else(|| {
            McpError::invalid_params(
                "resource URI must be namespaced as hub://<server>/<uri>",
                None,
            )
        })?;

        let denied = self.denied_instances(&context).await;
        let backend = backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;
        let t0 = std::time::Instant::now();
        let result = self
            .with_call_timeout(&request.uri, backend.read_resource(original.to_string()))
            .await?
            .map_err(|e| {
                tracing::warn!(
                    namespace = %ns,
                    uri = %request.uri,
                    elapsed_ms = t0.elapsed().as_millis() as u64,
                    error = %format!("{e:#}"),
                    "proxied read_resource failed"
                );
                McpError::internal_error(format!("{e:#}"), None)
            })?;
        tracing::debug!(
            namespace = %ns,
            uri = %request.uri,
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "proxied read_resource done"
        );
        self.check_response_size(&result)?;
        Ok(result)
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                self.bind(&context).await?;
                return Ok(ListPromptsResult {
                    prompts: Vec::new(),
                    next_cursor: None,
                    meta: None,
                });
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let denied = self.denied_instances(&context).await;
        let lists = futures::future::join_all(
            backends
                .iter()
                .filter(|b| !denied.contains(&b.instance_id))
                .map(|b| async move {
                    (
                        &b.namespace,
                        self.with_list_timeout(b.list_namespaced_prompts()).await,
                    )
                }),
        )
        .await;
        let mut prompts = Vec::new();
        for (namespace, r) in lists {
            match r {
                Ok(mut p) => prompts.append(&mut p),
                Err(e) => tracing::debug!(namespace = %namespace, error = %e, "no prompts"),
            }
        }
        Ok(ListPromptsResult {
            prompts,
            next_cursor: None,
            meta: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        let group_id = match Self::endpoint(&context)? {
            McpEndpoint::Management => {
                return Err(McpError::invalid_params(
                    "prompts are served on your connector group endpoints (/mcp/<group>)",
                    None,
                ));
            }
            McpEndpoint::Group { group_id, .. } => group_id,
        };
        let backends = self.group_backends(&context, &group_id).await?;
        let (ns, original) = request.name.split_once("__").ok_or_else(|| {
            McpError::invalid_params("prompt name must be namespaced as <server>__<prompt>", None)
        })?;

        let denied = self.denied_instances(&context).await;
        let backend = backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;
        let t0 = std::time::Instant::now();
        let result = self
            .with_call_timeout(
                &request.name,
                backend.get_prompt(original.to_string(), request.arguments),
            )
            .await?
            .map_err(|e| {
                tracing::warn!(
                    namespace = %ns,
                    prompt = %request.name,
                    elapsed_ms = t0.elapsed().as_millis() as u64,
                    error = %format!("{e:#}"),
                    "proxied get_prompt failed"
                );
                McpError::internal_error(format!("{e:#}"), None)
            })?;
        tracing::debug!(
            namespace = %ns,
            prompt = %request.name,
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "proxied get_prompt done"
        );
        self.check_response_size(&result)?;
        Ok(result)
    }
}
