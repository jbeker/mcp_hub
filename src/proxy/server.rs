//! The aggregating MCP server handler. One instance per client session; it
//! lazily binds to the authenticated user and fans requests out to that user's
//! enabled backends, namespacing everything as `<server>__<tool>`.

use rmcp::model::{
    CallToolRequestParam, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParam,
    ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::sync::Mutex;

use crate::instances;
use crate::proxy::backend::Backend;
use crate::proxy::{management, AuthedUser};
use crate::AppState;

/// One aggregating proxy session.
pub struct HubProxy {
    state: AppState,
    bound: Mutex<Option<Bound>>,
}

/// The user-specific state, established on the first authenticated request.
struct Bound {
    user_id: String,
    admin: bool,
    backends: Vec<Backend>,
}

impl HubProxy {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            bound: Mutex::new(None),
        }
    }

    /// Pull the authenticated user out of the forwarded HTTP request parts.
    fn authed(ctx: &RequestContext<RoleServer>) -> Result<AuthedUser, McpError> {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<AuthedUser>().cloned())
            .ok_or_else(|| McpError::invalid_request("missing authentication", None))
    }

    /// Ensure backends are connected for the request's user (lazy, once).
    async fn ensure_bound(&self, ctx: &RequestContext<RoleServer>) -> Result<(), McpError> {
        let authed = Self::authed(ctx)?;
        let mut guard = self.bound.lock().await;
        if guard.as_ref().is_some_and(|b| b.user_id == authed.user_id) {
            return Ok(());
        }
        if let Some(old) = guard.take() {
            for b in old.backends {
                b.shutdown().await;
            }
        }
        let backends = self.build_backends(&authed.user_id).await;
        tracing::info!(user = %authed.user_id, backends = backends.len(), "bound proxy session");
        *guard = Some(Bound {
            user_id: authed.user_id,
            admin: authed.admin,
            backends,
        });
        Ok(())
    }

    /// Connect every enabled instance; a failing backend is logged and skipped
    /// so it can't take down the whole session.
    async fn build_backends(&self, user_id: &str) -> Vec<Backend> {
        let mut out = Vec::new();
        let instances = match instances::list_for_user(&self.state.db, user_id).await {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(error = %e, "listing instances failed");
                return out;
            }
        };
        let per_user_cap = self.state.config.limits.max_backends_per_user;
        for inst in instances.into_iter().filter(|i| i.enabled) {
            if out.len() >= per_user_cap {
                tracing::warn!(
                    cap = per_user_cap,
                    "per-user backend cap reached; remaining servers not started"
                );
                break;
            }
            // Acquire a global slot; if exhausted, stop adding backends.
            let permit = match self.state.backend_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("global backend capacity reached; skipping remaining backends");
                    break;
                }
            };
            let def = match instances::resolve_def(&self.state.db, &inst).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(namespace = %inst.namespace, error = %e, "resolve def failed");
                    continue;
                }
            };
            let env = match instances::resolved_env(&self.state.db, &self.state.secrets, &inst).await
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(namespace = %inst.namespace, error = %e, "resolve env failed");
                    continue;
                }
            };
            match Backend::spawn(
                &def,
                &env,
                inst.namespace.clone(),
                inst.display_name.clone(),
                permit,
            )
            .await
            {
                Ok(b) => out.push(b),
                Err(e) => {
                    tracing::warn!(namespace = %inst.namespace, error = %e, "backend failed to start")
                }
            }
        }
        out
    }
}

impl ServerHandler for HubProxy {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
            server_info: Implementation {
                name: "mcp-hub".into(),
                title: Some("MCP Hub".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Aggregating MCP proxy. Tools are namespaced as <server>__<tool>. \
                 Use the hub__ tools to manage your configured servers."
                    .into(),
            ),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.ensure_bound(&context).await?;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");

        // The built-in management tools always come first.
        let mut tools = management::tools(bound.admin);
        for b in &bound.backends {
            match b.list_namespaced_tools().await {
                Ok(mut t) => tools.append(&mut t),
                Err(e) => {
                    tracing::warn!(namespace = %b.namespace, error = %e, "list_tools failed")
                }
            }
        }
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_bound(&context).await?;

        // Management tools are handled in-process by the hub itself.
        if management::is_management_tool(&request.name) {
            let (user_id, admin) = {
                let guard = self.bound.lock().await;
                let bound = guard.as_ref().expect("bound after ensure_bound");
                (bound.user_id.clone(), bound.admin)
            };
            let op = request.name.strip_prefix("hub__").unwrap_or_default();
            return management::dispatch(&self.state, &user_id, admin, op, request.arguments).await;
        }

        let (ns, original) = request.name.split_once("__").ok_or_else(|| {
            McpError::invalid_params(
                "tool name must be namespaced as <server>__<tool>",
                None,
            )
        })?;

        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let backend = bound
            .backends
            .iter()
            .find(|b| b.namespace == ns)
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;

        backend
            .call_tool(original.to_string(), request.arguments)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))
    }
}
