//! The aggregating MCP server handler. One instance per client session; it
//! lazily binds to the authenticated user and fans requests out to that user's
//! enabled backends, namespacing everything as `<server>__<tool>`.

use rmcp::model::{
    CallToolRequestParam, CallToolResult, GetPromptRequestParam, GetPromptResult, Implementation,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParam, ProtocolVersion, ReadResourceRequestParam, ReadResourceResult,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::sync::Mutex;

use crate::instances;
use crate::proxy::backend::{unwrap_uri, Backend};
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
        let enabled: Vec<_> = instances.into_iter().filter(|i| i.enabled).collect();
        for (idx, inst) in enabled.iter().enumerate() {
            if out.len() >= per_user_cap {
                tracing::warn!(cap = per_user_cap, "per-user backend cap reached");
                self.mark_skipped(&enabled[idx..], "per-user backend cap reached").await;
                break;
            }
            // Acquire a global slot; if exhausted, stop adding backends.
            let permit = match self.state.backend_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("global backend capacity reached");
                    self.mark_skipped(&enabled[idx..], "global backend capacity reached").await;
                    break;
                }
            };
            let mut def = match instances::resolve_def(&self.state.db, inst).await {
                Ok(d) => d,
                Err(e) => {
                    self.mark_status(inst, "error", Some(&format!("resolve failed: {e:#}"))).await;
                    continue;
                }
            };
            // For http remotes, let the instance override the catalog's URL with
            // its own endpoint (see instances::URL_KEY).
            if def.transport == "http" {
                if let Some(u) = inst
                    .config
                    .get(instances::URL_KEY)
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    def.url = Some(u.to_string());
                }
                if def.url.as_deref().unwrap_or("").trim().is_empty() {
                    self.mark_status(
                        inst,
                        "error",
                        Some("no remote URL set — configure it on the server page"),
                    )
                    .await;
                    continue;
                }
            }
            // Git-sourced backends run from their prebuilt virtualenv. Rewrite
            // the def to a direct stdio exec; skip if it has not been built yet.
            if crate::gitsrc::is_git_source(&def) {
                let ready = inst.build_status == "ready"
                    && crate::gitsrc::env_path(&self.state.config.env_dir, &inst.id).exists();
                if ready {
                    match crate::gitsrc::launch_command(&self.state.config.env_dir, &inst.id, &def) {
                        Ok((program, args)) => {
                            def.transport = "stdio".into();
                            def.command = Some(program);
                            def.args = args;
                        }
                        Err(e) => {
                            self.mark_status(inst, "error", Some(&format!("git launch failed: {e:#}"))).await;
                            continue;
                        }
                    }
                } else {
                    self.mark_status(inst, "unbuilt", Some("not built yet; run hub__update_server")).await;
                    continue;
                }
            }
            let env = match instances::resolved_env(&self.state.db, &self.state.secrets, inst).await
            {
                Ok(e) => e,
                Err(e) => {
                    self.mark_status(inst, "error", Some(&format!("config error: {e:#}"))).await;
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
                Ok(b) => {
                    self.mark_status(inst, "ok", None).await;
                    out.push(b);
                }
                Err(e) => {
                    self.mark_status(inst, "error", Some(&format!("failed to start: {e:#}"))).await;
                }
            }
        }
        out
    }

    /// Persist a backend's connection outcome so the UI / hub__ tools can show
    /// why it is (not) running. Best-effort: a status-write failure is logged,
    /// not propagated.
    async fn mark_status(&self, inst: &instances::Instance, status: &str, detail: Option<&str>) {
        if status != "ok" {
            tracing::warn!(namespace = %inst.namespace, status, detail, "backend not running");
        }
        if let Err(e) =
            instances::set_runtime_status(&self.state.db, &inst.id, status, detail).await
        {
            tracing::error!(error = %e, "recording backend status failed");
        }
    }

    /// Mark a run of instances skipped (capacity reached before reaching them).
    async fn mark_skipped(&self, insts: &[instances::Instance], reason: &str) {
        for inst in insts {
            self.mark_status(inst, "skipped", Some(reason)).await;
        }
    }
}

impl ServerHandler for HubProxy {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .enable_prompts()
                .enable_prompts_list_changed()
                .build(),
            server_info: Implementation {
                name: "mcp-hub".into(),
                title: Some("MCP Hub".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Aggregating MCP proxy. Tools and prompts are namespaced as \
                 <server>__<name>, and resource URIs as hub://<server>/<uri>. \
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
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.ensure_bound(&context).await?;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut resources = Vec::new();
        for b in &bound.backends {
            match b.list_namespaced_resources().await {
                Ok(mut r) => resources.append(&mut r),
                // A backend without the resources capability errors here; that
                // is expected, so log at debug and move on.
                Err(e) => tracing::debug!(namespace = %b.namespace, error = %e, "no resources"),
            }
        }
        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.ensure_bound(&context).await?;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut resource_templates = Vec::new();
        for b in &bound.backends {
            match b.list_namespaced_resource_templates().await {
                Ok(mut t) => resource_templates.append(&mut t),
                Err(e) => tracing::debug!(namespace = %b.namespace, error = %e, "no templates"),
            }
        }
        Ok(ListResourceTemplatesResult {
            resource_templates,
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        self.ensure_bound(&context).await?;
        let (ns, original) = unwrap_uri(&request.uri).ok_or_else(|| {
            McpError::invalid_params(
                "resource URI must be namespaced as hub://<server>/<uri>",
                None,
            )
        })?;

        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let backend = bound.backends.iter().find(|b| b.namespace == ns).ok_or_else(|| {
            McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
        })?;
        backend
            .read_resource(original.to_string())
            .await
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        self.ensure_bound(&context).await?;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut prompts = Vec::new();
        for b in &bound.backends {
            match b.list_namespaced_prompts().await {
                Ok(mut p) => prompts.append(&mut p),
                Err(e) => tracing::debug!(namespace = %b.namespace, error = %e, "no prompts"),
            }
        }
        Ok(ListPromptsResult {
            prompts,
            next_cursor: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        self.ensure_bound(&context).await?;
        let (ns, original) = request.name.split_once("__").ok_or_else(|| {
            McpError::invalid_params("prompt name must be namespaced as <server>__<prompt>", None)
        })?;

        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let backend = bound.backends.iter().find(|b| b.namespace == ns).ok_or_else(|| {
            McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
        })?;
        backend
            .get_prompt(original.to_string(), request.arguments)
            .await
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }
}
