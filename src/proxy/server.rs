//! The aggregating MCP server handler. One instance per client session; it
//! lazily binds to the authenticated user and fans requests out to that user's
//! enabled backends, namespacing everything as `<server>__<tool>`.

use rmcp::model::{
    CallToolRequestParam, CallToolResult, GetPromptRequestParam, GetPromptResult, Icon,
    Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParam, ProtocolVersion, ReadResourceRequestParam,
    ReadResourceResult, ServerCapabilities, ServerInfo,
};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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

use crate::instances;
use crate::proxy::backend::{unwrap_uri, Backend};
use crate::proxy::{management, AuthedUser};
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
struct Bound {
    user_id: String,
    /// Resolved once at bind time so per-call audit events can name the actor.
    handle: String,
    admin: bool,
    backends: Vec<Backend>,
    /// instance_id -> reload epoch this session has acted on, for every enabled
    /// instance seen at bind time (running or not). Drives surgical restarts: a
    /// Restart click bumps the shared epoch, and `reconcile_reloads` respawns any
    /// instance whose shared epoch has moved past the one recorded here.
    applied_epochs: HashMap<String, u64>,
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

    /// The instance ids the request's credential (OAuth client or PAT) is denied,
    /// for per-credential backend access control. Empty = full access (the default
    /// and the case for any request without a recognizable credential). Looked up
    /// per request so a user's toggle on the Account page takes effect immediately.
    async fn denied_instances(&self, ctx: &RequestContext<RoleServer>) -> HashSet<String> {
        let cred = Self::authed(ctx)
            .ok()
            .and_then(|a| a.credential().map(|(t, id)| (t.to_string(), id.to_string())));
        match cred {
            Some((t, id)) => crate::access::denied_instances(&self.state.db, &t, &id)
                .await
                .unwrap_or_default(),
            None => HashSet::new(),
        }
    }

    /// Ensure backends are connected for the request's user (lazy, once), then
    /// reconcile any backend whose reload epoch advanced since this session last
    /// acted on it (the web Restart button). Both run under the same `bound`
    /// guard, so a request always observes a consistent backend set.
    async fn ensure_bound(&self, ctx: &RequestContext<RoleServer>) -> Result<(), McpError> {
        let authed = Self::authed(ctx)?;
        let mut guard = self.bound.lock().await;
        if guard.as_ref().is_none_or(|b| b.user_id != authed.user_id) {
            if let Some(old) = guard.take() {
                for b in old.backends {
                    b.shutdown().await;
                }
            }
            let t0 = std::time::Instant::now();
            let (backends, applied_epochs) = self.build_backends(&authed.user_id).await;
            let bind_ms = t0.elapsed().as_millis();
            tracing::info!(
                user = %authed.user_id,
                connected = backends.len(),
                attempted = applied_epochs.len(),
                elapsed_ms = bind_ms as u64,
                "bound MCP session backends"
            );
            // Resolve the handle once so per-call audit events can name the actor.
            let handle = crate::users::find_by_id(&self.state.db, &authed.user_id)
                .await
                .ok()
                .flatten()
                .map(|u| u.handle)
                .unwrap_or_default();
            crate::audit::event("mcp.bind")
                .actor(&handle)
                .actor_id(&authed.user_id)
                .client_id(authed.client_id.as_deref())
                .request(&authed.request)
                .object(&backends.len().to_string())
                .ok();
            *guard = Some(Bound {
                user_id: authed.user_id.clone(),
                handle,
                admin: authed.admin,
                backends,
                applied_epochs,
            });
            // Register this session's notification peer so a later backend-set
            // change (e.g. the web Restart button) can push tools/list_changed
            // to the client without it having to poll or manually refresh.
            self.state
                .register_client_peer(self.session_key, &authed.user_id, ctx.peer.clone());
        }
        self.reconcile_reloads(guard.as_mut().expect("bound above"), &authed.user_id)
            .await;
        Ok(())
    }

    /// Respawn any of this session's backends whose shared reload epoch has moved
    /// past the epoch recorded at bind/last-reconcile time. Only instances whose
    /// epoch actually changed do any work — the common path is a cheap compare
    /// with no DB or process activity. A surgical restart: untouched backends keep
    /// their live connections.
    async fn reconcile_reloads(&self, bound: &mut Bound, user_id: &str) {
        let stale: Vec<String> = bound
            .applied_epochs
            .iter()
            .filter(|(id, applied)| self.state.reload_epoch(id) != **applied)
            .map(|(id, _)| id.clone())
            .collect();
        if stale.is_empty() {
            return;
        }
        // A restart relaunches a stdio subprocess; resolve the sandbox identity
        // the same fail-closed way `build_backends` does.
        let sandbox = match self.state.sandbox_or_fail(user_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "restart skipped: sandbox unavailable");
                return;
            }
        };
        for id in stale {
            let cur = self.state.reload_epoch(&id);
            // Drop the running instance (if any), freeing its global slot first.
            if let Some(pos) = bound.backends.iter().position(|b| b.instance_id == id) {
                bound.backends.remove(pos).shutdown().await;
            }
            // Re-read from the DB so the relaunch picks up the latest def/config.
            // Gone or now-disabled instances stay down and stop being tracked.
            let inst = match instances::get_owned(&self.state.db, &id, user_id).await {
                Ok(Some(i)) if i.enabled => i,
                Ok(_) => {
                    bound.applied_epochs.remove(&id);
                    continue;
                }
                Err(e) => {
                    tracing::warn!(instance = %id, error = %e, "restart skipped: instance lookup failed");
                    continue;
                }
            };
            let permit = match self.state.backend_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("restart skipped: global backend capacity reached");
                    self.mark_status(&inst, "skipped", Some("global backend capacity reached")).await;
                    bound.applied_epochs.insert(id, cur);
                    continue;
                }
            };
            if let Some(b) = self.spawn_one(&inst, sandbox.as_ref(), permit).await {
                bound.backends.push(b);
            }
            bound.applied_epochs.insert(id, cur);
        }
    }

    /// Connect every enabled instance; a failing backend is logged and skipped
    /// so it can't take down the whole session. Returns the live backends plus
    /// the reload epoch recorded for every enabled instance seen (running or
    /// not), so [`reconcile_reloads`] can later restart just the ones that change.
    async fn build_backends(&self, user_id: &str) -> (Vec<Backend>, HashMap<String, u64>) {
        let mut out = Vec::new();
        let mut applied_epochs = HashMap::new();
        let instances = match instances::list_for_user(&self.state.db, user_id).await {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(error = %e, "listing instances failed");
                return (out, applied_epochs);
            }
        };
        let per_user_cap = self.state.config.limits.max_backends_per_user;
        let enabled: Vec<_> = instances.into_iter().filter(|i| i.enabled).collect();
        // Track the reload epoch of every enabled instance up front, so a later
        // Restart can (re)start one that failed to spawn here, not just recycle a
        // running one.
        for inst in &enabled {
            applied_epochs.insert(inst.id.clone(), self.state.reload_epoch(&inst.id));
        }
        // The per-user sandbox identity for this user's stdio subprocesses. Fail
        // closed: if sandboxing is configured but unavailable, start no backends
        // rather than running user commands as root.
        let sandbox = match self.state.sandbox_or_fail(user_id).await {
            Ok(s) => s,
            Err(e) => {
                self.mark_skipped(&enabled, &format!("sandbox unavailable: {e:#}")).await;
                return (out, applied_epochs);
            }
        };
        // Acquire each backend's global slot up front (synchronously), bounded by
        // the per-user cap, then spawn them all concurrently. Cold-start latency
        // is then the slowest single backend, not the sum — the connect handshake
        // of one backend no longer blocks the others, so the first `tools/list`
        // returns promptly instead of timing out the client into an empty list.
        let mut to_spawn = Vec::new();
        for (idx, inst) in enabled.iter().enumerate() {
            if to_spawn.len() >= per_user_cap {
                tracing::warn!(cap = per_user_cap, "per-user backend cap reached");
                self.mark_skipped(&enabled[idx..], "per-user backend cap reached").await;
                break;
            }
            // Acquire a global slot; if exhausted, stop adding backends.
            match self.state.backend_slots.clone().try_acquire_owned() {
                Ok(permit) => to_spawn.push((inst, permit)),
                Err(_) => {
                    tracing::warn!("global backend capacity reached");
                    self.mark_skipped(&enabled[idx..], "global backend capacity reached").await;
                    break;
                }
            }
        }
        let spawned = futures::future::join_all(
            to_spawn
                .into_iter()
                .map(|(inst, permit)| self.spawn_one(inst, sandbox.as_ref(), permit)),
        )
        .await;
        out.extend(spawned.into_iter().flatten());
        (out, applied_epochs)
    }

    /// Resolve, launch, and initialize a single backend, recording its connection
    /// outcome. Returns the live [`Backend`] on success, or `None` (with the
    /// instance's status marked) on any failure — so a bad backend can't take
    /// down the session. Shared by the initial bind and by restarts.
    async fn spawn_one(
        &self,
        inst: &instances::Instance,
        sandbox: Option<&crate::sandbox::Sandbox>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Option<Backend> {
        let mut def = match instances::resolve_def(&self.state.db, inst).await {
            Ok(d) => d,
            Err(e) => {
                self.mark_status(inst, "error", Some(&format!("resolve failed: {e:#}"))).await;
                return None;
            }
        };
        if def.transport == "http" {
            let url = def.url.as_deref().unwrap_or("").trim();
            if url.is_empty() {
                self.mark_status(inst, "error", Some("no remote URL set")).await;
                return None;
            }
            // Re-resolve the host at connect time (not just at save) so the
            // SSRF guard also defeats DNS rebinding.
            if let Err(e) =
                instances::check_backend_host(url, self.state.config.block_private_backend_ips)
            {
                self.mark_status(inst, "error", Some(&format!("{e}"))).await;
                return None;
            }
        }
        // Git-sourced backends run from their prebuilt virtualenv. Rewrite
        // the def to a direct stdio exec; skip if it has not been built yet.
        if crate::gitsrc::is_git_source(&def) {
            let ready = inst.build_status == "ready"
                && crate::gitsrc::env_path(&self.state.config.env_dir, &inst.id).exists();
            // A venv from before the interpreter relocation can't exec under
            // the sandbox. Don't launch it (that yields a cryptic EACCES);
            // point the user at the one-click heal instead. Rebuilding here
            // would block every MCP connection on a slow build.
            if ready && crate::gitsrc::venv_is_stale(&self.state.config.env_dir, inst, &def) {
                self.mark_status(
                    inst,
                    "unbuilt",
                    Some("needs rebuild after upgrade — open its page and click “Test connection”"),
                )
                .await;
                return None;
            }
            if ready {
                match crate::gitsrc::launch_command(&self.state.config.env_dir, &inst.id, &def) {
                    Ok((program, args)) => {
                        def.transport = "stdio".into();
                        def.command = Some(program);
                        def.args = args;
                    }
                    Err(e) => {
                        self.mark_status(inst, "error", Some(&format!("git launch failed: {e:#}"))).await;
                        return None;
                    }
                }
            } else {
                self.mark_status(inst, "unbuilt", Some("not built yet; run hub__update_server")).await;
                return None;
            }
        }
        let env = match instances::resolved_env(&self.state.db, &self.state.secrets, inst).await {
            Ok(e) => e,
            Err(e) => {
                self.mark_status(inst, "error", Some(&format!("config error: {e:#}"))).await;
                return None;
            }
        };
        let config_file =
            match instances::resolved_config_file(&self.state.db, &self.state.secrets, &inst.id)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    self.mark_status(inst, "error", Some(&format!("config error: {e:#}"))).await;
                    return None;
                }
            };
        let t0 = std::time::Instant::now();
        let result = Backend::spawn(
            &def,
            &env,
            inst.id.clone(),
            inst.namespace.clone(),
            inst.display_name.clone(),
            permit,
            sandbox,
            &self.state.config.env_dir,
            config_file.as_deref(),
            self.state.config.child_limits,
        )
        .await;
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        match result {
            Ok(b) => {
                tracing::info!(
                    namespace = %inst.namespace,
                    transport = %def.transport,
                    elapsed_ms,
                    "backend connected"
                );
                self.mark_status(inst, "ok", None).await;
                Some(b)
            }
            Err(e) => {
                tracing::info!(
                    namespace = %inst.namespace,
                    transport = %def.transport,
                    elapsed_ms,
                    error = %format!("{e:#}"),
                    "backend connect failed"
                );
                self.mark_status(inst, "error", Some(&format!("failed to start: {e:#}"))).await;
                None
            }
        }
    }

    /// Run a proxied backend call under the configured wall-clock timeout
    /// (`HUB_BACKEND_CALL_TIMEOUT_SECS`; 0 = no timeout). A timeout maps to an
    /// MCP internal error rather than hanging the client.
    async fn with_call_timeout<F, T>(&self, fut: F) -> Result<T, McpError>
    where
        F: std::future::Future<Output = T>,
    {
        let secs = self.state.config.limits.backend_call_timeout_secs;
        if secs == 0 {
            return Ok(fut.await);
        }
        match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
            Ok(v) => Ok(v),
            Err(_) => Err(McpError::internal_error(
                format!("backend call timed out after {secs}s"),
                None,
            )),
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
                    format!("backend response of {} bytes exceeds the {mb} MB limit", bytes.len()),
                    None,
                ));
            }
        }
        Ok(())
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
                icons: Some(vec![Icon {
                    src: HUB_ICON_DATA_URI.clone(),
                    mime_type: Some("image/png".into()),
                    sizes: Some(vec!["96x96".into()]),
                }]),
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
        let t0 = std::time::Instant::now();
        self.ensure_bound(&context).await?;
        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");

        // The built-in management tools always come first and are never restricted.
        let mut tools = management::tools(bound.admin);
        // Fan the per-backend tools/list out concurrently so the warm-refresh
        // latency is the slowest single backend, not the sum. Results are
        // collected in backend order, so the aggregate list stays deterministic.
        let backends: Vec<&Backend> = bound
            .backends
            .iter()
            .filter(|b| !denied.contains(&b.instance_id))
            .collect();
        let lists = futures::future::join_all(backends.iter().map(|b| async move {
            let bt0 = std::time::Instant::now();
            let r = b.list_namespaced_tools().await;
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
            let (user_id, handle, admin) = {
                let guard = self.bound.lock().await;
                let bound = guard.as_ref().expect("bound after ensure_bound");
                (bound.user_id.clone(), bound.handle.clone(), bound.admin)
            };
            // The calling client + origin come from the live request token (a
            // client may only manage its own connection label), not bound state.
            let authed = Self::authed(&context)?;
            let caller = management::Caller {
                user_id: &user_id,
                handle: &handle,
                admin,
                client_id: authed.client_id.as_deref(),
                request: &authed.request,
            };
            let op = request.name.strip_prefix("hub__").unwrap_or_default();
            return management::dispatch(&self.state, &caller, op, request.arguments).await;
        }

        let (ns, original) = request.name.split_once("__").ok_or_else(|| {
            McpError::invalid_params(
                "tool name must be namespaced as <server>__<tool>",
                None,
            )
        })?;

        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        // Proxied backend tool calls are high-volume; keep them out of the
        // info-level audit stream and log them at debug instead.
        tracing::debug!(user = %bound.user_id, tool = %request.name, "proxied tool call");
        // A backend the credential is denied is treated as if it doesn't exist.
        let backend = bound
            .backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;

        let result = self
            .with_call_timeout(backend.call_tool(original.to_string(), request.arguments))
            .await?
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))?;
        self.check_response_size(&result)?;
        Ok(result)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.ensure_bound(&context).await?;
        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut resources = Vec::new();
        for b in bound.backends.iter().filter(|b| !denied.contains(&b.instance_id)) {
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
        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut resource_templates = Vec::new();
        for b in bound.backends.iter().filter(|b| !denied.contains(&b.instance_id)) {
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

        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let backend = bound
            .backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;
        let result = self
            .with_call_timeout(backend.read_resource(original.to_string()))
            .await?
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))?;
        self.check_response_size(&result)?;
        Ok(result)
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        self.ensure_bound(&context).await?;
        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let mut prompts = Vec::new();
        for b in bound.backends.iter().filter(|b| !denied.contains(&b.instance_id)) {
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

        let denied = self.denied_instances(&context).await;
        let guard = self.bound.lock().await;
        let bound = guard.as_ref().expect("bound after ensure_bound");
        let backend = bound
            .backends
            .iter()
            .find(|b| b.namespace == ns && !denied.contains(&b.instance_id))
            .ok_or_else(|| {
                McpError::invalid_params(format!("no enabled server with namespace '{ns}'"), None)
            })?;
        let result = self
            .with_call_timeout(backend.get_prompt(original.to_string(), request.arguments))
            .await?
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))?;
        self.check_response_size(&result)?;
        Ok(result)
    }
}
