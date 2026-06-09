//! The built-in management MCP interface, exposed under the reserved `hub`
//! namespace. These tools let any MCP client configure the hub programmatically,
//! acting on the token's user. Catalog/user administration is gated on `admin`.

use std::sync::Arc;

use std::collections::BTreeMap;

use rmcp::model::{CallToolResult, Content, JsonObject, Tool};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};

use crate::auth::RequestInfo;
use crate::instances::{self, ServerDef};
use crate::{invites, users};
use crate::AppState;

/// Who is making a management call, for authorization and audit logging.
pub struct Caller<'a> {
    pub user_id: &'a str,
    pub handle: &'a str,
    pub admin: bool,
    /// The OAuth client this call came through (`None` for a personal token).
    pub client_id: Option<&'a str>,
    pub request: &'a RequestInfo,
}

/// Build the list of management tools available to the caller.
pub fn tools(admin: bool) -> Vec<Tool> {
    let mut t = vec![
        tool("hub__whoami", "Show the current user and their configured servers.", schema(json!({}), &[])),
        tool(
            "hub__list_my_servers",
            "List your configured servers, their launch command and status.",
            schema(json!({}), &[]),
        ),
        tool(
            "hub__add_server",
            "Add one of your own MCP servers. For stdio, give a 'command' line \
             (and optionally a 'repo' to build a cached venv from); for http, give \
             a 'url'. 'env' is a map of environment variables (encrypted).",
            schema(
                json!({
                    "namespace": {"type": "string", "description": "Unique tool-name prefix, e.g. 'zabbix'"},
                    "transport": {"type": "string", "enum": ["stdio", "http"]},
                    "command": {"type": "string", "description": "stdio: the command line, e.g. 'uvx zabbix-mcp-server'"},
                    "url": {"type": "string", "description": "http: the remote endpoint URL"},
                    "repo": {"type": "string", "description": "stdio (optional): git repo to build a cached venv from"},
                    "git_ref": {"type": "string", "description": "branch/tag for 'repo' (default main)"},
                    "display_name": {"type": "string"},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Values may reference ${VAR}, e.g. GOOGLE_APPLICATION_CREDENTIALS=${MCP_CONFIG_FILE}"},
                    "config_file": {"type": "string", "description": "stdio (optional): config file written to the server's working dir, path in MCP_CONFIG_FILE"}
                }),
                &["namespace", "transport"],
            ),
        ),
        tool(
            "hub__edit_server",
            "Change one of your servers' command/url/repo (omitted fields are \
             left unchanged).",
            schema(
                json!({
                    "namespace": {"type": "string"},
                    "command": {"type": "string"},
                    "url": {"type": "string"},
                    "repo": {"type": "string"},
                    "git_ref": {"type": "string"}
                }),
                &["namespace"],
            ),
        ),
        tool(
            "hub__set_env",
            "Replace the full set of environment variables on one of your servers \
             (encrypted at rest). Pass the complete map; omitted keys are removed. \
             Values may reference ${VAR} (expanded at launch), including \
             ${MCP_CONFIG_FILE} for the config file's path.",
            schema(
                json!({
                    "namespace": {"type": "string"},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}}
                }),
                &["namespace", "env"],
            ),
        ),
        tool(
            "hub__set_config_file",
            "Set or clear the configuration file for one of your stdio servers \
             (encrypted at rest). At launch the file is written into the server's \
             working directory and its path exposed as the MCP_CONFIG_FILE \
             environment variable. Pass an empty 'content' (or omit it) to remove \
             the file.",
            schema(
                json!({
                    "namespace": {"type": "string"},
                    "content": {"type": "string", "description": "File contents; empty/omitted clears it"}
                }),
                &["namespace"],
            ),
        ),
        tool(
            "hub__update_server",
            "Build or update a git-sourced server from its repository (fetches the \
             latest commit and rebuilds its environment). Run this after you push \
             changes; connecting otherwise uses the cached build.",
            schema(json!({"namespace": {"type": "string"}}), &["namespace"]),
        ),
        tool(
            "hub__enable",
            "Enable one of your servers.",
            schema(json!({"namespace": {"type": "string"}}), &["namespace"]),
        ),
        tool(
            "hub__disable",
            "Disable one of your servers.",
            schema(json!({"namespace": {"type": "string"}}), &["namespace"]),
        ),
        tool(
            "hub__remove",
            "Remove one of your servers.",
            schema(json!({"namespace": {"type": "string"}}), &["namespace"]),
        ),
        tool(
            "hub__list_tokens",
            "List your personal access tokens (metadata only — the token secrets \
             are never shown again). Create new ones from the Account web page.",
            schema(json!({}), &[]),
        ),
        tool(
            "hub__revoke_token",
            "Revoke one of your personal access tokens by its id (from \
             hub__list_tokens).",
            schema(json!({"token_id": {"type": "string"}}), &["token_id"]),
        ),
        tool(
            "hub__get_my_client",
            "Show how THIS MCP client (the one making the call) appears in your \
             connected-clients list: its client id, the name it registered with, \
             and any custom name and note you have set for it.",
            schema(json!({}), &[]),
        ),
        tool(
            "hub__set_my_client",
            "Set the custom name and/or note for THIS MCP client only (the one \
             making the call). You cannot change any other client, even your own \
             others. Omitted fields are left unchanged; pass an empty string to \
             clear one. Only available to OAuth clients, not personal access tokens.",
            schema(
                json!({
                    "name": {"type": "string", "description": "Custom display name for this client ('' clears it)"},
                    "note": {"type": "string", "description": "Freeform note for this client ('' clears it)"}
                }),
                &[],
            ),
        ),
    ];
    if admin {
        t.push(tool(
            "hub__list_users",
            "(admin) List all hub users.",
            schema(json!({}), &[]),
        ));
        t.push(tool(
            "hub__create_invite",
            "(admin) Generate a single-use invite code for registration. The \
             plaintext code is returned once and cannot be retrieved later.",
            schema(
                json!({"note": {"type": "string", "description": "Optional label, e.g. who it is for"}}),
                &[],
            ),
        ));
        t.push(tool(
            "hub__list_invites",
            "(admin) List invite codes and their status (metadata only; the \
             codes themselves are never shown again).",
            schema(json!({}), &[]),
        ));
        t.push(tool(
            "hub__revoke_invite",
            "(admin) Revoke an unused invite by its id (the short id from \
             hub__list_invites).",
            schema(json!({"id": {"type": "string"}}), &["id"]),
        ));
        t.push(tool(
            "hub__create_recovery",
            "(admin) Issue a one-time recovery code so a user who lost their \
             passkey can enroll a new one on their existing account. The code is \
             returned once and cannot be retrieved later.",
            schema(json!({"handle": {"type": "string"}}), &["handle"]),
        ));
        t.push(tool(
            "hub__disable_user",
            "(admin) Disable a user: end their sessions, revoke their tokens, and \
             block sign-in. Cannot target yourself or the last admin.",
            schema(json!({"handle": {"type": "string"}}), &["handle"]),
        ));
        t.push(tool(
            "hub__enable_user",
            "(admin) Re-enable a disabled user.",
            schema(json!({"handle": {"type": "string"}}), &["handle"]),
        ));
        t.push(tool(
            "hub__delete_user",
            "(admin) Permanently delete a user and all their servers, secrets and \
             passkeys. Cannot target yourself or the last admin.",
            schema(json!({"handle": {"type": "string"}}), &["handle"]),
        ));
    }
    t
}

/// Whether a (full, `hub__`-prefixed) tool name is a management tool.
pub fn is_management_tool(full_name: &str) -> bool {
    full_name.starts_with("hub__")
}

/// Dispatch a management tool call. `op` is the name without the `hub__` prefix.
/// The caller's OAuth `client_id` (`None` for a personal access token) scopes the
/// self-service `*_my_client` tools. Mutating tools emit a structured audit event.
pub async fn dispatch(
    state: &AppState,
    caller: &Caller<'_>,
    op: &str,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    let args = args.unwrap_or_default();
    let result = run(state, caller, op, &args).await;

    // Log mutating actions (reads return None from `action_for` and are skipped).
    if let Some(action) = action_for(op) {
        let object = if op == "set_my_client" {
            caller.client_id.unwrap_or("").to_string()
        } else {
            audit_object(&args)
        };
        let ev = crate::audit::event(action)
            .actor(caller.handle)
            .actor_id(caller.user_id)
            .client_id(caller.client_id)
            .request(caller.request)
            .object(&object);
        match &result {
            Ok(r) if r.is_error == Some(true) => ev.failed("tool_error"),
            Ok(_) => ev.ok(),
            Err(e) => ev.failed(e.message.as_ref()),
        }
    }
    result
}

async fn run(
    state: &AppState,
    caller: &Caller<'_>,
    op: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let user_id = caller.user_id;
    let admin = caller.admin;
    let client_id = caller.client_id;
    match op {
        "whoami" => whoami(state, user_id).await,
        "get_my_client" => get_my_client(state, user_id, client_id).await,
        "set_my_client" => set_my_client(state, user_id, client_id, args).await,
        "list_my_servers" => list_my_servers(state, user_id).await,
        "add_server" => add_server(state, user_id, args).await,
        "edit_server" => edit_server(state, user_id, args).await,
        "set_env" => set_env(state, user_id, args).await,
        "set_config_file" => set_config_file(state, user_id, args).await,
        "update_server" => update_server(state, user_id, args).await,
        "enable" => set_enabled(state, user_id, args, true).await,
        "disable" => set_enabled(state, user_id, args, false).await,
        "remove" => remove(state, user_id, args).await,
        "list_tokens" => list_tokens(state, user_id).await,
        "revoke_token" => revoke_token(state, user_id, args).await,
        "list_users" => {
            require_admin(admin)?;
            list_users(state).await
        }
        "create_invite" => {
            require_admin(admin)?;
            create_invite(state, user_id, args).await
        }
        "list_invites" => {
            require_admin(admin)?;
            list_invites(state).await
        }
        "revoke_invite" => {
            require_admin(admin)?;
            revoke_invite(state, args).await
        }
        "create_recovery" => {
            require_admin(admin)?;
            create_recovery(state, user_id, args).await
        }
        "disable_user" => {
            require_admin(admin)?;
            set_user_disabled(state, user_id, args, true).await
        }
        "enable_user" => {
            require_admin(admin)?;
            set_user_disabled(state, user_id, args, false).await
        }
        "delete_user" => {
            require_admin(admin)?;
            delete_user(state, user_id, args).await
        }
        other => Err(McpError::invalid_params(
            format!("unknown management tool 'hub__{other}'"),
            None,
        )),
    }
}

/// Map a management op to its audit action verb. Read-only ops return `None`
/// (not logged); mutating ops share the same vocabulary as the web handlers.
fn action_for(op: &str) -> Option<&'static str> {
    Some(match op {
        "add_server" => "server.add",
        "edit_server" => "server.edit",
        "set_env" => "server.set_env",
        "set_config_file" => "server.set_config_file",
        "update_server" => "server.update",
        "enable" => "server.enable",
        "disable" => "server.disable",
        "remove" => "server.remove",
        "revoke_token" => "token.revoke",
        "set_my_client" => "client.label",
        "create_invite" => "invite.create",
        "revoke_invite" => "invite.revoke",
        "create_recovery" => "recovery.create",
        "disable_user" => "user.disable",
        "enable_user" => "user.enable",
        "delete_user" => "user.delete",
        // Reads (whoami, list_*, get_my_client) are not audited.
        _ => return None,
    })
}

/// Best-effort identifier of the object a management call acted on, pulled from
/// the common argument keys.
fn audit_object(args: &JsonObject) -> String {
    for key in ["namespace", "handle", "token_id", "id"] {
        if let Some(v) = args.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
            return v.to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async fn whoami(state: &AppState, user_id: &str) -> Result<CallToolResult, McpError> {
    let user = users::find_by_id(&state.db, user_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| McpError::invalid_request("user not found", None))?;
    let servers = instances::list_for_user(&state.db, user_id)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|i| json!({"namespace": i.namespace, "enabled": i.enabled}))
        .collect::<Vec<_>>();
    ok(json!({
        "handle": user.handle,
        "display_name": user.display_name,
        "admin": user.is_admin,
        "servers": servers,
    }))
}

/// Resolve the calling client's id, rejecting personal-access-token callers
/// (which are not tied to a registered OAuth client).
fn require_client(client_id: Option<&str>) -> Result<&str, McpError> {
    client_id.filter(|c| !c.is_empty()).ok_or_else(|| {
        McpError::invalid_request(
            "this tool is only available to OAuth-authenticated MCP clients, \
             not personal access tokens",
            None,
        )
    })
}

/// `hub__get_my_client` — show the calling client's own connection label.
async fn get_my_client(
    state: &AppState,
    user_id: &str,
    client_id: Option<&str>,
) -> Result<CallToolResult, McpError> {
    let client_id = require_client(client_id)?;
    let (name, note) = crate::oauth::store::get_client_label(&state.db, user_id, client_id)
        .await
        .map_err(internal)?;
    // The name the client declared at registration (DCR metadata), if any.
    let registered_name = crate::oauth::store::get_client(&state.db, client_id)
        .await
        .map_err(internal)?
        .and_then(|c| {
            c.metadata
                .get("client_name")
                .and_then(|v| v.as_str().map(String::from))
        });
    ok(json!({
        "client_id": client_id,
        "registered_name": registered_name,
        "name": name,
        "note": note,
    }))
}

/// `hub__set_my_client` — set the calling client's own name and/or note. Scoped
/// strictly to the authenticated client_id, so a client can never touch another
/// client's label, even one on the same account.
async fn set_my_client(
    state: &AppState,
    user_id: &str,
    client_id: Option<&str>,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let client_id = require_client(client_id)?;
    // Only label a client the user actually has a live connection to (matches
    // the web Account page and avoids labelling stale ids).
    if !crate::oauth::store::user_has_connection(&state.db, user_id, client_id)
        .await
        .map_err(internal)?
    {
        return Err(McpError::invalid_request(
            "this client is not currently connected to your account",
            None,
        ));
    }
    // Partial update: start from the existing label and overwrite only the
    // fields that were supplied. A present-but-empty string clears that field.
    let (mut name, mut note) = crate::oauth::store::get_client_label(&state.db, user_id, client_id)
        .await
        .map_err(internal)?;
    let mut changed = false;
    if let Some(n) = args.get("name").and_then(|v| v.as_str()) {
        name = n.trim().chars().take(60).collect();
        changed = true;
    }
    if let Some(n) = args.get("note").and_then(|v| v.as_str()) {
        note = n.trim().chars().take(200).collect();
        changed = true;
    }
    if !changed {
        return Err(McpError::invalid_params(
            "provide 'name' and/or 'note' to set",
            None,
        ));
    }
    crate::oauth::store::set_client_label(&state.db, user_id, client_id, &name, &note)
        .await
        .map_err(internal)?;
    ok(json!({ "client_id": client_id, "name": name, "note": note }))
}

async fn list_my_servers(state: &AppState, user_id: &str) -> Result<CallToolResult, McpError> {
    let instances = instances::list_for_user(&state.db, user_id)
        .await
        .map_err(internal)?;
    let mut out = Vec::new();
    for i in instances {
        let env_keys = instances::secret_names(&state.db, &i.id)
            .await
            .map_err(internal)?;
        let def = instances::resolve_def(&state.db, &i).await.ok();
        // The exact launch command for stdio/git backends (None for http).
        let command = def.as_ref().and_then(|def| {
            crate::gitsrc::resolved_command(&state.config.env_dir, &i, def).map(|(program, args)| {
                let mut v = vec![program];
                v.extend(args);
                v
            })
        });
        out.push(json!({
            "namespace": i.namespace,
            "display_name": i.display_name,
            "enabled": i.enabled,
            "transport": def.as_ref().map(|d| d.transport.clone()),
            "url": def.as_ref().and_then(|d| d.url.clone()),
            "repo": def.as_ref().and_then(|d| d.repo.clone()),
            "command": command,
            "env_keys": env_keys,
            "build_status": i.build_status,
            "built_commit": i.built_commit,
            "runtime_status": i.runtime_status,
            "runtime_detail": i.runtime_detail,
            "runtime_checked_at": i.runtime_checked_at,
        }));
    }
    ok(json!({ "servers": out }))
}

/// Build a `ServerDef` from add-server args (transport stdio | http).
fn def_from_args(args: &JsonObject, display_name: &str) -> Result<ServerDef, McpError> {
    let transport = req_str(args, "transport")?;
    if !matches!(transport.as_str(), "stdio" | "http") {
        return Err(McpError::invalid_params("transport must be stdio or http", None));
    }
    if transport == "http" {
        let url = req_str(args, "url")?;
        instances::validate_remote_url(&url).map_err(bad_request)?;
        Ok(ServerDef {
            name: display_name.to_string(),
            description: String::new(),
            transport,
            command: None,
            args: vec![],
            url: Some(url),
            runtime: String::new(),
            repo: None,
            git_ref: None,
            entry: None,
            module: None,
        })
    } else {
        let line = req_str(args, "command")?;
        let (command, cmd_args) = instances::parse_command(&line).map_err(bad_request)?;
        if command.is_none() {
            return Err(McpError::invalid_params("a command line is required", None));
        }
        let repo = opt_str(args, "repo");
        if let Some(r) = &repo {
            url::Url::parse(r)
                .map_err(|_| McpError::invalid_params("repo must be a valid URL", None))?;
        }
        let git_ref = repo
            .as_ref()
            .map(|_| opt_str(args, "git_ref").unwrap_or_else(|| "main".into()));
        Ok(ServerDef {
            name: display_name.to_string(),
            description: String::new(),
            transport,
            command,
            args: cmd_args,
            url: None,
            runtime: String::new(),
            repo,
            git_ref,
            entry: None,
            module: None,
        })
    }
}

/// Parse an `env` object argument into a validated KEY=VALUE map.
fn env_from_args(args: &JsonObject) -> Result<BTreeMap<String, String>, McpError> {
    let Some(obj) = args.get("env") else {
        return Ok(BTreeMap::new());
    };
    let obj = obj
        .as_object()
        .ok_or_else(|| McpError::invalid_params("'env' must be an object", None))?;
    let mut text = String::new();
    for (k, v) in obj {
        let value = v
            .as_str()
            .ok_or_else(|| McpError::invalid_params(format!("env '{k}' must be a string"), None))?;
        text.push_str(&format!("{k}={value}\n"));
    }
    instances::parse_env(&text).map_err(bad_request)
}

async fn add_server(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let display_name = opt_str(args, "display_name").unwrap_or_else(|| namespace.clone());
    let def = def_from_args(args, &display_name)?;
    let env = env_from_args(args)?;

    let inst = instances::create(&state.db, user_id, None, Some(&def), &namespace, &display_name)
        .await
        .map_err(bad_request)?;
    instances::replace_env(&state.db, &state.secrets, &inst.id, &env)
        .await
        .map_err(internal)?;
    if let Some(content) = opt_str(args, "config_file").filter(|c| !c.is_empty()) {
        instances::set_config_file(&state.db, &state.secrets, &inst.id, &content)
            .await
            .map_err(internal)?;
    }
    ok(json!({ "added": true, "namespace": inst.namespace }))
}

async fn edit_server(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    let mut def = instances::resolve_def(&state.db, &inst).await.map_err(internal)?;

    if let Some(line) = opt_str(args, "command") {
        let (command, cmd_args) = instances::parse_command(&line).map_err(bad_request)?;
        def.command = command;
        def.args = cmd_args;
    }
    if let Some(url) = opt_str(args, "url") {
        instances::validate_remote_url(&url).map_err(bad_request)?;
        def.url = Some(url);
    }
    if let Some(repo) = opt_str(args, "repo") {
        url::Url::parse(&repo)
            .map_err(|_| McpError::invalid_params("repo must be a valid URL", None))?;
        def.repo = Some(repo);
        if def.git_ref.is_none() {
            def.git_ref = Some("main".into());
        }
    }
    if let Some(git_ref) = opt_str(args, "git_ref") {
        def.git_ref = Some(git_ref);
    }
    instances::update_def(&state.db, &inst.id, &def)
        .await
        .map_err(internal)?;
    ok(json!({ "edited": true, "namespace": namespace }))
}

async fn set_env(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    let env = env_from_args(args)?;
    instances::replace_env(&state.db, &state.secrets, &inst.id, &env)
        .await
        .map_err(internal)?;
    ok(json!({ "set": true, "namespace": namespace, "keys": env.keys().collect::<Vec<_>>() }))
}

async fn set_config_file(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    let content = opt_str(args, "content").unwrap_or_default();
    if content.is_empty() {
        instances::clear_config_file(&state.db, &inst.id)
            .await
            .map_err(internal)?;
        crate::proxy::backend::remove_workdir(&state.config.env_dir, &inst.id);
        ok(json!({ "namespace": namespace, "cleared": true }))
    } else {
        instances::set_config_file(&state.db, &state.secrets, &inst.id, &content)
            .await
            .map_err(internal)?;
        ok(json!({ "namespace": namespace, "set": true }))
    }
}

async fn update_server(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    let def = instances::resolve_def(&state.db, &inst)
        .await
        .map_err(internal)?;
    if !crate::gitsrc::is_git_source(&def) {
        return Err(McpError::invalid_params(
            format!("'{namespace}' is not a git-sourced server"),
            None,
        ));
    }
    // Serialize builds: they are slow and disk-bound.
    let _guard = state.build_lock.lock().await;
    // Fail closed: never build (which runs repo code) as root.
    let sandbox = state.sandbox_or_fail(user_id).await.map_err(internal)?;
    let report = crate::gitsrc::update_instance(
        &state.db,
        &state.config.env_dir,
        &inst,
        &def,
        sandbox.as_ref(),
    )
    .await
    .map_err(bad_request)?;
    ok(json!({
        "namespace": namespace,
        "updated": report.changed,
        "commit": report.commit,
        "previous_commit": report.previous_commit,
        "note": if report.changed { "rebuilt; reconnect to use the new version" } else { "already up to date" },
    }))
}

async fn set_enabled(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
    enabled: bool,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    instances::set_enabled(&state.db, &inst.id, enabled)
        .await
        .map_err(internal)?;
    ok(json!({ "namespace": namespace, "enabled": enabled }))
}

async fn remove(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    instances::delete(&state.db, &inst.id)
        .await
        .map_err(internal)?;
    crate::proxy::backend::remove_workdir(&state.config.env_dir, &inst.id);
    ok(json!({ "removed": true, "namespace": namespace }))
}

async fn list_tokens(state: &AppState, user_id: &str) -> Result<CallToolResult, McpError> {
    let tokens = crate::tokens::list_for_user(&state.db, user_id)
        .await
        .map_err(internal)?;
    let out = tokens
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "created_at": t.created_at,
                "last_used_at": t.last_used_at,
                "expires_at": t.expires_at,
            })
        })
        .collect::<Vec<_>>();
    ok(json!({ "tokens": out }))
}

async fn revoke_token(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let token_id = req_str(args, "token_id")?;
    let revoked = crate::tokens::revoke(&state.db, user_id, &token_id)
        .await
        .map_err(internal)?;
    ok(json!({ "revoked": revoked }))
}

async fn list_users(state: &AppState) -> Result<CallToolResult, McpError> {
    let users = users::list(&state.db).await.map_err(internal)?;
    let out = users
        .into_iter()
        .map(|u| {
            json!({
                "handle": u.handle,
                "display_name": u.display_name,
                "admin": u.is_admin,
                "disabled": u.disabled,
            })
        })
        .collect::<Vec<_>>();
    ok(json!({ "users": out }))
}

/// Resolve the target of an admin user action, enforcing that it exists, is not
/// the caller, and is not the last administrator.
async fn admin_target(
    state: &AppState,
    caller_id: &str,
    handle: &str,
) -> Result<users::User, McpError> {
    let target = users::find_by_handle(&state.db, handle)
        .await
        .map_err(internal)?
        .ok_or_else(|| McpError::invalid_params(format!("no user with handle '{handle}'"), None))?;
    if target.id == caller_id {
        return Err(McpError::invalid_params(
            "you cannot disable or delete your own account",
            None,
        ));
    }
    if target.is_admin && users::count_admins(&state.db).await.map_err(internal)? <= 1 {
        return Err(McpError::invalid_params(
            "cannot disable or delete the last administrator",
            None,
        ));
    }
    Ok(target)
}

async fn set_user_disabled(
    state: &AppState,
    caller_id: &str,
    args: &JsonObject,
    disabled: bool,
) -> Result<CallToolResult, McpError> {
    let handle = req_str(args, "handle")?;
    if disabled {
        let target = admin_target(state, caller_id, &handle).await?;
        crate::web::deactivate_user(state, &target.id)
            .await
            .map_err(internal)?;
    } else {
        // Enabling has no self/last-admin hazard.
        let target = users::find_by_handle(&state.db, &handle)
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                McpError::invalid_params(format!("no user with handle '{handle}'"), None)
            })?;
        users::set_disabled(&state.db, &target.id, false)
            .await
            .map_err(internal)?;
    }
    ok(json!({ "handle": handle, "disabled": disabled }))
}

async fn delete_user(
    state: &AppState,
    caller_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let handle = req_str(args, "handle")?;
    let target = admin_target(state, caller_id, &handle).await?;
    crate::web::purge_user(state, &target.id)
        .await
        .map_err(internal)?;
    ok(json!({ "deleted": true, "handle": handle }))
}

async fn create_invite(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let note = opt_str(args, "note").unwrap_or_default();
    let (code, inv) = invites::create(&state.db, user_id, &note)
        .await
        .map_err(internal)?;
    ok(json!({
        "created": true,
        "code": code,
        "id": inv.short_id(),
        "note": inv.note,
        "note_advice": "single-use; this code is shown only once and cannot be retrieved later",
    }))
}

async fn list_invites(state: &AppState) -> Result<CallToolResult, McpError> {
    let out = invites::list(&state.db)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|i| {
            json!({
                "id": i.short_id(),
                "note": i.note,
                "used": i.used(),
                "created_at": i.created_at,
                "used_at": i.used_at,
            })
        })
        .collect::<Vec<_>>();
    ok(json!({ "invites": out }))
}

async fn revoke_invite(state: &AppState, args: &JsonObject) -> Result<CallToolResult, McpError> {
    let id = req_str(args, "id")?;
    let revoked = invites::revoke(&state.db, &id).await.map_err(internal)?;
    if revoked {
        ok(json!({ "revoked": true, "id": id }))
    } else {
        Err(McpError::invalid_params(
            format!("no unused invite with id '{id}' (used invites cannot be revoked)"),
            None,
        ))
    }
}

async fn create_recovery(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let handle = req_str(args, "handle")?;
    let target = users::find_by_handle(&state.db, &handle)
        .await
        .map_err(internal)?
        .ok_or_else(|| McpError::invalid_params(format!("no user with handle '{handle}'"), None))?;
    let (code, inv) = invites::create_recovery(&state.db, user_id, &target.id)
        .await
        .map_err(internal)?;
    ok(json!({
        "created": true,
        "code": code,
        "id": inv.short_id(),
        "for_handle": target.handle,
        "redeem_at": format!("{}/recover", state.config.base_url),
        "advice": "single-use; shown only once. The user enrolls a new passkey with their handle and this code.",
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn find_instance(
    state: &AppState,
    user_id: &str,
    namespace: &str,
) -> Result<instances::Instance, McpError> {
    instances::list_for_user(&state.db, user_id)
        .await
        .map_err(internal)?
        .into_iter()
        .find(|i| i.namespace == namespace)
        .ok_or_else(|| McpError::invalid_params(format!("no server with namespace '{namespace}'"), None))
}

fn require_admin(admin: bool) -> Result<(), McpError> {
    if admin {
        Ok(())
    } else {
        Err(McpError::invalid_request(
            "this tool requires administrator privileges",
            None,
        ))
    }
}

fn schema(properties: Value, required: &[&str]) -> Arc<JsonObject> {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), "object".into());
    m.insert("properties".into(), properties);
    if !required.is_empty() {
        m.insert(
            "required".into(),
            Value::Array(required.iter().map(|s| Value::from(*s)).collect()),
        );
    }
    Arc::new(m)
}

fn tool(name: &'static str, description: &'static str, input_schema: Arc<JsonObject>) -> Tool {
    Tool {
        name: name.into(),
        title: None,
        description: Some(description.into()),
        input_schema,
        output_schema: None,
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn ok(value: Value) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    Ok(CallToolResult {
        content: vec![Content::text(text)],
        structured_content: Some(value),
        is_error: Some(false),
        meta: None,
    })
}

fn internal(e: anyhow::Error) -> McpError {
    tracing::error!(error = %e, "management tool error");
    McpError::internal_error(e.to_string(), None)
}

fn bad_request(e: anyhow::Error) -> McpError {
    McpError::invalid_params(e.to_string(), None)
}

fn req_str(args: &JsonObject, key: &str) -> Result<String, McpError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpError::invalid_params(format!("'{key}' is required"), None))
}

fn opt_str(args: &JsonObject, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}
