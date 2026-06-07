//! The built-in management MCP interface, exposed under the reserved `hub`
//! namespace. These tools let any MCP client configure the hub programmatically,
//! acting on the token's user. Catalog/user administration is gated on `admin`.

use std::sync::Arc;

use rmcp::model::{CallToolResult, Content, JsonObject, Tool};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};

use crate::catalog::{self, CatalogServer};
use crate::{instances, invites, users};
use crate::AppState;

/// Build the list of management tools available to the caller.
pub fn tools(admin: bool) -> Vec<Tool> {
    let mut t = vec![
        tool("hub__whoami", "Show the current user and their configured servers.", schema(json!({}), &[])),
        tool(
            "hub__list_catalog",
            "List MCP servers available in the hub catalog.",
            schema(json!({}), &[]),
        ),
        tool(
            "hub__list_my_servers",
            "List your configured server instances and their status.",
            schema(json!({}), &[]),
        ),
        tool(
            "hub__add_server",
            "Add a server from the catalog to your account.",
            schema(
                json!({
                    "catalog_slug": {"type": "string", "description": "Catalog entry slug, e.g. 'zabbix'"},
                    "namespace": {"type": "string", "description": "Unique namespace prefix for the server's tools"},
                    "display_name": {"type": "string"}
                }),
                &["catalog_slug", "namespace"],
            ),
        ),
        tool(
            "hub__configure",
            "Set one or more configuration/secret values on one of your servers. \
             For an http remote, set 'MCP_URL' to point it at your own endpoint.",
            schema(
                json!({
                    "namespace": {"type": "string"},
                    "values": {"type": "object", "description": "Map of config key -> value", "additionalProperties": {"type": "string"}}
                }),
                &["namespace", "values"],
            ),
        ),
        tool(
            "hub__set_secret",
            "Set a single encrypted secret value on one of your servers.",
            schema(
                json!({
                    "namespace": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {"type": "string"}
                }),
                &["namespace", "key", "value"],
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
    ];
    if admin {
        t.push(tool(
            "hub__list_users",
            "(admin) List all hub users.",
            schema(json!({}), &[]),
        ));
        t.push(tool(
            "hub__catalog_upsert",
            "(admin) Create or update a catalog entry.",
            schema(
                json!({
                    "slug": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "transport": {"type": "string", "enum": ["stdio", "http"]},
                    "command": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "url": {"type": "string"},
                    "runtime": {"type": "string"},
                    "supported": {"type": "boolean"},
                    "secret_schema": {"type": "array"}
                }),
                &["slug", "name", "transport"],
            ),
        ));
        t.push(tool(
            "hub__catalog_remove",
            "(admin) Remove a catalog entry by slug.",
            schema(json!({"slug": {"type": "string"}}), &["slug"]),
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
pub async fn dispatch(
    state: &AppState,
    user_id: &str,
    admin: bool,
    op: &str,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    let args = args.unwrap_or_default();
    match op {
        "whoami" => whoami(state, user_id).await,
        "list_catalog" => list_catalog(state).await,
        "list_my_servers" => list_my_servers(state, user_id).await,
        "add_server" => add_server(state, user_id, &args).await,
        "configure" => configure(state, user_id, &args).await,
        "set_secret" => set_secret(state, user_id, &args).await,
        "update_server" => update_server(state, user_id, &args).await,
        "enable" => set_enabled(state, user_id, &args, true).await,
        "disable" => set_enabled(state, user_id, &args, false).await,
        "remove" => remove(state, user_id, &args).await,
        "list_users" => {
            require_admin(admin)?;
            list_users(state).await
        }
        "catalog_upsert" => {
            require_admin(admin)?;
            catalog_upsert(state, user_id, &args).await
        }
        "catalog_remove" => {
            require_admin(admin)?;
            catalog_remove(state, &args).await
        }
        "create_invite" => {
            require_admin(admin)?;
            create_invite(state, user_id, &args).await
        }
        "list_invites" => {
            require_admin(admin)?;
            list_invites(state).await
        }
        "revoke_invite" => {
            require_admin(admin)?;
            revoke_invite(state, &args).await
        }
        "create_recovery" => {
            require_admin(admin)?;
            create_recovery(state, user_id, &args).await
        }
        "disable_user" => {
            require_admin(admin)?;
            set_user_disabled(state, user_id, &args, true).await
        }
        "enable_user" => {
            require_admin(admin)?;
            set_user_disabled(state, user_id, &args, false).await
        }
        "delete_user" => {
            require_admin(admin)?;
            delete_user(state, user_id, &args).await
        }
        other => Err(McpError::invalid_params(
            format!("unknown management tool 'hub__{other}'"),
            None,
        )),
    }
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

async fn list_catalog(state: &AppState) -> Result<CallToolResult, McpError> {
    let entries = catalog::list(&state.db).await.map_err(internal)?;
    let out = entries
        .into_iter()
        .map(|e| {
            json!({
                "slug": e.slug,
                "name": e.name,
                "description": e.description,
                "transport": e.transport,
                "supported": e.supported,
                "required_config": e.secret_schema.iter().map(|f| json!({
                    "name": f.name, "label": f.label, "secret": f.secret, "required": f.required
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    ok(json!({ "catalog": out }))
}

async fn list_my_servers(state: &AppState, user_id: &str) -> Result<CallToolResult, McpError> {
    let instances = instances::list_for_user(&state.db, user_id)
        .await
        .map_err(internal)?;
    let mut out = Vec::new();
    for i in instances {
        let secrets = instances::secret_names(&state.db, &i.id)
            .await
            .map_err(internal)?;
        out.push(json!({
            "namespace": i.namespace,
            "display_name": i.display_name,
            "enabled": i.enabled,
            "config": i.config,
            "secrets_set": secrets,
            "build_status": i.build_status,
            "built_commit": i.built_commit,
            "runtime_status": i.runtime_status,
            "runtime_detail": i.runtime_detail,
            "runtime_checked_at": i.runtime_checked_at,
        }));
    }
    ok(json!({ "servers": out }))
}

async fn add_server(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let slug = req_str(args, "catalog_slug")?;
    let namespace = req_str(args, "namespace")?;
    let display_name = opt_str(args, "display_name").unwrap_or_else(|| namespace.clone());

    let entry = catalog::get_by_slug(&state.db, &slug)
        .await
        .map_err(internal)?
        .ok_or_else(|| McpError::invalid_params(format!("no catalog entry '{slug}'"), None))?;
    if !entry.supported {
        return Err(McpError::invalid_params(
            format!("catalog entry '{slug}' is not supported in this version"),
            None,
        ));
    }
    let inst =
        instances::create(&state.db, user_id, Some(&entry.id), None, &namespace, &display_name)
            .await
            .map_err(bad_request)?;
    ok(json!({ "added": true, "namespace": inst.namespace, "next": "use hub__configure or hub__set_secret to provide credentials, then hub__enable" }))
}

async fn configure(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let values = args
        .get("values")
        .and_then(|v| v.as_object())
        .ok_or_else(|| McpError::invalid_params("'values' must be an object", None))?;

    let inst = find_instance(state, user_id, &namespace).await?;
    let def = instances::resolve_def(&state.db, &inst)
        .await
        .map_err(internal)?;

    for (key, val) in values {
        let value = val.as_str().ok_or_else(|| {
            McpError::invalid_params(format!("value for '{key}' must be a string"), None)
        })?;
        // The remote URL of an http backend is settable on any http instance
        // (it is a connection target, not injected process environment).
        if key == instances::URL_KEY && def.transport == "http" {
            instances::validate_remote_url(value).map_err(bad_request)?;
            instances::set_config_value(&state.db, &inst.id, key, value)
                .await
                .map_err(internal)?;
            continue;
        }
        // Only keys declared by the server's schema may be set. These keys
        // become process environment variables, so accepting arbitrary names
        // would let a user inject PYTHONSTARTUP / NODE_OPTIONS / LD_PRELOAD etc.
        let field = def.secret_schema.iter().find(|f| &f.name == key).ok_or_else(|| {
            McpError::invalid_params(
                format!("'{key}' is not a configuration key for this server"),
                None,
            )
        })?;
        if field.secret {
            instances::set_secret(&state.db, &state.secrets, &inst.id, key, value)
                .await
                .map_err(internal)?;
        } else {
            instances::set_config_value(&state.db, &inst.id, key, value)
                .await
                .map_err(internal)?;
        }
    }
    ok(json!({ "configured": true, "namespace": namespace, "keys": values.keys().collect::<Vec<_>>() }))
}

async fn set_secret(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let namespace = req_str(args, "namespace")?;
    let key = req_str(args, "key")?;
    let value = req_str(args, "value")?;
    let inst = find_instance(state, user_id, &namespace).await?;
    let def = instances::resolve_def(&state.db, &inst)
        .await
        .map_err(internal)?;
    // The key must be a declared secret field (see configure() for why).
    let declared = def
        .secret_schema
        .iter()
        .any(|f| f.name == key && f.secret);
    if !declared {
        return Err(McpError::invalid_params(
            format!("'{key}' is not a secret field for this server"),
            None,
        ));
    }
    instances::set_secret(&state.db, &state.secrets, &inst.id, &key, &value)
        .await
        .map_err(internal)?;
    ok(json!({ "set": true, "namespace": namespace, "key": key }))
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
    let report = crate::gitsrc::update_instance(&state.db, &state.config.env_dir, &inst, &def)
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
    ok(json!({ "removed": true, "namespace": namespace }))
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

async fn catalog_upsert(
    state: &AppState,
    user_id: &str,
    args: &JsonObject,
) -> Result<CallToolResult, McpError> {
    let mut server: CatalogServer =
        serde_json::from_value(Value::Object(args.clone())).map_err(|e| {
            McpError::invalid_params(format!("invalid catalog entry: {e}"), None)
        })?;
    server.is_builtin = false;
    let id = catalog::upsert(&state.db, &server, Some(user_id))
        .await
        .map_err(internal)?;
    ok(json!({ "upserted": true, "slug": server.slug, "id": id }))
}

async fn catalog_remove(state: &AppState, args: &JsonObject) -> Result<CallToolResult, McpError> {
    let slug = req_str(args, "slug")?;
    let entry = catalog::get_by_slug(&state.db, &slug)
        .await
        .map_err(internal)?
        .ok_or_else(|| McpError::invalid_params(format!("no catalog entry '{slug}'"), None))?;
    catalog::delete(&state.db, &entry.id).await.map_err(internal)?;
    ok(json!({ "removed": true, "slug": slug }))
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
