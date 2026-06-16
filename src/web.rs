//! Server-rendered web UI pages.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use axum::Form;
use serde::Deserialize;

use crate::auth::session;
use crate::auth::{AuthUser, MaybeUser, RequestInfo};
use crate::{instances, invites, users, AppState};

/// Emit a successful-action audit event for a web (browser-session) actor.
fn audit_ok(action: &str, user: &users::User, headers: &HeaderMap, object: &str) {
    let info = RequestInfo::from_headers(headers);
    crate::audit::event(action)
        .actor(&user.handle)
        .actor_id(&user.id)
        .request(&info)
        .object(object)
        .ok();
}

/// Emit a refused-action audit event (CSRF / authz / validation) for a web actor.
fn audit_denied(action: &str, user: &users::User, headers: &HeaderMap, object: &str, reason: &str) {
    let info = RequestInfo::from_headers(headers);
    crate::audit::event(action)
        .actor(&user.handle)
        .actor_id(&user.id)
        .request(&info)
        .object(object)
        .denied(reason);
}

/// Optional `?next=` redirect target carried into the login/register pages.
#[derive(Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    pub next: Option<String>,
}

/// Wrap page content in the shared HTML shell.
fn page_with(title: &str, body: &str, class: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} · MCP Hub</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="{class}">{body}</main>
  <script src="/static/auth.js"></script>
</body>
</html>"#
    ))
}

/// A standard, narrow page — used for the auth flows and one-off confirmations.
fn page(title: &str, body: &str) -> Html<String> {
    page_with(title, body, "card")
}

/// A wider page for content-heavy views (dashboard, account, users, invites,
/// server detail) whose lists and forms are cramped in the narrow card.
fn page_wide(title: &str, body: &str) -> Html<String> {
    page_with(title, body, "card wide")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/// `/` — dashboard (requires login).
pub async fn dashboard(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let admin_badge = if user.is_admin {
        r#"<span class="badge">admin</span>"#
    } else {
        ""
    };

    let instances = instances::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();

    let mut rows = String::new();
    if instances.is_empty() {
        rows.push_str(r#"<p class="muted">No servers yet. Add one to get started.</p>"#);
    } else {
        rows.push_str("<ul class=\"servers\">");
        for inst in &instances {
            let status = if inst.enabled { "enabled" } else { "disabled" };
            rows.push_str(&format!(
                r#"<li><a href="/servers/{id}"><code>{ns}</code> · {name}</a> <span class="muted">{status}</span></li>"#,
                id = esc(&inst.id),
                ns = esc(&inst.namespace),
                name = esc(&inst.display_name),
                status = status,
            ));
        }
        rows.push_str("</ul>");
    }

    let body = format!(
        r#"<header class="row">
  <h1>MCP Hub</h1>
  <div class="row">
    <a href="/account">Account</a>
    <form method="post" action="/logout">{csrf}<button class="ghost">Sign out</button></form>
  </div>
</header>
<p>Signed in as <strong>{handle}</strong> {badge}</p>
<section>
  <div class="row"><h2>Your MCP servers</h2><a href="/servers/new">+ Add a server</a></div>
  {rows}
</section>
{admin_section}
<p class="muted">Your MCP endpoint: <code>{mcp}</code></p>"#,
        csrf = csrf,
        handle = esc(&user.handle),
        badge = admin_badge,
        rows = rows,
        admin_section = if user.is_admin {
            r#"<section><div class="row"><h2>Administration</h2><span><a href="/invites">Invites</a> · <a href="/users">Users</a> · <a href="/stats">Stats</a></span></div></section>"#
        } else {
            ""
        },
        mcp = esc(&state.config.mcp_url()),
    );
    page_wide("Dashboard", &body).into_response()
}

// ---------------------------------------------------------------------------
// Adding + editing a user's own servers
// ---------------------------------------------------------------------------

/// Editable fields shared by the add and edit forms. `transport` is a `<select>`
/// only when creating (it is fixed once a server exists).
#[allow(clippy::too_many_arguments)]
fn server_fields(
    transport: &str,
    transport_select: bool,
    command_line: &str,
    repo: &str,
    git_ref: &str,
    url: &str,
    env: &str,
    config_file: &str,
) -> String {
    let stdio_hidden = if transport == "http" { "hidden" } else { "" };
    let http_hidden = if transport == "http" { "" } else { "hidden" };
    let transport_field = if transport_select {
        format!(
            r#"<label>Transport<select name="transport" id="transport-select">
    <option value="stdio" {s}>stdio (run a command)</option>
    <option value="http" {h}>http (remote URL)</option>
  </select></label>"#,
            s = if transport == "http" { "" } else { "selected" },
            h = if transport == "http" { "selected" } else { "" },
        )
    } else {
        format!(
            r#"<p class="muted">Transport: <code>{}</code></p><input type="hidden" name="transport" value="{0}">"#,
            esc(transport)
        )
    };
    format!(
        r#"{transport_field}
  <div class="stdio-only {stdio_hidden}">
    <label>Command line<input name="command" value="{cmd}" placeholder="uvx your-mcp-server"></label>
    <label>Repository (optional — builds a cached venv from a git repo)<input name="repo" value="{repo}" placeholder="https://github.com/you/your-mcp"></label>
    <label>Git ref (branch or tag)<input name="git_ref" value="{git_ref}" placeholder="main"></label>
    <label>Config file (optional — written to the server's working directory; its path is exposed as <code>$MCP_CONFIG_FILE</code>)<textarea name="config_file" rows="6" placeholder="(paste a config file the server needs on disk)">{config_file}</textarea></label>
  </div>
  <div class="http-only {http_hidden}">
    <label>Remote URL<input name="url" value="{url}" placeholder="https://server.example.com/mcp"></label>
  </div>
  <label>Environment variables (one <code>KEY=VALUE</code> per line; values may reference <code>${{VAR}}</code>, e.g. <code>GOOGLE_APPLICATION_CREDENTIALS=${{MCP_CONFIG_FILE}}</code>)<textarea name="env" rows="6" placeholder="API_TOKEN=...">{env}</textarea></label>"#,
        transport_field = transport_field,
        stdio_hidden = stdio_hidden,
        http_hidden = http_hidden,
        cmd = esc(command_line),
        repo = esc(repo),
        git_ref = esc(git_ref),
        url = esc(url),
        env = esc(env),
        config_file = esc(config_file),
    )
}

/// `/servers/new` — form to add a server (any user).
pub async fn new_server(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let body = format!(
        r#"<header class="row"><h1>Add a server</h1><a href="/">← Back</a></header>
<form id="server-form" method="post" action="/servers/create">
  {csrf}
  <label>Display name<input name="display_name" required></label>
  <label>Namespace (tool prefix, e.g. <code>zabbix</code>)<input name="namespace" required></label>
  {fields}
  <button type="submit">Add server</button>
</form>"#,
        csrf = csrf,
        fields = server_fields("stdio", true, "", "", "", "", "", ""),
    );
    page("Add a server", &body).into_response()
}

/// Form body for creating a server.
#[derive(Deserialize)]
pub struct CreateServerForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub git_ref: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub config_file: String,
}

/// `POST /servers/create`
pub async fn create_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<CreateServerForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.add", &user, &headers, form.namespace.trim(), "csrf");
        return forbidden();
    }
    let (def, env) = match def_from_form(&form) {
        Ok(v) => v,
        Err(e) => return error_page(&e),
    };
    let display = if form.display_name.trim().is_empty() {
        form.namespace.trim()
    } else {
        form.display_name.trim()
    };
    let inst = match instances::create(
        &state.db,
        &user.id,
        None,
        Some(&def),
        form.namespace.trim(),
        display,
    )
    .await
    {
        Ok(i) => i,
        Err(e) => return error_page(&e.to_string()),
    };
    if let Err(e) = instances::replace_env(&state.db, &state.secrets, &inst.id, &env).await {
        return error_page(&e.to_string());
    }
    if let Err(e) = apply_config_file(&state, &inst.id, &form.config_file).await {
        return error_page(&e.to_string());
    }
    audit_ok("server.add", &user, &headers, form.namespace.trim());
    Redirect::to(&format!("/servers/{}", inst.id)).into_response()
}

/// Store or clear an instance's config file from a submitted form value. A blank
/// value clears it (and removes any on-disk copy left in the working directory).
async fn apply_config_file(
    state: &AppState,
    instance_id: &str,
    content: &str,
) -> anyhow::Result<()> {
    if content.trim().is_empty() {
        instances::clear_config_file(&state.db, instance_id).await?;
        crate::proxy::backend::remove_workdir(&state.config.env_dir, instance_id);
    } else {
        instances::set_config_file(&state.db, &state.secrets, instance_id, content).await?;
    }
    Ok(())
}

/// Build a `ServerDef` + env map from submitted command/url/repo/env fields.
fn def_from_form(
    form: &CreateServerForm,
) -> Result<(instances::ServerDef, std::collections::BTreeMap<String, String>), String> {
    let transport = form.transport.trim();
    if !matches!(transport, "stdio" | "http") {
        return Err("transport must be stdio or http".into());
    }
    let env = instances::parse_env(&form.env).map_err(|e| e.to_string())?;
    let opt = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    let (command, args, url, repo, git_ref) = if transport == "http" {
        let url = opt(&form.url).ok_or("a remote URL is required for an http server")?;
        instances::validate_remote_url(&url).map_err(|e| e.to_string())?;
        (None, Vec::new(), Some(url), None, None)
    } else {
        let (command, args) =
            instances::parse_command(&form.command).map_err(|e| e.to_string())?;
        if command.is_none() {
            return Err("a command line is required for a stdio server".into());
        }
        let repo = opt(&form.repo);
        if let Some(r) = &repo {
            url::Url::parse(r).map_err(|_| "repository must be a valid URL".to_string())?;
        }
        let git_ref = if repo.is_some() {
            Some(opt(&form.git_ref).unwrap_or_else(|| "main".into()))
        } else {
            None
        };
        (command, args, None, repo, git_ref)
    };

    Ok((
        instances::ServerDef {
            name: form.display_name.trim().to_string(),
            description: String::new(),
            transport: transport.to_string(),
            command,
            args,
            url,
            runtime: String::new(),
            repo,
            git_ref,
            entry: None,
            module: None,
        },
        env,
    ))
}

/// A form carrying only the CSRF token (for button-only POSTs).
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf: String,
}

/// Render a 403 page for a missing/invalid CSRF token.
fn forbidden() -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        page(
            "Blocked",
            r#"<h1>Request blocked</h1><p>Invalid or missing security token. Reload the page and try again.</p><p><a href="/">← Back</a></p>"#,
        ),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Instance detail + configuration
// ---------------------------------------------------------------------------

/// `/servers/{id}` — configure an instance.
pub async fn server_detail(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let def = match instances::resolve_def(&state.db, &inst).await {
        Ok(d) => d,
        Err(e) => return error_page(&e.to_string()),
    };
    let env = instances::env_for_edit(&state.db, &state.secrets, &inst.id)
        .await
        .unwrap_or_default();
    let config_file = instances::config_file_for_edit(&state.db, &state.secrets, &inst.id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let fields = server_fields(
        &def.transport,
        false,
        &instances::render_command(&def.command, &def.args),
        def.repo.as_deref().unwrap_or(""),
        def.git_ref.as_deref().unwrap_or(""),
        def.url.as_deref().unwrap_or(""),
        &instances::render_env(&env),
        &config_file,
    );

    let toggle = if inst.enabled {
        format!(r#"<form method="post" action="/servers/{{id}}/disable">{csrf}<button class="ghost">Disable</button></form>"#)
    } else {
        format!(r#"<form method="post" action="/servers/{{id}}/enable">{csrf}<button class="ghost">Enable</button></form>"#)
    }
    .replace("{id}", &esc(&inst.id));

    // Git-sourced servers get a build status line and an Update button.
    let git_section = if crate::gitsrc::is_git_source(&def) {
        let commit = inst
            .built_commit
            .as_deref()
            .map(|c| &c[..c.len().min(10)])
            .unwrap_or("—");
        format!(
            r#"<section>
  <h2>Source</h2>
  <p class="muted">Repo <code>{repo}</code> @ <code>{git_ref}</code> · build <code>{status}</code> · commit <code>{commit}</code></p>
  <form method="post" action="/servers/{id}/update">{csrf}<button>Update from repository</button></form>
</section>"#,
            repo = esc(def.repo.as_deref().unwrap_or("?")),
            git_ref = esc(def.git_ref.as_deref().unwrap_or("main")),
            status = esc(&inst.build_status),
            commit = esc(commit),
            id = esc(&inst.id),
            csrf = csrf,
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<header class="row"><h1>{name}</h1><a href="/">← Back</a></header>
<p class="muted">Namespace <code>{ns}</code> · {transport} · {status}</p>
{tabs}
{runtime}
{command}
<form method="post" action="/servers/{id}/config">
  {csrf}
  {fields}
  <button type="submit">Save configuration</button>
</form>
{git_section}
<div class="row" style="margin-top:18px">
  <form method="post" action="/servers/{id}/test">{csrf}<button class="ghost">Test connection</button></form>
  {toggle}
  <form method="post" action="/servers/{id}/delete" data-confirm="Remove this server?">{csrf}<button class="ghost danger">Remove</button></form>
</div>"#,
        name = esc(&inst.display_name),
        ns = esc(&inst.namespace),
        transport = esc(&def.transport),
        status = if inst.enabled { "enabled" } else { "disabled" },
        tabs = server_tabs(&inst.id, "config"),
        runtime = runtime_banner(&inst),
        command = command_line(&state, &inst, &def),
        id = esc(&inst.id),
        csrf = csrf,
        fields = fields,
        git_section = git_section,
        toggle = toggle,
    );
    page_wide(&inst.display_name, &body).into_response()
}

/// For stdio/git backends, show the exact command that will be executed.
fn command_line(
    state: &AppState,
    inst: &instances::Instance,
    def: &instances::ServerDef,
) -> String {
    match crate::gitsrc::resolved_command(&state.config.env_dir, inst, def) {
        Some((program, args)) => {
            // Quote any argument containing whitespace so the line is unambiguous.
            let mut parts = vec![program];
            parts.extend(args);
            let rendered = parts
                .iter()
                .map(|p| {
                    if p.chars().any(char::is_whitespace) {
                        format!("\"{p}\"")
                    } else {
                        p.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                r#"<p class="muted">Command</p><pre class="cmd"><code>{}</code></pre>"#,
                esc(&rendered)
            )
        }
        // git source not built yet → nothing exact to show (the Source section
        // already explains it needs a build).
        None if def.transport == "git" => String::new(),
        None => String::new(),
    }
}

/// Two-tab nav for the server pages; the active tab is just a styled link.
fn server_tabs(id: &str, active: &str) -> String {
    let cls = |t: &str| if t == active { r#" class="active""# } else { "" };
    format!(
        r#"<nav class="tabs"><a href="/servers/{id}"{a}>Configuration</a><a href="/servers/{id}/capabilities"{b}>Capabilities</a></nav>"#,
        id = esc(id),
        a = cls("config"),
        b = cls("capabilities"),
    )
}

/// Render the backend's last connection outcome as a coloured banner.
fn runtime_banner(inst: &instances::Instance) -> String {
    let when = inst
        .runtime_checked_at
        .map(|t| format!(" · checked {}", ago(crate::util::now_unix() - t)))
        .unwrap_or_default();
    let (class, label) = match inst.runtime_status.as_str() {
        "ok" => ("ok", "running".to_string()),
        "error" => ("danger", "error".to_string()),
        "unbuilt" => ("warn", "not built".to_string()),
        "skipped" => ("warn", "not started".to_string()),
        _ => return String::new(), // 'unknown' before the first connection
    };
    // A single-line reason sits inline; a multi-line one (e.g. captured stderr
    // from a Test connection) goes in its own block so it stays readable.
    let detail = match &inst.runtime_detail {
        Some(d) if d.contains('\n') => {
            format!("{when}<pre class=\"cmd\"><code>{}</code></pre>", esc(d))
        }
        Some(d) if !d.is_empty() => format!(": {}{when}", esc(d)),
        _ => when,
    };
    format!(
        r#"<div class="status status-{class}">Backend {label}{detail}</div>"#,
        class = class,
        label = label,
        detail = detail,
    )
}

/// `POST /servers/{id}/config` — save an edit to the server's def + env.
pub async fn save_config(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CreateServerForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.edit", &user, &headers, &id, "csrf");
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let existing = match instances::resolve_def(&state.db, &inst).await {
        Ok(d) => d,
        Err(e) => return error_page(&e.to_string()),
    };
    // Transport and namespace are fixed on edit; the form carries the rest.
    let mut form = form;
    form.transport = existing.transport.clone();
    let (mut def, env) = match def_from_form(&form) {
        Ok(v) => v,
        Err(e) => return error_page(&e),
    };
    // Preserve the display name (not edited on this form).
    def.name = existing.name.clone();
    if let Err(e) = instances::update_def(&state.db, &inst.id, &def).await {
        return error_page(&e.to_string());
    }
    if let Err(e) = instances::replace_env(&state.db, &state.secrets, &inst.id, &env).await {
        return error_page(&e.to_string());
    }
    if let Err(e) = apply_config_file(&state, &inst.id, &form.config_file).await {
        return error_page(&e.to_string());
    }
    audit_ok("server.edit", &user, &headers, &inst.namespace);
    Redirect::to(&format!("/servers/{id}")).into_response()
}

async fn set_enabled_and_redirect(
    state: &AppState,
    user: &users::User,
    headers: &HeaderMap,
    id: &str,
    enabled: bool,
) -> Response {
    let Some(inst) = instances::get_owned(&state.db, id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let _ = instances::set_enabled(&state.db, id, enabled).await;
    let action = if enabled { "server.enable" } else { "server.disable" };
    audit_ok(action, user, headers, &inst.namespace);
    Redirect::to(&format!("/servers/{id}")).into_response()
}

pub async fn enable_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.enable", &user, &headers, &id, "csrf");
        return forbidden();
    }
    set_enabled_and_redirect(&state, &user, &headers, &id, true).await
}

pub async fn disable_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.disable", &user, &headers, &id, "csrf");
        return forbidden();
    }
    set_enabled_and_redirect(&state, &user, &headers, &id, false).await
}

pub async fn delete_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.remove", &user, &headers, &id, "csrf");
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let _ = instances::delete(&state.db, &id).await;
    crate::gitsrc::remove_env(&state.config.env_dir, &id);
    crate::proxy::backend::remove_workdir(&state.config.env_dir, &id);
    audit_ok("server.remove", &user, &headers, &inst.namespace);
    Redirect::to("/").into_response()
}

/// `POST /servers/{id}/update` — (re)build a git-sourced server.
pub async fn update_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.update", &user, &headers, &id, "csrf");
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let def = match instances::resolve_def(&state.db, &inst).await {
        Ok(d) => d,
        Err(e) => return error_page(&e.to_string()),
    };
    if !crate::gitsrc::is_git_source(&def) {
        return error_page("this server is not git-sourced");
    }
    let _guard = state.build_lock.lock().await;
    let sandbox = match state.sandbox_or_fail(&user.id).await {
        Ok(s) => s,
        Err(e) => return error_page(&format!("sandbox unavailable: {e:#}")),
    };
    match crate::gitsrc::update_instance(&state.db, &state.config.env_dir, &inst, &def, sandbox.as_ref()).await {
        Ok(_) => {
            audit_ok("server.update", &user, &headers, &inst.namespace);
            Redirect::to(&format!("/servers/{id}")).into_response()
        }
        Err(e) => {
            audit_denied("server.update", &user, &headers, &inst.namespace, "error");
            error_page(&format!("update failed: {e}"))
        }
    }
}

/// `POST /servers/{id}/test` — start the backend once, right now, record the
/// outcome (with the subprocess's own stderr on failure), then return to the
/// server page. Lets a user verify a server actually runs without opening a
/// fresh MCP client connection.
pub async fn test_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.test", &user, &headers, &id, "csrf");
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let (status, detail, snapshot) = probe_instance(&state, &user.id, &inst).await;
    let _ = instances::set_runtime_status(&state.db, &inst.id, status, detail.as_deref()).await;
    if let Some(snap) = &snapshot {
        let _ = instances::set_capabilities_snapshot(&state.db, &inst.id, snap).await;
    }
    if status == "ok" {
        audit_ok("server.test", &user, &headers, &inst.namespace);
    } else {
        audit_denied("server.test", &user, &headers, &inst.namespace, status);
    }
    Redirect::to(&format!("/servers/{id}")).into_response()
}

/// Resolve and start one instance once, mirroring the proxy's per-backend launch
/// logic, and return a `(status, detail)` pair suitable for
/// [`instances::set_runtime_status`].
async fn probe_instance(
    state: &AppState,
    user_id: &str,
    inst: &instances::Instance,
) -> (
    &'static str,
    Option<String>,
    Option<instances::CapabilitiesSnapshot>,
) {
    let mut def = match instances::resolve_def(&state.db, inst).await {
        Ok(d) => d,
        Err(e) => return ("error", Some(format!("resolve failed: {e:#}")), None),
    };
    if def.transport == "http" {
        let url = def.url.as_deref().unwrap_or("").trim();
        if url.is_empty() {
            return ("error", Some("no remote URL set".into()), None);
        }
        if let Err(e) = instances::check_backend_host(url, state.config.block_private_backend_ips) {
            return ("error", Some(format!("{e}")), None);
        }
    }
    // Fail closed: resolve the sandbox identity up front (used for both the
    // self-heal rebuild and the probe spawn) rather than ever running as root.
    let sandbox = match state.sandbox_or_fail(user_id).await {
        Ok(s) => s,
        Err(e) => return ("error", Some(format!("sandbox unavailable: {e:#}")), None),
    };
    // Git-sourced backends run from their prebuilt virtualenv; rewrite to a
    // direct stdio exec, or report that they need building first.
    if crate::gitsrc::is_git_source(&def) {
        let ready = inst.build_status == "ready"
            && crate::gitsrc::env_path(&state.config.env_dir, &inst.id).exists();
        if !ready {
            return (
                "unbuilt",
                Some("not built yet; run “Update from repository” first".into()),
                None,
            );
        }
        // A venv built before the interpreter was relocated cannot exec under
        // the sandbox; rebuild it transparently so testing just works.
        if crate::gitsrc::venv_is_stale(&state.config.env_dir, inst, &def) {
            let _guard = state.build_lock.lock().await;
            if let Err(e) = crate::gitsrc::update_instance(
                &state.db,
                &state.config.env_dir,
                inst,
                &def,
                sandbox.as_ref(),
            )
            .await
            {
                return ("error", Some(format!("rebuild failed: {e:#}")), None);
            }
        }
        match crate::gitsrc::launch_command(&state.config.env_dir, &inst.id, &def) {
            Ok((program, args)) => {
                def.transport = "stdio".into();
                def.command = Some(program);
                def.args = args;
            }
            Err(e) => return ("error", Some(format!("git launch failed: {e:#}")), None),
        }
    }
    let env = match instances::resolved_env(&state.db, &state.secrets, inst).await {
        Ok(e) => e,
        Err(e) => return ("error", Some(format!("config error: {e:#}")), None),
    };
    let config_file = match instances::resolved_config_file(&state.db, &state.secrets, &inst.id).await
    {
        Ok(c) => c,
        Err(e) => return ("error", Some(format!("config error: {e:#}")), None),
    };
    match crate::proxy::backend::Backend::probe(
        &def,
        &env,
        sandbox.as_ref(),
        &state.config.env_dir,
        &inst.id,
        config_file.as_deref(),
        state.config.child_limits,
    )
    .await
    {
        Ok(snap) => ("ok", None, Some(snap)),
        Err(e) => ("error", Some(format!("failed to start: {e:#}")), None),
    }
}

/// `/servers/{id}/capabilities` — the Capabilities tab: everything the backend
/// advertised to MCP clients the last time it was probed, rendered from the
/// cached snapshot.
pub async fn server_capabilities(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let def = match instances::resolve_def(&state.db, &inst).await {
        Ok(d) => d,
        Err(e) => return error_page(&e.to_string()),
    };
    let snapshot = instances::get_capabilities_snapshot(&state.db, &inst.id)
        .await
        .unwrap_or_default();

    let fetched = match &snapshot {
        Some(s) => format!("Fetched {}", ago(crate::util::now_unix() - s.fetched_at)),
        None => "Never fetched".to_string(),
    };
    let content = match &snapshot {
        Some(s) => render_snapshot(s, &inst.namespace),
        None => r#"<p class="muted">No capability snapshot yet. Click Refresh (or Test connection on the Configuration tab) to fetch what this server advertises.</p>"#.to_string(),
    };

    let body = format!(
        r#"<header class="row"><h1>{name}</h1><a href="/">← Back</a></header>
<p class="muted">Namespace <code>{ns}</code> · {transport} · {status}</p>
{tabs}
{runtime}
<div class="row">
  <p class="muted">{fetched}</p>
  <form method="post" action="/servers/{id}/capabilities/refresh">{csrf}<button class="ghost inline">Refresh</button></form>
</div>
{content}"#,
        name = esc(&inst.display_name),
        ns = esc(&inst.namespace),
        transport = esc(&def.transport),
        status = if inst.enabled { "enabled" } else { "disabled" },
        tabs = server_tabs(&inst.id, "capabilities"),
        runtime = runtime_banner(&inst),
        fetched = esc(&fetched),
        id = esc(&inst.id),
        csrf = csrf,
        content = content,
    );
    page_wide(&inst.display_name, &body).into_response()
}

/// `POST /servers/{id}/capabilities/refresh` — reconnect to the backend, store
/// a fresh capabilities snapshot, and return to the Capabilities tab. On
/// failure the runtime banner shows the error and any stale snapshot stays.
pub async fn refresh_capabilities(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("server.capabilities", &user, &headers, &id, "csrf");
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let (status, detail, snapshot) = probe_instance(&state, &user.id, &inst).await;
    let _ = instances::set_runtime_status(&state.db, &inst.id, status, detail.as_deref()).await;
    if let Some(snap) = &snapshot {
        let _ = instances::set_capabilities_snapshot(&state.db, &inst.id, snap).await;
    }
    if status == "ok" {
        audit_ok("server.capabilities", &user, &headers, &inst.namespace);
    } else {
        audit_denied("server.capabilities", &user, &headers, &inst.namespace, status);
    }
    Redirect::to(&format!("/servers/{id}/capabilities")).into_response()
}

/// Truncate a one-line summary at ~`max` characters on a char boundary.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{}…", cut.trim_end())
    }
}

/// Pretty-print a JSON schema object for an expandable `<pre>` block.
fn schema_block(label: &str, schema: &serde_json::Map<String, serde_json::Value>) -> String {
    let json = serde_json::to_string_pretty(schema).unwrap_or_default();
    format!(
        r#"<p class="muted">{label}</p><pre class="cmd"><code>{}</code></pre>"#,
        esc(&json)
    )
}

/// Render a cached [`instances::CapabilitiesSnapshot`] as the body of the
/// Capabilities tab: server summary, instructions, then tools / prompts /
/// resources with `<details>` expanders.
fn render_snapshot(snap: &instances::CapabilitiesSnapshot, namespace: &str) -> String {
    let caps = &snap.server.capabilities;
    let mut out = String::new();

    // --- Server summary -----------------------------------------------------
    let mut badges = String::new();
    let mut badge = |label: String| {
        badges.push_str(&format!(r#"<span class="badge">{}</span> "#, esc(&label)));
    };
    if let Some(t) = &caps.tools {
        badge(if t.list_changed == Some(true) { "tools · listChanged".into() } else { "tools".into() });
    }
    if let Some(p) = &caps.prompts {
        badge(if p.list_changed == Some(true) { "prompts · listChanged".into() } else { "prompts".into() });
    }
    if let Some(r) = &caps.resources {
        let mut label = "resources".to_string();
        if r.subscribe == Some(true) {
            label.push_str(" · subscribe");
        }
        if r.list_changed == Some(true) {
            label.push_str(" · listChanged");
        }
        badge(label);
    }
    if caps.logging.is_some() {
        badge("logging".into());
    }
    if caps.completions.is_some() {
        badge("completions".into());
    }
    if caps.experimental.is_some() {
        badge("experimental".into());
    }
    if badges.is_empty() {
        badges = r#"<span class="muted">none advertised</span>"#.into();
    }

    let info = &snap.server.server_info;
    let title_row = match &info.title {
        Some(t) if !t.is_empty() => format!(
            "<tr><th>Title</th><td>{}</td></tr>",
            esc(t)
        ),
        _ => String::new(),
    };
    out.push_str(&format!(
        r#"<section>
<h2>Server</h2>
<table class="invites"><tbody>
<tr><th>Name</th><td>{name}</td></tr>
{title_row}
<tr><th>Version</th><td>{version}</td></tr>
<tr><th>Protocol</th><td>{protocol}</td></tr>
<tr><th>Capabilities</th><td>{badges}</td></tr>
</tbody></table>
</section>"#,
        name = esc(&info.name),
        title_row = title_row,
        version = esc(&info.version),
        protocol = esc(&snap.server.protocol_version.to_string()),
        badges = badges,
    ));

    if let Some(instructions) = snap.server.instructions.as_deref().filter(|s| !s.trim().is_empty()) {
        out.push_str(&format!(
            r#"<section><h2>Instructions</h2><pre class="cmd"><code>{}</code></pre></section>"#,
            esc(instructions)
        ));
    }

    // --- Tools ---------------------------------------------------------------
    out.push_str(&format!("<section><h2>Tools ({})</h2>", snap.tools.len()));
    if caps.tools.is_none() {
        out.push_str(r#"<p class="muted">Not supported by this server.</p>"#);
    } else if snap.tools.is_empty() {
        out.push_str(r#"<p class="muted">None advertised.</p>"#);
    } else {
        out.push_str(&format!(
            r#"<p class="muted">Names shown are the server's own; clients see them as <code>{}__&lt;name&gt;</code>.</p>"#,
            esc(namespace)
        ));
        for tool in &snap.tools {
            let desc = tool.description.as_deref().unwrap_or("");
            let mut body = String::new();
            if let Some(title) = tool.title.as_deref().filter(|t| !t.is_empty()) {
                body.push_str(&format!("<p><strong>{}</strong></p>", esc(title)));
            }
            if !desc.is_empty() {
                body.push_str(&format!("<p>{}</p>", esc(desc)));
            }
            body.push_str(&schema_block("Input schema", &tool.input_schema));
            if let Some(output) = &tool.output_schema {
                body.push_str(&schema_block("Output schema", output));
            }
            out.push_str(&format!(
                r#"<details class="tool"><summary><code>{name}</code> <span class="muted">{summary}</span></summary>{body}</details>"#,
                name = esc(&tool.name),
                summary = esc(&truncate_chars(desc, 120)),
                body = body,
            ));
        }
    }
    out.push_str("</section>");

    // --- Prompts ---------------------------------------------------------------
    out.push_str(&format!("<section><h2>Prompts ({})</h2>", snap.prompts.len()));
    if caps.prompts.is_none() {
        out.push_str(r#"<p class="muted">Not supported by this server.</p>"#);
    } else if snap.prompts.is_empty() {
        out.push_str(r#"<p class="muted">None advertised.</p>"#);
    } else {
        for prompt in &snap.prompts {
            let desc = prompt.description.as_deref().unwrap_or("");
            let mut body = String::new();
            if !desc.is_empty() {
                body.push_str(&format!("<p>{}</p>", esc(desc)));
            }
            if let Some(args) = prompt.arguments.as_deref().filter(|a| !a.is_empty()) {
                body.push_str(r#"<p class="muted">Arguments</p><ul>"#);
                for arg in args {
                    let required = if arg.required == Some(true) { " (required)" } else { "" };
                    let arg_desc = arg
                        .description
                        .as_deref()
                        .filter(|d| !d.is_empty())
                        .map(|d| format!(r#" — <span class="muted">{}</span>"#, esc(d)))
                        .unwrap_or_default();
                    body.push_str(&format!(
                        "<li><code>{}</code>{}{}</li>",
                        esc(&arg.name),
                        required,
                        arg_desc
                    ));
                }
                body.push_str("</ul>");
            }
            out.push_str(&format!(
                r#"<details class="tool"><summary><code>{name}</code> <span class="muted">{summary}</span></summary>{body}</details>"#,
                name = esc(&prompt.name),
                summary = esc(&truncate_chars(desc, 120)),
                body = body,
            ));
        }
    }
    out.push_str("</section>");

    // --- Resources ---------------------------------------------------------------
    out.push_str(&format!("<section><h2>Resources ({})</h2>", snap.resources.len()));
    if caps.resources.is_none() {
        out.push_str(r#"<p class="muted">Not supported by this server.</p>"#);
    } else if snap.resources.is_empty() {
        out.push_str(r#"<p class="muted">None advertised.</p>"#);
    } else {
        out.push_str(r#"<table class="invites"><thead><tr><th>URI</th><th>Name</th><th>MIME type</th></tr></thead><tbody>"#);
        for r in &snap.resources {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                esc(&r.uri),
                esc(&r.name),
                esc(r.mime_type.as_deref().unwrap_or("—")),
            ));
        }
        out.push_str("</tbody></table>");
    }
    if !snap.resource_templates.is_empty() {
        out.push_str(&format!(
            "<h2>Resource templates ({})</h2>",
            snap.resource_templates.len()
        ));
        out.push_str(r#"<table class="invites"><thead><tr><th>URI template</th><th>Name</th><th>MIME type</th></tr></thead><tbody>"#);
        for t in &snap.resource_templates {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                esc(&t.uri_template),
                esc(&t.name),
                esc(t.mime_type.as_deref().unwrap_or("—")),
            ));
        }
        out.push_str("</tbody></table>");
    }
    out.push_str("</section>");

    out
}

fn error_page(msg: &str) -> Response {
    page("Error", &format!(r#"<h1>Something went wrong</h1><p>{}</p><p><a href="/">← Back</a></p>"#, esc(msg)))
        .into_response()
}

// ---------------------------------------------------------------------------
// Invites (admin)
// ---------------------------------------------------------------------------

/// 403 page shown when a non-admin reaches an admin-only route.
fn admin_forbidden() -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        page(
            "Forbidden",
            r#"<h1>Administrators only</h1><p>You do not have access to this page.</p><p><a href="/">← Back</a></p>"#,
        ),
    )
        .into_response()
}

/// `/invites` — admin view: generate codes and review existing ones.
pub async fn invites_page(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    if !user.is_admin {
        return admin_forbidden();
    }
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let list = invites::list(&state.db).await.unwrap_or_default();

    let mut rows = String::new();
    if list.is_empty() {
        rows.push_str(r#"<p class="muted">No invites yet. Generate one above to let someone register.</p>"#);
    } else {
        rows.push_str("<table class=\"invites\"><thead><tr><th>ID</th><th>Note</th><th>Status</th><th></th></tr></thead><tbody>");
        for inv in &list {
            let (status, action) = if inv.used() {
                ("used".to_string(), String::new())
            } else {
                (
                    "available".to_string(),
                    format!(
                        r#"<form method="post" action="/invites/revoke" data-confirm="Revoke this invite?">{csrf}<input type="hidden" name="short_id" value="{sid}"><button class="ghost danger">Revoke</button></form>"#,
                        csrf = csrf,
                        sid = esc(inv.short_id()),
                    ),
                )
            };
            rows.push_str(&format!(
                r#"<tr><td><code>{sid}</code></td><td>{note}</td><td>{status}</td><td>{action}</td></tr>"#,
                sid = esc(inv.short_id()),
                note = esc(&inv.note),
                status = status,
                action = action,
            ));
        }
        rows.push_str("</tbody></table>");
    }

    let body = format!(
        r#"<header class="row"><h1>Invites</h1><a href="/">← Back</a></header>
<p class="muted">Registration is invite-only. Each code works once. The code is shown only when generated — copy it then.</p>
<form method="post" action="/invites/create">
  {csrf}
  <label>Note (optional)<input name="note" placeholder="e.g. for Alice" autocomplete="off"></label>
  <button type="submit">Generate invite</button>
</form>
<section style="margin-top:18px">{rows}</section>
<section style="margin-top:18px">
  <h2>Recovery code</h2>
  <p class="muted">Issue a one-time code that lets an existing user who lost their device enroll a new passkey on their account.</p>
  <form method="post" action="/invites/recovery">
    {csrf}
    <label>User handle<input name="handle" placeholder="their handle" autocomplete="off" required></label>
    <button type="submit">Issue recovery code</button>
  </form>
</section>"#,
        csrf = csrf,
        rows = rows,
    );
    page_wide("Invites", &body).into_response()
}

#[derive(Deserialize)]
pub struct RecoveryForm {
    #[serde(default)]
    pub csrf: String,
    pub handle: String,
}

/// `POST /invites/recovery` — admin issues a recovery code for a user.
pub async fn create_recovery(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<RecoveryForm>,
) -> Response {
    if !user.is_admin {
        audit_denied("recovery.create", &user, &headers, form.handle.trim(), "not_admin");
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("recovery.create", &user, &headers, form.handle.trim(), "csrf");
        return forbidden();
    }
    let target = match crate::users::find_by_handle(&state.db, form.handle.trim()).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_page("no user with that handle"),
        Err(e) => return error_page(&e.to_string()),
    };
    let (code, _) = match invites::create_recovery(&state.db, &user.id, &target.id).await {
        Ok(v) => v,
        Err(e) => return error_page(&e.to_string()),
    };
    audit_ok("recovery.create", &user, &headers, &target.handle);
    let body = format!(
        r#"<header class="row"><h1>Recovery code created</h1><a href="/invites">← Back</a></header>
<p>Give this one-time code to <strong>{handle}</strong>. It works once and <strong>will not be shown again</strong>:</p>
<p><code class="invite-code">{code}</code></p>
<p class="muted">They enroll a new passkey at <code>{base}/recover</code> using their handle and this code.</p>"#,
        handle = esc(&target.handle),
        code = esc(&code),
        base = esc(&state.config.base_url),
    );
    page("Recovery code created", &body).into_response()
}

#[derive(Deserialize)]
pub struct CreateInviteForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub note: String,
}

/// `POST /invites/create` — generate a code and show it once.
pub async fn create_invite(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<CreateInviteForm>,
) -> Response {
    if !user.is_admin {
        audit_denied("invite.create", &user, &headers, "", "not_admin");
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("invite.create", &user, &headers, "", "csrf");
        return forbidden();
    }
    let (code, inv) = match invites::create(&state.db, &user.id, form.note.trim()).await {
        Ok(v) => v,
        Err(e) => return error_page(&e.to_string()),
    };
    audit_ok("invite.create", &user, &headers, inv.short_id());
    // Show the plaintext exactly once; it is never stored or shown again.
    let body = format!(
        r#"<header class="row"><h1>Invite created</h1><a href="/invites">← Back</a></header>
<p>Share this code with the person you are inviting. It works once and <strong>will not be shown again</strong>:</p>
<p><code class="invite-code">{code}</code></p>
<p class="muted">They register at <code>{base}/register</code> using this code.</p>"#,
        code = esc(&code),
        base = esc(&state.config.base_url),
    );
    page("Invite created", &body).into_response()
}

#[derive(Deserialize)]
pub struct RevokeInviteForm {
    #[serde(default)]
    pub csrf: String,
    pub short_id: String,
}

/// `POST /invites/revoke` — revoke an unused invite.
pub async fn revoke_invite(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<RevokeInviteForm>,
) -> Response {
    if !user.is_admin {
        audit_denied("invite.revoke", &user, &headers, form.short_id.trim(), "not_admin");
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("invite.revoke", &user, &headers, form.short_id.trim(), "csrf");
        return forbidden();
    }
    let _ = invites::revoke(&state.db, form.short_id.trim()).await;
    audit_ok("invite.revoke", &user, &headers, form.short_id.trim());
    Redirect::to("/invites").into_response()
}

// ---------------------------------------------------------------------------
// Account / passkey management
// ---------------------------------------------------------------------------

/// `/account` — manage the signed-in user's passkeys.
pub async fn account_page(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let now = crate::util::now_unix();
    let creds = users::list_credentials(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let only_one = creds.len() <= 1;

    let mut rows = String::new();
    rows.push_str("<ul class=\"servers\">");
    for c in &creds {
        let name = if c.name.is_empty() { "passkey" } else { &c.name };
        // Removing the last passkey would lock the account out, so it is refused.
        let remove = if only_one {
            r#"<span class="muted">only key</span>"#.to_string()
        } else {
            format!(
                r#"<form method="post" action="/account/passkeys/remove" data-confirm="Remove this passkey?">{csrf}<input type="hidden" name="cred_id" value="{id}"><button class="ghost danger">Remove</button></form>"#,
                csrf = csrf,
                id = esc(&c.id),
            )
        };
        let used = match c.last_used_at {
            Some(u) => format!("last used {}", ago(now - u)),
            None => "never used".to_string(),
        };
        rows.push_str(&format!(
            r#"<li><div><code>{name}</code><div class="meta muted">added {added} · {used}{origin}</div></div> {remove}</li>"#,
            name = esc(name),
            added = ago(now - c.created_at),
            used = used,
            origin = origin_detail(&c.last_ip, &c.last_user_agent),
            remove = remove,
        ));
    }
    rows.push_str("</ul>");

    // The user's backends, for the per-credential access toggles below.
    let user_instances = instances::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();

    // Connected MCP clients (OAuth) and browser sessions, each revocable.
    let connections = crate::oauth::store::list_user_connections(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let mut conn_rows = String::new();
    if connections.is_empty() {
        conn_rows.push_str(r#"<p class="muted">No MCP clients are connected.</p>"#);
    } else {
        conn_rows.push_str("<ul class=\"conns\">");
        for c in &connections {
            // The original name the client declared at registration.
            let dcr_name = c.client_name.clone().unwrap_or_default();
            // What to show as the heading: the user's custom name wins, then the
            // DCR name, then the opaque client_id as a last resort.
            let title = if !c.custom_name.is_empty() {
                c.custom_name.clone()
            } else if !dcr_name.is_empty() {
                dcr_name.clone()
            } else {
                c.client_id.clone()
            };
            // When a custom name overrides the DCR name, keep the original
            // visible so the user can still recognise which client it is.
            let orig = if !c.custom_name.is_empty() && !dcr_name.is_empty() {
                format!("“{}” · ", esc(&dcr_name))
            } else {
                String::new()
            };

            let mut redirects = String::new();
            if !c.redirect_uris.is_empty() {
                redirects.push_str(r#"<div class="conn-redirects muted">"#);
                for uri in &c.redirect_uris {
                    redirects.push_str(&format!("<code>{}</code>", esc(uri)));
                }
                redirects.push_str("</div>");
            }

            // Which backends this client may use (a checkbox per backend).
            let denied = crate::access::denied_instances(
                &state.db,
                crate::access::OAUTH,
                &c.client_id,
            )
            .await
            .unwrap_or_default();
            let access = access_form(
                "/account/connections/access",
                "client_id",
                &c.client_id,
                &user_instances,
                &denied,
                &csrf,
            );

            conn_rows.push_str(&format!(
                r#"<li>
  <div class="conn-head">
    <span class="conn-title"><code>{title}</code></span>
    <form method="post" action="/account/connections/revoke" data-confirm="Disconnect this client?">{csrf}<input type="hidden" name="client_id" value="{cid}"><button class="ghost danger">Disconnect</button></form>
  </div>
  <div class="conn-meta muted">{orig}<code>{cid}</code> · last accessed {last} · connected {first}{origin}</div>
  {redirects}
  <form class="conn-edit" method="post" action="/account/connections/label">
    {csrf}
    <input type="hidden" name="client_id" value="{cid}">
    <label>Name<br><input type="text" name="name" value="{cname}" placeholder="{cname_ph}" maxlength="60"></label>
    <label>Note<br><input type="text" name="note" value="{note}" maxlength="200"></label>
    <button class="ghost" type="submit">Save</button>
  </form>
  {access}
</li>"#,
                title = esc(&title),
                orig = orig,
                cid = esc(&c.client_id),
                last = ago(now - c.last_seen),
                first = ago(now - c.first_seen),
                origin = origin_detail(&c.last_ip, &c.last_user_agent),
                redirects = redirects,
                access = access,
                csrf = csrf,
                cname = esc(&c.custom_name),
                cname_ph = esc(&dcr_name),
                note = esc(&c.note),
            ));
        }
        conn_rows.push_str("</ul>");
    }

    let sessions = session::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let other_sessions = sessions.len().saturating_sub(1);
    let current_sid = session::current_session_id(&jar).unwrap_or_default();
    let mut session_rows = String::new();
    session_rows.push_str("<ul class=\"servers\">");
    for s in &sessions {
        let this = if s.id == current_sid {
            r#" <span class="badge">this device</span>"#
        } else {
            ""
        };
        session_rows.push_str(&format!(
            r#"<li><div><code>session</code>{this}<div class="meta muted">started {started} · expires in {expiry}{origin}</div></div></li>"#,
            this = this,
            started = ago(now - s.created_at),
            expiry = duration(s.expires_at - now),
            origin = origin_detail(&s.last_ip, &s.last_user_agent),
        ));
    }
    session_rows.push_str("</ul>");

    // Personal access tokens (for clients that can't do the OAuth flow).
    let pats = crate::tokens::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let mut pat_rows = String::new();
    if pats.is_empty() {
        pat_rows.push_str(r#"<p class="muted">No tokens yet.</p>"#);
    } else {
        pat_rows.push_str("<ul class=\"conns\">");
        for t in &pats {
            let name = if t.name.is_empty() { "token" } else { &t.name };
            let used = match t.last_used_at {
                Some(u) => format!("last used {}", ago(now - u)),
                None => "never used".to_string(),
            };
            let expiry = if t.expires_at <= now {
                "expired".to_string()
            } else {
                format!("expires in {}", duration(t.expires_at - now))
            };
            // Which backends this token may use (a checkbox per backend).
            let denied = crate::access::denied_instances(&state.db, crate::access::PAT, &t.id)
                .await
                .unwrap_or_default();
            let access = access_form(
                "/account/tokens/access",
                "token_id",
                &t.id,
                &user_instances,
                &denied,
                &csrf,
            );
            pat_rows.push_str(&format!(
                r#"<li>
  <div class="conn-head">
    <span class="conn-title"><code>{name}</code> <span class="muted">· {used} · {expiry}</span></span>
    <form method="post" action="/account/tokens/revoke" data-confirm="Revoke this token?">{csrf}<input type="hidden" name="token_id" value="{id}"><button class="ghost danger">Revoke</button></form>
  </div>
  {access}
</li>"#,
                name = esc(name),
                used = used,
                expiry = expiry,
                access = access,
                csrf = csrf,
                id = esc(&t.id),
            ));
        }
        pat_rows.push_str("</ul>");
    }

    let body = format!(
        r#"<header class="row"><h1>Account</h1><a href="/">← Back</a></header>
<p>Signed in as <strong>{handle}</strong></p>
<section>
  <h2>Passkeys</h2>
  <p class="muted">Passkeys are how you sign in — a private key held by your device or hardware key (Touch ID, Face ID, Windows Hello, a YubiKey, …) that proves who you are without a password. The hub only stores the matching public key, so there is nothing to phish or leak. Add a second passkey (another device or a hardware key) so you are not locked out if you lose one.</p>
  {rows}
  <button id="add-passkey-btn" class="inline" type="button">Add a passkey</button>
  <p class="error" id="add-passkey-error"></p>
</section>
<section style="margin-top:18px">
  <h2>Connected MCP clients</h2>
  <p class="muted">Clients you have authorized to reach your MCP endpoint. Disconnecting revokes refresh access; any active token still works until it expires (≤15 min).</p>
  {conn_rows}
</section>
<section style="margin-top:18px">
  <h2>Personal access tokens</h2>
  <p class="muted">For MCP clients that can't sign in with OAuth. A token is a bearer credential with full access to your MCP endpoint — treat it like a password. Shown once at creation.</p>
  {pat_rows}
  <form method="post" action="/account/tokens/create" class="token-create">
    {csrf}
    <label class="name">Name<br><input type="text" name="name" placeholder="e.g. my-laptop" maxlength="60" required></label>
    <label class="expires">Expires<br><select name="expires_days">
      <option value="7">7 days</option>
      <option value="30" selected>30 days</option>
      <option value="90">90 days</option>
      <option value="180">180 days</option>
      <option value="365">365 days</option>
    </select></label>
    <button class="inline" type="submit">Create token</button>
  </form>
</section>
<section style="margin-top:18px">
  <h2>Browser sessions</h2>
  <p class="muted">You have {n_sessions} active session(s){other}.</p>
  {session_rows}
  {sign_out_others}
</section>"#,
        handle = esc(&user.handle),
        rows = rows,
        conn_rows = conn_rows,
        pat_rows = pat_rows,
        session_rows = session_rows,
        n_sessions = sessions.len(),
        other = if other_sessions > 0 {
            format!(", including {other_sessions} other than this one")
        } else {
            String::new()
        },
        sign_out_others = if other_sessions > 0 {
            format!(
                r#"<form method="post" action="/account/sessions/revoke-others">{csrf}<button class="ghost">Sign out other sessions</button></form>"#,
                csrf = csrf
            )
        } else {
            String::new()
        },
    );
    page_wide("Account", &body).into_response()
}

/// `POST /account/sessions/revoke-others` — end every session but this one.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("session.revoke_others", &user, &headers, "", "csrf");
        return forbidden();
    }
    let keep = session::current_session_id(&jar).unwrap_or_default();
    let _ = session::delete_others(&state.db, &user.id, &keep).await;
    audit_ok("session.revoke_others", &user, &headers, "");
    Redirect::to("/account").into_response()
}

#[derive(Deserialize)]
pub struct RevokeConnectionForm {
    #[serde(default)]
    pub csrf: String,
    pub client_id: String,
}

/// `POST /account/connections/revoke` — disconnect one OAuth client.
pub async fn revoke_connection(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<RevokeConnectionForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("connection.revoke", &user, &headers, form.client_id.trim(), "csrf");
        return forbidden();
    }
    let _ =
        crate::oauth::store::revoke_user_client(&state.db, &user.id, form.client_id.trim()).await;
    audit_ok("connection.revoke", &user, &headers, form.client_id.trim());
    Redirect::to("/account").into_response()
}

#[derive(Deserialize)]
pub struct LabelConnectionForm {
    #[serde(default)]
    pub csrf: String,
    pub client_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub note: String,
}

/// `POST /account/connections/label` — set a custom name + note for one of the
/// user's connected OAuth clients. Editing is only allowed for clients the user
/// actually has a live connection to.
pub async fn update_connection_label(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<LabelConnectionForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("client.label", &user, &headers, form.client_id.trim(), "csrf");
        return forbidden();
    }
    let client_id = form.client_id.trim();
    // Match the input lengths to the form maxlength attributes.
    let name: String = form.name.trim().chars().take(60).collect();
    let note: String = form.note.trim().chars().take(200).collect();
    // Don't let a user attach labels to client IDs they aren't connected to.
    match crate::oauth::store::user_has_connection(&state.db, &user.id, client_id).await {
        Ok(true) => {
            let _ =
                crate::oauth::store::set_client_label(&state.db, &user.id, client_id, &name, &note)
                    .await;
        }
        _ => return error_page("no such connected client"),
    }
    audit_ok("client.label", &user, &headers, client_id);
    Redirect::to("/account").into_response()
}

/// Compute the denied instance ids from an access form: every backend the user
/// owns that was NOT checked (`allow_<instance_id>` absent from the submission).
async fn denied_from_form(
    state: &AppState,
    user_id: &str,
    submitted: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let instances = instances::list_for_user(&state.db, user_id)
        .await
        .unwrap_or_default();
    instances
        .into_iter()
        .filter(|i| !submitted.contains_key(&format!("allow_{}", i.id)))
        .map(|i| i.id)
        .collect()
}

/// `POST /account/connections/access` — set which backends an OAuth client may use.
pub async fn update_connection_access(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let csrf = form.get("csrf").map(String::as_str).unwrap_or_default();
    if !session::check_csrf(&jar, &state.config.master_key, csrf) {
        return forbidden();
    }
    let client_id = form.get("client_id").map(|s| s.trim()).unwrap_or_default();
    // Only a client the user is actually connected to.
    if !matches!(
        crate::oauth::store::user_has_connection(&state.db, &user.id, client_id).await,
        Ok(true)
    ) {
        return error_page("no such connected client");
    }
    let denied = denied_from_form(&state, &user.id, &form).await;
    let _ = crate::access::set_denials(&state.db, &user.id, crate::access::OAUTH, client_id, &denied)
        .await;
    audit_ok("client.access", &user, &headers, client_id);
    Redirect::to("/account").into_response()
}

/// `POST /account/tokens/access` — set which backends a personal access token may use.
pub async fn update_token_access(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let csrf = form.get("csrf").map(String::as_str).unwrap_or_default();
    if !session::check_csrf(&jar, &state.config.master_key, csrf) {
        return forbidden();
    }
    let token_id = form.get("token_id").map(|s| s.trim()).unwrap_or_default();
    // Only one of the user's own tokens.
    let owned = crate::tokens::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default()
        .iter()
        .any(|t| t.id == token_id);
    if !owned {
        return error_page("no such token");
    }
    let denied = denied_from_form(&state, &user.id, &form).await;
    let _ = crate::access::set_denials(&state.db, &user.id, crate::access::PAT, token_id, &denied)
        .await;
    audit_ok("token.access", &user, &headers, token_id);
    Redirect::to("/account").into_response()
}

#[derive(Deserialize)]
pub struct CreateTokenForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub expires_days: i64,
}

/// `POST /account/tokens/create` — mint a personal access token and reveal it
/// once. Creation is web-only (passkey-authenticated); see the plan rationale.
pub async fn create_token(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<CreateTokenForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("token.create", &user, &headers, "", "csrf");
        return forbidden();
    }
    let name = form.name.trim();
    if name.is_empty() {
        return error_page("a token name is required");
    }
    // Expiry is mandatory and bounded; clamp the submitted value to 1..=365 days.
    let days = form.expires_days.clamp(1, 365);
    let ttl = days * 86_400;
    let (_, plaintext) = match crate::tokens::create(&state.db, &user.id, name, ttl).await {
        Ok(v) => v,
        Err(e) => return error_page(&format!("could not create token: {e}")),
    };
    audit_ok("token.create", &user, &headers, name);

    // Reveal the secret exactly once. It is never recoverable after this page.
    let example = format!(
        "curl -H \"Authorization: Bearer {tok}\" {url}",
        tok = esc(&plaintext),
        url = esc(&state.config.mcp_url()),
    );
    let body = format!(
        r#"<header class="row"><h1>Token created</h1><a href="/account">← Account</a></header>
<p class="status status-warn">Copy this token now — it will <strong>not</strong> be shown again.</p>
<p class="muted">Token <code>{name}</code>, expires in {days} days. It grants full access to your MCP endpoint; store it like a password.</p>
<pre class="cmd"><code>{tok}</code></pre>
<p class="muted">Use it as a bearer token, e.g.</p>
<pre class="cmd"><code>{example}</code></pre>
<p><a href="/account">← Back to account</a></p>"#,
        name = esc(name),
        days = days,
        tok = esc(&plaintext),
        example = example,
    );
    page("Token created", &body).into_response()
}

#[derive(Deserialize)]
pub struct RevokeTokenForm {
    #[serde(default)]
    pub csrf: String,
    pub token_id: String,
}

/// `POST /account/tokens/revoke` — delete one of the user's tokens.
pub async fn revoke_token(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<RevokeTokenForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("token.revoke", &user, &headers, form.token_id.trim(), "csrf");
        return forbidden();
    }
    let _ = crate::tokens::revoke(&state.db, &user.id, form.token_id.trim()).await;
    // Drop any backend-access denials for the now-deleted token.
    let _ = crate::access::clear_for_credential(
        &state.db,
        crate::access::PAT,
        form.token_id.trim(),
    )
    .await;
    audit_ok("token.revoke", &user, &headers, form.token_id.trim());
    Redirect::to("/account").into_response()
}

/// Render an elapsed duration as a coarse "N units ago" string.
fn ago(secs: i64) -> String {
    let s = secs.max(0);
    if s < 90 {
        "just now".to_string()
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

/// Render an optional last-seen IP and User-Agent as a trailing muted detail
/// (" · IP 1.2.3.4 · Mozilla/5.0 …"), omitting whichever is absent. Returns an
/// empty string when neither is known.
fn origin_detail(ip: &Option<String>, ua: &Option<String>) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("IP {}", esc(ip)));
    }
    if let Some(ua) = ua.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(esc(ua));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" · {}", parts.join(" · "))
    }
}

/// Render the per-credential backend-access form: a checkbox per backend, checked
/// when the credential is allowed it (i.e. not in `denied`). Each box uses a
/// distinct `allow_<instance_id>` name so it deserializes cleanly. Empty when the
/// user has no backends.
fn access_form(
    action: &str,
    id_field: &str,
    id_value: &str,
    instances: &[instances::Instance],
    denied: &std::collections::HashSet<String>,
    csrf: &str,
) -> String {
    if instances.is_empty() {
        return String::new();
    }
    let mut boxes = String::new();
    for i in instances {
        let checked = if denied.contains(&i.id) { "" } else { " checked" };
        boxes.push_str(&format!(
            r#"<label class="checkbox"><input type="checkbox" name="allow_{id}" value="on"{checked}> <code>{ns}</code></label>"#,
            id = esc(&i.id),
            checked = checked,
            ns = esc(&i.namespace),
        ));
    }
    format!(
        r#"<form class="access" method="post" action="{action}">{csrf}<input type="hidden" name="{id_field}" value="{idv}"><span class="muted">Backends:</span><div class="access-grid">{boxes}</div><button class="ghost" type="submit">Save access</button></form>"#,
        action = action,
        csrf = csrf,
        id_field = id_field,
        idv = esc(id_value),
        boxes = boxes,
    )
}

/// Render a remaining duration coarsely ("N days" / "N hours").
fn duration(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 86_400 {
        format!("{} days", s / 86_400)
    } else if s >= 3600 {
        format!("{} hours", s / 3600)
    } else {
        format!("{} minutes", (s / 60).max(1))
    }
}

#[derive(Deserialize)]
pub struct RemovePasskeyForm {
    #[serde(default)]
    pub csrf: String,
    pub cred_id: String,
}

/// `POST /account/passkeys/remove` — delete one of the user's passkeys.
pub async fn remove_passkey(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<RemovePasskeyForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        audit_denied("passkey.remove", &user, &headers, form.cred_id.trim(), "csrf");
        return forbidden();
    }
    // Never let a user remove their last passkey — that is an unrecoverable
    // lockout (only an admin recovery code could undo it).
    match users::count_credentials(&state.db, &user.id).await {
        Ok(n) if n <= 1 => return error_page("you cannot remove your only passkey"),
        Ok(_) => {}
        Err(e) => return error_page(&e.to_string()),
    }
    let _ = users::delete_credential(&state.db, &user.id, form.cred_id.trim()).await;
    audit_ok("passkey.remove", &user, &headers, form.cred_id.trim());
    Redirect::to("/account").into_response()
}

/// `/recover` — bind a new passkey to an existing account with a recovery code.
pub async fn recover_page(MaybeUser(user): MaybeUser) -> Response {
    if user.is_some() {
        return Redirect::to("/account").into_response();
    }
    let body = r#"<h1>Recover access</h1>
<p class="muted">Lost the device with your passkey? Ask an administrator for a recovery code, then enroll a new passkey here.</p>
<form id="recover-form">
  <label>Handle<input id="recover-handle" name="handle" autocomplete="username" required></label>
  <label>Recovery code<input id="recover-code" name="code" autocomplete="off" required></label>
  <button id="recover-btn" type="submit">Recover &amp; add passkey</button>
</form>
<p class="error" id="recover-error"></p>
<p class="muted"><a href="/login">← Back to sign in</a></p>"#;
    page("Recover access", body).into_response()
}

// ---------------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------------

/// `/users` — admin view: disable/enable/delete accounts.
pub async fn users_page(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    if !admin.is_admin {
        return admin_forbidden();
    }
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let all = users::list(&state.db).await.unwrap_or_default();
    let admin_count = all.iter().filter(|u| u.is_admin).count();

    let mut rows = String::new();
    rows.push_str("<table class=\"invites\"><thead><tr><th>Handle</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>");
    for u in &all {
        let is_self = u.id == admin.id;
        let last_admin = u.is_admin && admin_count <= 1;
        let role = if u.is_admin { "admin" } else { "user" };
        let status = if u.disabled { "disabled" } else { "active" };
        // No destructive action on yourself or the last remaining admin.
        let actions = if is_self || last_admin {
            r#"<span class="muted">—</span>"#.to_string()
        } else {
            let toggle = if u.disabled {
                ("/users/enable", "Enable")
            } else {
                ("/users/disable", "Disable")
            };
            format!(
                r#"<form method="post" action="{ta}">{csrf}<input type="hidden" name="handle" value="{h}"><button class="ghost">{tl}</button></form>
<form method="post" action="/users/delete" data-confirm="Delete this user and all their data?">{csrf}<input type="hidden" name="handle" value="{h}"><button class="ghost danger">Delete</button></form>"#,
                ta = toggle.0,
                tl = toggle.1,
                csrf = csrf,
                h = esc(&u.handle),
            )
        };
        rows.push_str(&format!(
            r#"<tr><td><code>{h}</code></td><td>{role}</td><td>{status}</td><td><div class="row">{actions}</div></td></tr>"#,
            h = esc(&u.handle),
            role = role,
            status = status,
            actions = actions,
        ));
    }
    rows.push_str("</tbody></table>");

    let body = format!(
        r#"<header class="row"><h1>Users</h1><a href="/">← Back</a></header>
<p class="muted">Disabling an account ends its sessions and revokes its tokens immediately; deleting also removes its servers and passkeys. You cannot act on your own account or the last admin.</p>
{rows}"#,
        rows = rows,
    );
    page_wide("Users", &body).into_response()
}

// ---------------------------------------------------------------------------
// Runtime statistics (admin)
// ---------------------------------------------------------------------------

/// `/stats` — admin view: live backend-slot usage, active session count,
/// configured limits, and each backend's last-known runtime status. The slot
/// gauge and session count are live; the instance table is a snapshot.
pub async fn stats_page(State(state): State<AppState>, AuthUser(admin): AuthUser) -> Response {
    if !admin.is_admin {
        return admin_forbidden();
    }
    let s = crate::stats::gather(&state).await;

    // Headline: how close the global backend pool is to its ceiling, and how
    // many MCP sessions are live (the signal behind "global backend capacity
    // reached" — each session holds its own copy of a user's backends).
    let pct = (s.slots.used * 100).checked_div(s.slots.total).unwrap_or(0);
    let slots_class = match pct {
        p if p >= 90 => "danger",
        p if p >= 75 => "warn",
        _ => "ok",
    };
    let headline = format!(
        r#"<div class="row">
  <div class="status status-{slots_class}">Backend slots: <strong>{used} / {total}</strong> ({pct}% in use)</div>
  <div class="status status-ok">Active sessions: <strong>{sessions}</strong></div>
</div>"#,
        slots_class = slots_class,
        used = s.slots.used,
        total = s.slots.total,
        pct = pct,
        sessions = s.active_sessions,
    );

    // Configured ceilings, with their env-var names so the admin knows the knob.
    let limits = format!(
        r#"<table class="invites"><thead><tr><th>Limit</th><th>Value</th><th>Env var</th></tr></thead><tbody>
<tr><td>Max backends (global)</td><td>{global}</td><td><code>HUB_MAX_BACKENDS_GLOBAL</code></td></tr>
<tr><td>Max backends per user</td><td>{per_user}</td><td><code>HUB_MAX_BACKENDS_PER_USER</code></td></tr>
<tr><td>Backend idle timeout</td><td>{idle}s</td><td><code>HUB_BACKEND_IDLE_SECS</code></td></tr>
<tr><td>Per-call timeout</td><td>{call}</td><td><code>HUB_BACKEND_CALL_TIMEOUT_SECS</code></td></tr>
<tr><td>Max response size</td><td>{resp}</td><td><code>HUB_MAX_RESPONSE_MB</code></td></tr>
</tbody></table>"#,
        global = s.limits.max_backends_global,
        per_user = s.limits.max_backends_per_user,
        idle = s.limits.backend_idle_secs,
        call = if s.limits.backend_call_timeout_secs == 0 {
            "off".to_string()
        } else {
            format!("{}s", s.limits.backend_call_timeout_secs)
        },
        resp = if s.limits.max_response_mb == 0 {
            "uncapped".to_string()
        } else {
            format!("{} MB", s.limits.max_response_mb)
        },
    );

    // Aggregate counts across every user's instances.
    let totals = format!(
        r#"<p class="muted">{users} user(s) · {insts} server(s) ({enabled} enabled) · running {running} · error {error} · not started {skipped} · not built {unbuilt} · unknown {unknown}</p>"#,
        users = s.totals.users,
        insts = s.totals.instances,
        enabled = s.totals.enabled_instances,
        running = s.totals.running,
        error = s.totals.error,
        skipped = s.totals.skipped,
        unbuilt = s.totals.unbuilt,
        unknown = s.totals.unknown,
    );

    // Per-instance status table.
    let now = crate::util::now_unix();
    let mut rows = String::new();
    rows.push_str(
        "<table class=\"invites\"><thead><tr><th>Owner</th><th>Server</th><th>Status</th><th>Detail</th><th>Checked</th></tr></thead><tbody>",
    );
    if s.instances.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="muted">No servers configured.</td></tr>"#);
    } else {
        for i in &s.instances {
            let (class, label) = match i.runtime_status.as_str() {
                "ok" => ("ok", "running"),
                "error" => ("danger", "error"),
                "skipped" => ("warn", "not started"),
                "unbuilt" => ("warn", "not built"),
                _ => ("muted", "unknown"),
            };
            // Detail can carry captured stderr; collapse to a single line here.
            let detail = match &i.runtime_detail {
                Some(d) if !d.is_empty() => esc(d.lines().next().unwrap_or("")),
                _ => String::new(),
            };
            let checked = i
                .runtime_checked_at
                .map(|t| ago(now - t))
                .unwrap_or_else(|| "—".to_string());
            rows.push_str(&format!(
                r#"<tr><td><code>{owner}</code></td><td><code>{ns}</code> · {name}</td><td><span class="status status-{class}">{label}</span></td><td class="muted">{detail}</td><td class="muted">{checked}</td></tr>"#,
                owner = esc(&i.owner),
                ns = esc(&i.namespace),
                name = esc(&i.display_name),
                class = class,
                label = label,
                detail = detail,
                checked = checked,
            ));
        }
    }
    rows.push_str("</tbody></table>");

    let body = format!(
        r#"<header class="row"><h1>Runtime stats</h1><a href="/">← Back</a></header>
<p class="muted">Backend slots and active sessions are live; the server table shows each backend's last-known status. Reload to refresh.</p>
{headline}
<section><h2>Limits</h2>{limits}</section>
<section><h2>Servers</h2>{totals}{rows}</section>"#,
        headline = headline,
        limits = limits,
        totals = totals,
        rows = rows,
    );
    page_wide("Runtime stats", &body).into_response()
}

#[derive(Deserialize)]
pub struct UserActionForm {
    #[serde(default)]
    pub csrf: String,
    pub handle: String,
}

/// Resolve a target user for an admin action, enforcing the shared guards:
/// CSRF, admin caller, target exists, not self, not the last admin.
async fn resolve_admin_target(
    state: &AppState,
    admin: &users::User,
    jar: &SignedCookieJar,
    headers: &HeaderMap,
    action: &str,
    form: &UserActionForm,
) -> Result<users::User, Response> {
    if !admin.is_admin {
        audit_denied(action, admin, headers, form.handle.trim(), "not_admin");
        return Err(admin_forbidden());
    }
    if !session::check_csrf(jar, &state.config.master_key, &form.csrf) {
        audit_denied(action, admin, headers, form.handle.trim(), "csrf");
        return Err(forbidden());
    }
    let target = match users::find_by_handle(&state.db, form.handle.trim()).await {
        Ok(Some(u)) => u,
        _ => return Err(error_page("no user with that handle")),
    };
    if target.id == admin.id {
        return Err(error_page("you cannot act on your own account here"));
    }
    if target.is_admin && users::count_admins(&state.db).await.unwrap_or(0) <= 1 {
        return Err(error_page("cannot disable or delete the last administrator"));
    }
    Ok(target)
}

/// `POST /users/disable` — disable an account and revoke its access.
pub async fn disable_user(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &headers, "user.disable", &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(e) = deactivate_user(&state, &target.id).await {
        audit_denied("user.disable", &admin, &headers, &target.handle, "error");
        return error_page(&e.to_string());
    }
    audit_ok("user.disable", &admin, &headers, &target.handle);
    Redirect::to("/users").into_response()
}

/// `POST /users/enable` — re-enable a disabled account.
pub async fn enable_user(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &headers, "user.enable", &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let _ = users::set_disabled(&state.db, &target.id, false).await;
    audit_ok("user.enable", &admin, &headers, &target.handle);
    Redirect::to("/users").into_response()
}

/// `POST /users/delete` — delete an account and all its data.
pub async fn delete_user(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &headers, "user.delete", &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(e) = purge_user(&state, &target.id).await {
        audit_denied("user.delete", &admin, &headers, &target.handle, "error");
        return error_page(&e.to_string());
    }
    audit_ok("user.delete", &admin, &headers, &target.handle);
    Redirect::to("/users").into_response()
}

/// Disable an account: set the flag, then end its sessions and tokens so the
/// revocation takes effect immediately.
pub async fn deactivate_user(state: &AppState, user_id: &str) -> anyhow::Result<()> {
    users::set_disabled(&state.db, user_id, true).await?;
    session::delete_all_for_user(&state.db, user_id).await?;
    crate::oauth::store::revoke_all_user_tokens(&state.db, user_id).await?;
    crate::tokens::revoke_all_for_user(&state.db, user_id).await?;
    Ok(())
}

/// Delete an account and everything it owns. Database rows cascade; git
/// environments live on disk, so remove those first.
pub async fn purge_user(state: &AppState, user_id: &str) -> anyhow::Result<()> {
    if let Ok(insts) = instances::list_for_user(&state.db, user_id).await {
        for inst in insts {
            crate::gitsrc::remove_env(&state.config.env_dir, &inst.id);
        }
    }
    users::delete(&state.db, user_id).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth pages
// ---------------------------------------------------------------------------

/// Stash a validated `next` target in a short-lived cookie for after login.
fn with_next(jar: SignedCookieJar, state: &AppState, next: Option<String>) -> SignedCookieJar {
    match next.as_deref().and_then(session::safe_next) {
        Some(n) => jar.add(session::next_cookie(n, state.config.cookie_secure())),
        None => jar,
    }
}

/// `/login` — passkey sign-in.
pub async fn login_page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    jar: SignedCookieJar,
    Query(q): Query<NextQuery>,
) -> Response {
    if user.is_some() {
        return Redirect::to("/").into_response();
    }
    let jar = with_next(jar, &state, q.next);
    let body = r#"<h1>Sign in</h1>
<form id="login-form">
  <label>Handle<input id="login-handle" name="handle" autocomplete="username webauthn" required></label>
  <button id="login-btn" type="submit">Sign in with passkey</button>
</form>
<p class="error" id="login-error"></p>
<p class="muted">Need an account? <a href="/register">Register</a></p>
<p class="muted">Lost your device? <a href="/recover">Recover access</a></p>"#;
    (jar, page("Sign in", body)).into_response()
}

/// `/register` — create an account + first passkey.
pub async fn register_page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    jar: SignedCookieJar,
    Query(q): Query<NextQuery>,
) -> Response {
    if user.is_some() {
        return Redirect::to("/").into_response();
    }
    let jar = with_next(jar, &state, q.next);
    let body = r#"<h1>Create account</h1>
<form id="register-form">
  <label>Handle<input id="reg-handle" name="handle" autocomplete="username" required></label>
  <label>Display name<input id="reg-display" name="display_name" required></label>
  <label>Invite code<input id="reg-invite" name="invite_code" autocomplete="off"></label>
  <p class="muted">Registration is invite-only. Leave the code blank only if you are setting up the very first (admin) account.</p>
  <button id="register-btn" type="submit">Create account &amp; passkey</button>
</form>
<p class="error" id="register-error"></p>
<p class="muted">Already have an account? <a href="/login">Sign in</a></p>"#;
    (jar, page("Register", body)).into_response()
}

/// `/logout` GET fallback (the POST handler lives in auth::webauthn::logout).
pub async fn logout_get(State(_state): State<AppState>) -> Redirect {
    Redirect::to("/login")
}

#[cfg(test)]
mod tests {
    use super::render_snapshot;
    use crate::instances::CapabilitiesSnapshot;

    /// The capabilities page shows the server identity, marks unsupported
    /// sections as such, renders tools with their schemas, and escapes
    /// backend-supplied text.
    #[test]
    fn snapshot_renders_sections_and_escapes() {
        let mut server = rmcp::model::InitializeResult::default();
        server.server_info.name = "demo <server>".into();
        server.server_info.version = "1.2.3".into();
        server.instructions = Some("Use the tools wisely.".into());
        server.capabilities = rmcp::model::ServerCapabilities {
            tools: Some(rmcp::model::ToolsCapability { list_changed: None }),
            ..Default::default()
        };
        let mut schema = serde_json::Map::new();
        schema.insert("type".into(), serde_json::Value::String("object".into()));
        let snap = CapabilitiesSnapshot {
            fetched_at: 0,
            server,
            tools: vec![rmcp::model::Tool::new(
                "search",
                "Find <things> fast",
                std::sync::Arc::new(schema),
            )],
            prompts: Vec::new(),
            resources: Vec::new(),
            resource_templates: Vec::new(),
        };

        let html = render_snapshot(&snap, "demo");
        assert!(html.contains("demo &lt;server&gt;"), "server name escaped: {html}");
        assert!(html.contains("1.2.3"));
        assert!(html.contains("Use the tools wisely."));
        assert!(html.contains("Tools (1)"));
        assert!(html.contains("<code>search</code>"));
        assert!(html.contains("Find &lt;things&gt; fast"));
        assert!(html.contains("&quot;type&quot;: &quot;object&quot;"), "schema rendered: {html}");
        assert!(html.contains("<code>demo__&lt;name&gt;</code>"), "namespacing note present");
        // Prompts/resources capabilities are absent → marked unsupported.
        assert!(html.contains("Prompts (0)"));
        assert!(html.contains("Not supported by this server."));
    }
}
