//! Server-rendered web UI pages.

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use axum::Form;
use serde::Deserialize;

use crate::auth::session;
use crate::auth::{AuthUser, MaybeUser};
use crate::{instances, invites, users, AppState};

/// Optional `?next=` redirect target carried into the login/register pages.
#[derive(Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    pub next: Option<String>,
}

/// Wrap page content in the shared HTML shell.
fn page(title: &str, body: &str) -> Html<String> {
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
  <main class="card">{body}</main>
  <script src="/static/auth.js"></script>
</body>
</html>"#
    ))
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
            r#"<section><div class="row"><h2>Administration</h2><span><a href="/invites">Invites</a> · <a href="/users">Users</a></span></div></section>"#
        } else {
            ""
        },
        mcp = esc(&state.config.mcp_url()),
    );
    page("Dashboard", &body).into_response()
}

// ---------------------------------------------------------------------------
// Adding + editing a user's own servers
// ---------------------------------------------------------------------------

/// Editable fields shared by the add and edit forms. `transport` is a `<select>`
/// only when creating (it is fixed once a server exists).
fn server_fields(
    transport: &str,
    transport_select: bool,
    command_line: &str,
    repo: &str,
    git_ref: &str,
    url: &str,
    env: &str,
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
  </div>
  <div class="http-only {http_hidden}">
    <label>Remote URL<input name="url" value="{url}" placeholder="https://server.example.com/mcp"></label>
  </div>
  <label>Environment variables (one <code>KEY=VALUE</code> per line)<textarea name="env" rows="6" placeholder="API_TOKEN=...">{env}</textarea></label>"#,
        transport_field = transport_field,
        stdio_hidden = stdio_hidden,
        http_hidden = http_hidden,
        cmd = esc(command_line),
        repo = esc(repo),
        git_ref = esc(git_ref),
        url = esc(url),
        env = esc(env),
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
        fields = server_fields("stdio", true, "", "", "", "", ""),
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
}

/// `POST /servers/create`
pub async fn create_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Form(form): Form<CreateServerForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
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
    Redirect::to(&format!("/servers/{}", inst.id)).into_response()
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

    let fields = server_fields(
        &def.transport,
        false,
        &instances::render_command(&def.command, &def.args),
        def.repo.as_deref().unwrap_or(""),
        def.git_ref.as_deref().unwrap_or(""),
        def.url.as_deref().unwrap_or(""),
        &instances::render_env(&env),
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
{runtime}
{command}
<form method="post" action="/servers/{id}/config">
  {csrf}
  {fields}
  <button type="submit">Save configuration</button>
</form>
{git_section}
<div class="row" style="margin-top:18px">
  {toggle}
  <form method="post" action="/servers/{id}/delete" data-confirm="Remove this server?">{csrf}<button class="ghost danger">Remove</button></form>
</div>"#,
        name = esc(&inst.display_name),
        ns = esc(&inst.namespace),
        transport = esc(&def.transport),
        status = if inst.enabled { "enabled" } else { "disabled" },
        runtime = runtime_banner(&inst),
        command = command_line(&state, &inst, &def),
        id = esc(&inst.id),
        csrf = csrf,
        fields = fields,
        git_section = git_section,
        toggle = toggle,
    );
    page(&inst.display_name, &body).into_response()
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

/// Render the backend's last connection outcome as a coloured banner.
fn runtime_banner(inst: &instances::Instance) -> String {
    let when = inst
        .runtime_checked_at
        .map(|t| {
            let secs = (crate::util::now_unix() - t).max(0);
            if secs < 90 {
                format!(" · checked {secs}s ago")
            } else {
                format!(" · checked {}m ago", secs / 60)
            }
        })
        .unwrap_or_default();
    let (class, label) = match inst.runtime_status.as_str() {
        "ok" => ("ok", "running".to_string()),
        "error" => ("danger", "error".to_string()),
        "unbuilt" => ("warn", "not built".to_string()),
        "skipped" => ("warn", "not started".to_string()),
        _ => return String::new(), // 'unknown' before the first connection
    };
    let detail = match &inst.runtime_detail {
        Some(d) if !d.is_empty() => format!(": {}", esc(d)),
        _ => String::new(),
    };
    format!(
        r#"<p class="status status-{class}">Backend {label}{detail}{when}</p>"#,
        class = class,
        label = label,
        detail = detail,
        when = when,
    )
}

/// `POST /servers/{id}/config` — save an edit to the server's def + env.
pub async fn save_config(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CreateServerForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
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
    Redirect::to(&format!("/servers/{id}")).into_response()
}

async fn set_enabled_and_redirect(
    state: &AppState,
    user_id: &str,
    id: &str,
    enabled: bool,
) -> Response {
    if instances::get_owned(&state.db, id, user_id).await.ok().flatten().is_none() {
        return error_page("server not found");
    }
    let _ = instances::set_enabled(&state.db, id, enabled).await;
    Redirect::to(&format!("/servers/{id}")).into_response()
}

pub async fn enable_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    set_enabled_and_redirect(&state, &user.id, &id, true).await
}

pub async fn disable_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    set_enabled_and_redirect(&state, &user.id, &id, false).await
}

pub async fn delete_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    if instances::get_owned(&state.db, &id, &user.id).await.ok().flatten().is_none() {
        return error_page("server not found");
    }
    let _ = instances::delete(&state.db, &id).await;
    crate::gitsrc::remove_env(&state.config.env_dir, &id);
    Redirect::to("/").into_response()
}

/// `POST /servers/{id}/update` — (re)build a git-sourced server.
pub async fn update_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
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
    let uid = state.sandbox_uid(&user.id).await;
    match crate::gitsrc::update_instance(&state.db, &state.config.env_dir, &inst, &def, uid).await {
        Ok(_) => Redirect::to(&format!("/servers/{id}")).into_response(),
        Err(e) => error_page(&format!("update failed: {e}")),
    }
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
    page("Invites", &body).into_response()
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
    Form(form): Form<RecoveryForm>,
) -> Response {
    if !user.is_admin {
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
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
    Form(form): Form<CreateInviteForm>,
) -> Response {
    if !user.is_admin {
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    let (code, _) = match invites::create(&state.db, &user.id, form.note.trim()).await {
        Ok(v) => v,
        Err(e) => return error_page(&e.to_string()),
    };
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
    Form(form): Form<RevokeInviteForm>,
) -> Response {
    if !user.is_admin {
        return admin_forbidden();
    }
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    let _ = invites::revoke(&state.db, form.short_id.trim()).await;
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
        rows.push_str(&format!(
            r#"<li><span><code>{name}</code></span> {remove}</li>"#,
            name = esc(name),
            remove = remove,
        ));
    }
    rows.push_str("</ul>");

    // Connected MCP clients (OAuth) and browser sessions, each revocable.
    let connections = crate::oauth::store::list_user_connections(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let mut conn_rows = String::new();
    if connections.is_empty() {
        conn_rows.push_str(r#"<p class="muted">No MCP clients are connected.</p>"#);
    } else {
        conn_rows.push_str("<ul class=\"servers\">");
        for c in &connections {
            let name = c.client_name.clone().unwrap_or_else(|| c.client_id.clone());
            conn_rows.push_str(&format!(
                r#"<li><span><code>{name}</code></span>
  <form method="post" action="/account/connections/revoke" data-confirm="Disconnect this client?">{csrf}<input type="hidden" name="client_id" value="{cid}"><button class="ghost danger">Disconnect</button></form></li>"#,
                name = esc(&name),
                csrf = csrf,
                cid = esc(&c.client_id),
            ));
        }
        conn_rows.push_str("</ul>");
    }

    let sessions = session::list_for_user(&state.db, &user.id)
        .await
        .unwrap_or_default();
    let other_sessions = sessions.len().saturating_sub(1);

    let body = format!(
        r#"<header class="row"><h1>Account</h1><a href="/">← Back</a></header>
<p>Signed in as <strong>{handle}</strong></p>
<section>
  <h2>Passkeys</h2>
  <p class="muted">Add a second passkey (another device or a hardware key) so you are not locked out if you lose one.</p>
  {rows}
  <button id="add-passkey-btn" type="button">Add a passkey</button>
  <p class="error" id="add-passkey-error"></p>
</section>
<section style="margin-top:18px">
  <h2>Connected MCP clients</h2>
  <p class="muted">Clients you have authorized to reach your MCP endpoint. Disconnecting revokes refresh access; any active token still works until it expires (≤15 min).</p>
  {conn_rows}
</section>
<section style="margin-top:18px">
  <h2>Browser sessions</h2>
  <p class="muted">You have {n_sessions} active session(s){other}.</p>
  {sign_out_others}
</section>"#,
        handle = esc(&user.handle),
        rows = rows,
        conn_rows = conn_rows,
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
    page("Account", &body).into_response()
}

/// `POST /account/sessions/revoke-others` — end every session but this one.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    let keep = session::current_session_id(&jar).unwrap_or_default();
    let _ = session::delete_others(&state.db, &user.id, &keep).await;
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
    Form(form): Form<RevokeConnectionForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    let _ =
        crate::oauth::store::revoke_user_client(&state.db, &user.id, form.client_id.trim()).await;
    Redirect::to("/account").into_response()
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
    Form(form): Form<RemovePasskeyForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
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
    page("Users", &body).into_response()
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
    form: &UserActionForm,
) -> Result<users::User, Response> {
    if !admin.is_admin {
        return Err(admin_forbidden());
    }
    if !session::check_csrf(jar, &state.config.master_key, &form.csrf) {
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
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(e) = deactivate_user(&state, &target.id).await {
        return error_page(&e.to_string());
    }
    Redirect::to("/users").into_response()
}

/// `POST /users/enable` — re-enable a disabled account.
pub async fn enable_user(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let _ = users::set_disabled(&state.db, &target.id, false).await;
    Redirect::to("/users").into_response()
}

/// `POST /users/delete` — delete an account and all its data.
pub async fn delete_user(
    State(state): State<AppState>,
    AuthUser(admin): AuthUser,
    jar: SignedCookieJar,
    Form(form): Form<UserActionForm>,
) -> Response {
    let target = match resolve_admin_target(&state, &admin, &jar, &form).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(e) = purge_user(&state, &target.id).await {
        return error_page(&e.to_string());
    }
    Redirect::to("/users").into_response()
}

/// Disable an account: set the flag, then end its sessions and tokens so the
/// revocation takes effect immediately.
pub async fn deactivate_user(state: &AppState, user_id: &str) -> anyhow::Result<()> {
    users::set_disabled(&state.db, user_id, true).await?;
    session::delete_all_for_user(&state.db, user_id).await?;
    crate::oauth::store::revoke_all_user_tokens(&state.db, user_id).await?;
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
