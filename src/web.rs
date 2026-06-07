//! Server-rendered web UI pages.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::SignedCookieJar;
use axum::Form;
use serde::Deserialize;

use crate::auth::session;
use crate::auth::{AuthUser, MaybeUser};
use crate::{catalog, instances, invites, AppState};

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
        rows.push_str(r#"<p class="muted">No servers configured yet. Browse the catalog to add one.</p>"#);
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
  <form method="post" action="/logout">{csrf}<button class="ghost">Sign out</button></form>
</header>
<p>Signed in as <strong>{handle}</strong> {badge}</p>
<section>
  <div class="row"><h2>Your MCP servers</h2><a href="/servers/catalog">Browse catalog →</a></div>
  {rows}
</section>
{admin_section}
<p class="muted">Your MCP endpoint: <code>{mcp}</code></p>"#,
        csrf = csrf,
        handle = esc(&user.handle),
        badge = admin_badge,
        rows = rows,
        admin_section = if user.is_admin {
            r#"<section><div class="row"><h2>Administration</h2><a href="/invites">Manage invites →</a></div></section>"#
        } else {
            ""
        },
        mcp = esc(&state.config.mcp_url()),
    );
    page("Dashboard", &body).into_response()
}

// ---------------------------------------------------------------------------
// Catalog browsing + adding instances
// ---------------------------------------------------------------------------

/// `/servers/catalog` — pick a server to add.
pub async fn catalog_page(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    jar: SignedCookieJar,
) -> Response {
    let csrf = session::csrf_field(&jar, &state.config.master_key);
    let entries = catalog::list(&state.db).await.unwrap_or_default();
    let mut cards = String::new();
    for e in &entries {
        let disabled = if e.supported { "" } else { "disabled" };
        let note = if e.supported {
            String::new()
        } else {
            r#"<p class="muted">Not supported in this version.</p>"#.to_string()
        };
        cards.push_str(&format!(
            r#"<div class="catalog-entry">
  <h3>{name} <span class="muted">({transport})</span></h3>
  <p class="muted">{desc}</p>
  {note}
  <form method="post" action="/servers/add">
    {csrf}
    <input type="hidden" name="catalog_id" value="{id}">
    <label>Namespace<input name="namespace" value="{slug}" required></label>
    <label>Display name<input name="display_name" value="{name}" required></label>
    <button type="submit" {disabled}>Add</button>
  </form>
</div>"#,
            csrf = csrf,
            name = esc(&e.name),
            transport = esc(&e.transport),
            desc = esc(&e.description),
            note = note,
            id = esc(&e.id),
            slug = esc(&e.slug),
            disabled = disabled,
        ));
    }
    let body = format!(
        r#"<header class="row"><h1>Catalog</h1><a href="/">← Back</a></header>{cards}"#
    );
    page("Catalog", &body).into_response()
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

#[derive(Deserialize)]
pub struct AddServerForm {
    #[serde(default)]
    pub csrf: String,
    pub catalog_id: String,
    pub namespace: String,
    pub display_name: String,
}

/// `POST /servers/add`
pub async fn add_server(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Form(form): Form<AddServerForm>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return forbidden();
    }
    let entry = match catalog::get(&state.db, &form.catalog_id).await {
        Ok(Some(e)) => e,
        _ => return error_page("unknown catalog entry"),
    };
    if !entry.supported {
        return error_page("that server is not supported in this version");
    }
    match instances::create(
        &state.db,
        &user.id,
        Some(&entry.id),
        None,
        form.namespace.trim(),
        form.display_name.trim(),
    )
    .await
    {
        Ok(inst) => Redirect::to(&format!("/servers/{}", inst.id)).into_response(),
        Err(e) => error_page(&e.to_string()),
    }
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
    let set_secrets = instances::secret_names(&state.db, &inst.id).await.unwrap_or_default();

    let mut fields = String::new();
    for f in &def.secret_schema {
        let label = if f.label.is_empty() { &f.name } else { &f.label };
        let req = if f.required { " *" } else { "" };
        if f.secret {
            let placeholder = if set_secrets.contains(&f.name) {
                "•••••• (leave blank to keep)"
            } else {
                ""
            };
            fields.push_str(&format!(
                r#"<label>{label}{req}<input name="{name}" type="password" placeholder="{ph}"></label>"#,
                label = esc(label),
                req = req,
                name = esc(&f.name),
                ph = placeholder,
            ));
        } else {
            let current = inst.config.get(&f.name).cloned().unwrap_or_default();
            fields.push_str(&format!(
                r#"<label>{label}{req}<input name="{name}" value="{val}"></label>"#,
                label = esc(label),
                req = req,
                name = esc(&f.name),
                val = esc(&current),
            ));
        }
    }
    if def.secret_schema.is_empty() {
        fields.push_str(r#"<p class="muted">This server needs no configuration.</p>"#);
    }

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
        id = esc(&inst.id),
        csrf = csrf,
        fields = fields,
        git_section = git_section,
        toggle = toggle,
    );
    page(&inst.display_name, &body).into_response()
}

/// `POST /servers/{id}/config` — save secret + non-secret fields.
pub async fn save_config(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !session::check_csrf(&jar, &state.config.master_key, form.get("csrf").map(String::as_str).unwrap_or("")) {
        return forbidden();
    }
    let Some(inst) = instances::get_owned(&state.db, &id, &user.id).await.ok().flatten() else {
        return error_page("server not found");
    };
    let def = match instances::resolve_def(&state.db, &inst).await {
        Ok(d) => d,
        Err(e) => return error_page(&e.to_string()),
    };
    for f in &def.secret_schema {
        let Some(value) = form.get(&f.name) else { continue };
        if value.is_empty() {
            // Blank secret means "leave unchanged"; blank non-secret clears it.
            if f.secret {
                continue;
            }
        }
        let res = if f.secret {
            instances::set_secret(&state.db, &state.secrets, &inst.id, &f.name, value).await
        } else {
            instances::set_config_value(&state.db, &inst.id, &f.name, value).await
        };
        if let Err(e) = res {
            return error_page(&e.to_string());
        }
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
    match crate::gitsrc::update_instance(&state.db, &state.config.env_dir, &inst, &def).await {
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
<section style="margin-top:18px">{rows}</section>"#,
        csrf = csrf,
        rows = rows,
    );
    page("Invites", &body).into_response()
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
<p class="muted">Need an account? <a href="/register">Register</a></p>"#;
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
