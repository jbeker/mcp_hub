//! The authorization endpoint and consent decision.
//!
//! `GET /authorize` validates the request, requires a passkey-authenticated
//! session (redirecting to `/login` otherwise), and renders a consent screen.
//! `POST /authorize/decision` issues the authorization code and redirects back
//! to the client.

use axum::extract::{Query, RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;

use crate::auth::session::AuthUser;
use crate::auth::MaybeUser;
use crate::oauth::{random_token, store};
use crate::AppState;

/// Signed cookie holding the validated authorization request across the
/// consent round-trip.
const AUTHREQ_COOKIE: &str = "hub_authreq";
const AUTH_CODE_TTL_SECS: i64 = 600;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

/// The validated request stashed in the signed cookie between the two steps.
#[derive(Serialize, Deserialize)]
struct PendingAuth {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    resource: Option<String>,
    user_id: String,
}

fn error_page(msg: &str) -> Response {
    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Authorization error</title>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto\">\
         <h1>Authorization error</h1><p>{}</p></body>",
        msg.replace('<', "&lt;")
    ))
    .into_response()
}

/// Append query parameters to a redirect URI and build a redirect response.
/// Classify an RFC 8707 `resource` value against our endpoints: `Ok(None)` for
/// the base `/mcp` endpoint, `Ok(Some(slug))` for a syntactically valid group
/// endpoint `/mcp/<slug>`, `Err(())` for anything else. A trailing slash is
/// tolerated (some clients normalize URLs that way).
fn resource_group_slug(
    resource: &str,
    config: &crate::config::Config,
) -> Result<Option<String>, ()> {
    let resource = resource.trim_end_matches('/');
    if resource == config.mcp_url() {
        return Ok(None);
    }
    let prefix = format!("{}/", config.mcp_url());
    match resource.strip_prefix(&prefix) {
        Some(slug) if crate::groups::valid_slug(slug) => Ok(Some(slug.to_string())),
        _ => Err(()),
    }
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match url::Url::parse(redirect_uri) {
        Ok(mut url) => {
            {
                let mut qp = url.query_pairs_mut();
                for (k, v) in params {
                    qp.append_pair(k, v);
                }
            }
            Redirect::to(url.as_str()).into_response()
        }
        Err(_) => error_page("invalid redirect_uri"),
    }
}

/// `GET /authorize`
pub async fn authorize(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    jar: SignedCookieJar,
    Query(q): Query<AuthorizeQuery>,
    RawQuery(raw): RawQuery,
) -> Response {
    // The client + redirect_uri must be validated before we trust the
    // redirect_uri enough to bounce errors back to it.
    let client = match store::get_client(&state.db, &q.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return error_page("unknown client_id"),
        Err(e) => return crate::oauth::OAuthError::from(e).into_response(),
    };
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return error_page("redirect_uri is not registered for this client");
    }

    // From here, protocol errors are returned to the client via redirect.
    let st = q.state.as_deref().unwrap_or("");
    if q.response_type != "code" {
        return redirect_with(
            &q.redirect_uri,
            &[("error", "unsupported_response_type"), ("state", st)],
        );
    }
    if q.code_challenge_method.as_deref().unwrap_or("S256") != "S256" {
        return redirect_with(
            &q.redirect_uri,
            &[
                ("error", "invalid_request"),
                ("error_description", "only S256 PKCE is supported"),
                ("state", st),
            ],
        );
    }
    if q.code_challenge.is_empty() {
        return redirect_with(
            &q.redirect_uri,
            &[
                ("error", "invalid_request"),
                ("error_description", "code_challenge is required"),
                ("state", st),
            ],
        );
    }
    // Bind the token to one of our resources: the base /mcp endpoint or a
    // connector-group endpoint /mcp/<slug>. Reject anything else outright;
    // whether the slug actually exists for this user is checked post-login.
    let group_slug = match &q.resource {
        None => None,
        Some(res) => match resource_group_slug(res, &state.config) {
            Ok(slug) => slug,
            Err(()) => {
                return redirect_with(
                    &q.redirect_uri,
                    &[("error", "invalid_target"), ("state", st)],
                );
            }
        },
    };

    // Require an authenticated human; otherwise send them to log in and return.
    let Some(user) = user else {
        let next = match raw {
            Some(r) => format!("/authorize?{r}"),
            None => "/authorize".to_string(),
        };
        let login = format!("/login?next={}", urlencode(&next));
        return Redirect::to(&login).into_response();
    };

    // A group resource must name one of *this user's* groups. Failing here —
    // at consent time — beats minting a token that 404s on first use.
    if let Some(slug) = &group_slug {
        match crate::groups::find_by_slug(&state.db, &user.id, slug).await {
            Ok(Some(_)) => {}
            _ => {
                return redirect_with(
                    &q.redirect_uri,
                    &[("error", "invalid_target"), ("state", st)],
                );
            }
        }
    }

    let pending = PendingAuth {
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone().unwrap_or_else(|| "mcp".into()),
        state: q.state.clone(),
        code_challenge: q.code_challenge.clone(),
        resource: q.resource.clone(),
        user_id: user.id.clone(),
    };
    let jar = jar.add(authreq_cookie(
        serde_json::to_string(&pending).unwrap_or_default(),
        state.config.cookie_secure(),
    ));

    let client_name = client.metadata["client_name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or(&q.client_id)
        .to_string();
    let csrf = crate::auth::session::csrf_field(&jar, &state.config.master_key);
    (
        jar,
        Html(consent_html(
            &client_name,
            &pending.scope,
            &user.handle,
            &csrf,
        )),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct Decision {
    pub decision: String,
    #[serde(default)]
    pub csrf: String,
}

/// `POST /authorize/decision`
pub async fn decision(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<Decision>,
) -> Response {
    let info = crate::auth::RequestInfo::from_headers(&headers);
    if !crate::auth::session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        crate::audit::event("oauth.consent")
            .actor(&user.handle)
            .actor_id(&user.id)
            .request(&info)
            .denied("csrf");
        return error_page("invalid security token; please restart authorization");
    }
    let Some(raw) = jar.get(AUTHREQ_COOKIE).map(|c| c.value().to_string()) else {
        return error_page("no authorization in progress");
    };
    let Ok(pending) = serde_json::from_str::<PendingAuth>(&raw) else {
        return error_page("invalid authorization request");
    };
    // The approving user must be the one the request was prepared for.
    if pending.user_id != user.id {
        return error_page("session mismatch; please restart authorization");
    }

    let jar = jar.add(clear_authreq_cookie(state.config.cookie_secure()));
    let st = pending.state.as_deref().unwrap_or("");

    if form.decision != "approve" {
        crate::audit::event("oauth.consent")
            .actor(&user.handle)
            .actor_id(&user.id)
            .client_id(Some(&pending.client_id))
            .request(&info)
            .object(&pending.client_id)
            .denied("declined");
        return (
            jar,
            redirect_with(
                &pending.redirect_uri,
                &[("error", "access_denied"), ("state", st)],
            ),
        )
            .into_response();
    }

    let code = random_token();
    if let Err(e) = store::insert_code(
        &state.auth_codes,
        &code,
        &pending.client_id,
        &user.id,
        &pending.redirect_uri,
        &pending.code_challenge,
        &pending.scope,
        pending.resource.as_deref(),
        AUTH_CODE_TTL_SECS,
    ) {
        return (jar, crate::oauth::OAuthError::from(e).into_response()).into_response();
    }

    crate::audit::event("oauth.consent")
        .actor(&user.handle)
        .actor_id(&user.id)
        .client_id(Some(&pending.client_id))
        .request(&info)
        .object(&pending.client_id)
        .ok();

    let mut params = vec![("code", code.as_str())];
    if !st.is_empty() {
        params.push(("state", st));
    }
    (jar, redirect_with(&pending.redirect_uri, &params)).into_response()
}

// ---------------------------------------------------------------------------
// Cookies + HTML
// ---------------------------------------------------------------------------
fn authreq_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(AUTHREQ_COOKIE, value);
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(secure);
    c.set_path("/");
    c.set_max_age(TimeDuration::seconds(AUTH_CODE_TTL_SECS));
    c
}

fn clear_authreq_cookie(secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(AUTHREQ_COOKIE, "");
    c.set_http_only(true);
    c.set_path("/");
    c.set_secure(secure);
    c.set_max_age(TimeDuration::seconds(0));
    c
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn consent_html(client_name: &str, scope: &str, handle: &str, csrf: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize · MCP Hub</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main class="card">
  <h1>Authorize access</h1>
  <p><strong>{client}</strong> wants to connect to your MCP Hub as <strong>{handle}</strong>.</p>
  <p class="muted">Requested scope: <code>{scope}</code></p>
  <form method="post" action="/authorize/decision">
    {csrf}
    <button name="decision" value="approve" type="submit">Authorize</button>
    <button name="decision" value="deny" type="submit" class="ghost" style="width:100%;margin-top:10px">Deny</button>
  </form>
</main></body></html>"#,
        csrf = csrf,
        client = esc(client_name),
        handle = esc(handle),
        scope = esc(scope),
    )
}
