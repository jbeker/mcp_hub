//! Browser session cookies and the request extractors that load the
//! authenticated user from them.

use anyhow::{Context, Result};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use base64::Engine;
use sqlx::SqlitePool;
use time::Duration as TimeDuration;

use crate::users::{self, User};
use crate::util::{new_id, now_unix};
use crate::AppState;

/// Name of the signed session cookie.
pub const SESSION_COOKIE: &str = "hub_session";
/// Cookie carrying a post-login redirect target (e.g. an in-flight /authorize).
pub const NEXT_COOKIE: &str = "hub_next";
/// Minimum seconds a session's idle deadline must advance before we write it
/// back — throttles the per-request slide to one DB update per minute of use.
const SESSION_TOUCH_THROTTLE_SECS: i64 = 60;

/// Validate that a redirect target is a safe same-origin path.
///
/// Only a path beginning with a single `/` is allowed. Backslashes and control
/// characters are rejected because browsers normalize `\` to `/`, so values like
/// `/\evil.com` would otherwise become the protocol-relative `//evil.com`.
pub fn safe_next(path: &str) -> Option<String> {
    let valid = path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.contains(|c: char| c.is_control());
    valid.then(|| path.to_string())
}

/// Build the short-lived cookie storing a post-login redirect target.
pub fn next_cookie(path: String, secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(NEXT_COOKIE, path);
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(secure);
    c.set_path("/");
    c.set_max_age(TimeDuration::seconds(600));
    c
}

/// Clear the next-redirect cookie.
pub fn clear_next_cookie(secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(NEXT_COOKIE, "");
    c.set_http_only(true);
    c.set_path("/");
    c.set_secure(secure);
    c.set_max_age(TimeDuration::seconds(0));
    c
}

/// Read and validate the post-login redirect target, defaulting to `/`.
pub fn take_next(jar: &SignedCookieJar) -> String {
    jar.get(NEXT_COOKIE)
        .and_then(|c| safe_next(c.value()))
        .unwrap_or_else(|| "/".to_string())
}

// ---------------------------------------------------------------------------
// CSRF tokens (synchronizer token, derived from the session secret)
// ---------------------------------------------------------------------------

/// Derive a CSRF token from the session id. The session id is a high-entropy
/// secret held only in an HttpOnly signed cookie, so a cross-site attacker
/// cannot compute this token, while same-origin pages can embed it.
fn csrf_token(master_key: &[u8; 32], session_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hub-csrf-v1");
    h.update(master_key);
    h.update(session_id.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

fn session_id(jar: &SignedCookieJar) -> Option<String> {
    jar.get(SESSION_COOKIE).map(|c| c.value().to_string())
}

/// The CSRF token for the current session, or `None` if unauthenticated.
pub fn csrf_for(jar: &SignedCookieJar, master_key: &[u8; 32]) -> Option<String> {
    session_id(jar).map(|sid| csrf_token(master_key, &sid))
}

/// A ready-to-embed hidden form field carrying the CSRF token.
pub fn csrf_field(jar: &SignedCookieJar, master_key: &[u8; 32]) -> String {
    match csrf_for(jar, master_key) {
        Some(t) => format!(r#"<input type="hidden" name="csrf" value="{t}">"#),
        None => String::new(),
    }
}

/// Constant-time check of a submitted CSRF token against the session's token.
pub fn check_csrf(jar: &SignedCookieJar, master_key: &[u8; 32], submitted: &str) -> bool {
    match csrf_for(jar, master_key) {
        Some(expected) => constant_time_eq(expected.as_bytes(), submitted.as_bytes()),
        None => false,
    }
}

/// Length-aware constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Create a session row for a user and return its id. The request's IP and
/// User-Agent are stored as the session's origin (shown on the Account page).
/// `expires_at` is the initial idle deadline (`now + idle_ttl_secs`); it slides
/// forward on activity in [`load_and_touch`], bounded by the absolute cap.
pub async fn create(
    pool: &SqlitePool,
    user_id: &str,
    info: &super::RequestInfo,
    idle_ttl_secs: i64,
) -> Result<String> {
    let id = new_id();
    let now = now_unix();
    sqlx::query(
        "INSERT INTO web_sessions (id, user_id, created_at, expires_at, last_ip, last_user_agent)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(now)
    .bind(now + idle_ttl_secs)
    .bind(info.ip.as_deref())
    .bind(info.user_agent.as_deref())
    .execute(pool)
    .await
    .context("creating session")?;
    Ok(id)
}

/// Delete a session row (logout).
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM web_sessions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A browser session belonging to a user (no secret material).
pub struct SessionInfo {
    pub id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_ip: Option<String>,
    pub last_user_agent: Option<String>,
}

/// Columns selected from `web_sessions` for the account listing.
type SessionRow = (String, i64, i64, Option<String>, Option<String>);

/// List a user's active (unexpired) sessions, newest first.
pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<SessionInfo>> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT id, created_at, expires_at, last_ip, last_user_agent FROM web_sessions \
         WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .bind(now_unix())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, created_at, expires_at, last_ip, last_user_agent)| SessionInfo {
                id,
                created_at,
                expires_at,
                last_ip,
                last_user_agent,
            },
        )
        .collect())
}

/// Delete all of a user's sessions except `keep` (sign out other devices).
/// Returns the number of sessions ended.
pub async fn delete_others(pool: &SqlitePool, user_id: &str, keep: &str) -> Result<u64> {
    let res = sqlx::query("DELETE FROM web_sessions WHERE user_id = ? AND id <> ?")
        .bind(user_id)
        .bind(keep)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Delete every session for a user (used when disabling the account).
pub async fn delete_all_for_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM web_sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Read the current session id from a signed cookie jar (for "keep this one").
pub fn current_session_id(jar: &SignedCookieJar) -> Option<String> {
    jar.get(SESSION_COOKIE).map(|c| c.value().to_string())
}

/// Load the user behind a session id, if the session exists and is unexpired.
/// Validation only (no slide) — used off the request-serving path (e.g. logout
/// audit). The request extractors use [`load_and_touch`] instead.
pub async fn user_for_session(pool: &SqlitePool, session_id: &str) -> Result<Option<User>> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT user_id, expires_at FROM web_sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    let Some((user_id, expires_at)) = row else {
        return Ok(None);
    };
    if expires_at < now_unix() {
        let _ = delete(pool, session_id).await;
        return Ok(None);
    }
    users::find_by_id(pool, &user_id).await
}

/// Load the user behind a session id and slide its idle deadline forward. This
/// is the request-path variant: it enforces both the idle timeout and the
/// absolute cap, and refreshes `expires_at` so an active session stays alive.
///
/// `expires_at` is the idle deadline; the absolute cap is `created_at +
/// absolute_ttl`. A session is valid only while **both** are in the future, so a
/// pre-existing long-lived session (huge `expires_at`, old `created_at`) is
/// rejected immediately by the absolute check rather than getting a one-request
/// grace. On each valid request the idle deadline slides to `min(now + idle_ttl,
/// created_at + absolute_ttl)`; the write is throttled (and also fires when the
/// stored deadline sits *above* the target, capping any legacy long session down).
pub async fn load_and_touch(
    pool: &SqlitePool,
    session_id: &str,
    idle_ttl_secs: i64,
    absolute_ttl_secs: i64,
) -> Result<Option<User>> {
    let row: Option<(String, i64, i64)> =
        sqlx::query_as("SELECT user_id, created_at, expires_at FROM web_sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    let Some((user_id, created_at, expires_at)) = row else {
        return Ok(None);
    };
    let now = now_unix();
    let absolute_deadline = created_at + absolute_ttl_secs;
    if expires_at <= now || absolute_deadline <= now {
        let _ = delete(pool, session_id).await;
        return Ok(None);
    }
    let target = (now + idle_ttl_secs).min(absolute_deadline);
    if expires_at > target || target - expires_at > SESSION_TOUCH_THROTTLE_SECS {
        let _ = sqlx::query("UPDATE web_sessions SET expires_at = ? WHERE id = ?")
            .bind(target)
            .bind(session_id)
            .execute(pool)
            .await;
    }
    users::find_by_id(pool, &user_id).await
}

/// Delete every session whose idle deadline has passed. Called periodically by
/// the background sweeper; expired rows never authenticate, so this is only
/// housekeeping to keep the table from accumulating dead rows.
pub async fn delete_expired(pool: &SqlitePool) -> Result<u64> {
    let res = sqlx::query("DELETE FROM web_sessions WHERE expires_at < ?")
        .bind(now_unix())
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Build the session cookie for a freshly created session id. Deliberately a
/// *session cookie* (no `Max-Age`): the browser drops it on close, and the
/// server-side idle/absolute deadlines are the real timeout. The cookie only
/// carries the (secret) session id.
pub fn session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, session_id);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie
}

/// A cleared session cookie for logout.
pub fn clear_session_cookie(secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, "");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie.set_max_age(TimeDuration::seconds(0));
    cookie
}

/// Read the session id from the signed cookie jar in the request.
fn session_id_from_parts(parts: &Parts, state: &AppState) -> Option<String> {
    let jar = SignedCookieJar::from_headers(&parts.headers, state.cookie_key.clone());
    jar.get(SESSION_COOKIE).map(|c| c.value().to_string())
}

/// Extractor that requires an authenticated user; redirects to `/login` otherwise.
pub struct AuthUser(pub User);

/// Rejection that redirects unauthenticated requests to the login page.
pub struct LoginRedirect;

impl IntoResponse for LoginRedirect {
    fn into_response(self) -> Response {
        Redirect::to("/login").into_response()
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = LoginRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, LoginRedirect> {
        let Some(sid) = session_id_from_parts(parts, state) else {
            return Err(LoginRedirect);
        };
        match load_and_touch(
            &state.db,
            &sid,
            state.config.session_idle_ttl_secs,
            state.config.session_absolute_ttl_secs,
        )
        .await
        {
            Ok(Some(user)) => Ok(AuthUser(user)),
            _ => Err(LoginRedirect),
        }
    }
}

/// Extractor that optionally loads the user without rejecting anonymous requests.
pub struct MaybeUser(pub Option<User>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = match session_id_from_parts(parts, state) {
            Some(sid) => load_and_touch(
                &state.db,
                &sid,
                state.config.session_idle_ttl_secs,
                state.config.session_absolute_ttl_secs,
            )
            .await
            .ok()
            .flatten(),
            None => None,
        };
        Ok(MaybeUser(user))
    }
}

#[cfg(test)]
mod tests {
    use super::safe_next;

    #[test]
    fn accepts_local_paths() {
        assert_eq!(safe_next("/").as_deref(), Some("/"));
        assert_eq!(
            safe_next("/authorize?x=1").as_deref(),
            Some("/authorize?x=1")
        );
        assert_eq!(safe_next("/servers/abc").as_deref(), Some("/servers/abc"));
    }

    #[test]
    fn rejects_open_redirects() {
        assert_eq!(safe_next("//evil.com"), None);
        assert_eq!(safe_next("/\\evil.com"), None); // backslash -> // in browsers
        assert_eq!(safe_next("/\t/evil.com"), None); // control char
        assert_eq!(safe_next("https://evil.com"), None);
        assert_eq!(safe_next("evil.com"), None);
        assert_eq!(safe_next(""), None);
    }
}
