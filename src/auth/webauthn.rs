//! WebAuthn (passkey) registration and authentication ceremonies.
//!
//! WebAuthn proves a *human's* identity to the hub. The challenge/response
//! ceremony is two round-trips: `start` issues a challenge and stashes the
//! server-side ceremony state (keyed by a short-lived signed cookie), and
//! `finish` verifies the authenticator's response.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::auth::session;
use crate::auth::AuthUser;
use crate::{invites, users};
use crate::AppState;

/// Name of the short-lived signed cookie tracking an in-flight ceremony.
const CEREMONY_COOKIE: &str = "hub_ceremony";
const CEREMONY_TTL_SECS: i64 = 300;
/// Hard cap on simultaneously in-flight ceremonies (a memory-DoS backstop).
const CEREMONY_CAP: usize = 4096;

/// What a passkey-registration ceremony does when it finishes.
pub enum RegPurpose {
    /// Create a brand-new account, optionally consuming an invite code.
    NewUser {
        is_admin: bool,
        /// Invite to consume at finish (None for the bootstrap admin or when
        /// open registration is enabled).
        invite_code: Option<String>,
    },
    /// Enroll an additional passkey onto an existing account. `recovery_code` is
    /// `Some` for an admin-issued recovery (consumed at finish); `None` when a
    /// logged-in user is adding a backup key.
    AddCredential { recovery_code: Option<String> },
}

/// In-flight registration ceremony state.
pub struct RegCeremony {
    pub state: PasskeyRegistration,
    /// The WebAuthn user handle, which is also the account's database id.
    pub user_id: Uuid,
    pub handle: String,
    pub display_name: String,
    pub purpose: RegPurpose,
    pub created_at: i64,
}

/// In-flight authentication ceremony state.
pub struct AuthCeremony {
    pub state: PasskeyAuthentication,
    pub user_id: String,
    pub created_at: i64,
}

/// Ceremony state that can be expired by age.
trait Expirable {
    fn created_at(&self) -> i64;
}
impl Expirable for RegCeremony {
    fn created_at(&self) -> i64 {
        self.created_at
    }
}
impl Expirable for AuthCeremony {
    fn created_at(&self) -> i64 {
        self.created_at
    }
}

/// Insert a ceremony after evicting expired entries, rejecting if the map is
/// full. This bounds memory use under a flood of `*/start` requests.
fn insert_ceremony<T: Expirable>(
    map: &Mutex<HashMap<String, T>>,
    key: String,
    value: T,
) -> Result<(), ApiError> {
    let now = crate::util::now_unix();
    let mut guard = map.lock().unwrap();
    guard.retain(|_, v| now - v.created_at() < CEREMONY_TTL_SECS);
    if guard.len() >= CEREMONY_CAP {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many sign-in attempts in progress; please try again shortly",
        ));
    }
    guard.insert(key, value);
    Ok(())
}

pub type RegStore = Arc<Mutex<HashMap<String, RegCeremony>>>;
pub type AuthStore = Arc<Mutex<HashMap<String, AuthCeremony>>>;

/// Build the configured Webauthn instance from the base URL + RP id.
pub fn build(base_url: &str, rp_id: &str) -> Result<Webauthn> {
    let origin = Url::parse(base_url)?;
    let webauthn = WebauthnBuilder::new(rp_id, &origin)?
        .rp_name("MCP Hub")
        .build()?;
    Ok(webauthn)
}

// ---------------------------------------------------------------------------
// JSON error helper
// ---------------------------------------------------------------------------
pub struct ApiError(StatusCode, String);

impl ApiError {
    fn new(code: StatusCode, msg: impl Into<String>) -> Self {
        ApiError(code, msg.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "internal error");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

// ---------------------------------------------------------------------------
// Ceremony cookie helpers
// ---------------------------------------------------------------------------
fn ceremony_cookie(id: String, secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(CEREMONY_COOKIE, id);
    c.set_http_only(true);
    c.set_same_site(SameSite::Lax);
    c.set_secure(secure);
    c.set_path("/");
    c.set_max_age(TimeDuration::seconds(CEREMONY_TTL_SECS));
    c
}

fn clear_ceremony_cookie(secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(CEREMONY_COOKIE, "");
    c.set_http_only(true);
    c.set_path("/");
    c.set_secure(secure);
    c.set_max_age(TimeDuration::seconds(0));
    c
}

fn ceremony_id(jar: &SignedCookieJar) -> Option<String> {
    jar.get(CEREMONY_COOKIE).map(|c| c.value().to_string())
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct RegisterStart {
    pub handle: String,
    pub display_name: String,
    /// Single-use invite code. Required for every account after the first,
    /// unless open registration is explicitly enabled.
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Serialize)]
pub struct FinishResponse {
    pub ok: bool,
    pub redirect: String,
}

pub async fn register_start(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(req): Json<RegisterStart>,
) -> Result<(SignedCookieJar, Json<CreationChallengeResponse>), ApiError> {
    let handle = req.handle.trim().to_string();
    let display_name = req.display_name.trim().to_string();
    if handle.is_empty() || display_name.is_empty() {
        return Err(bad("handle and display name are required"));
    }

    // Registration policy: the first account bootstraps the admin and needs no
    // invite. After that, registration is invite-only — each new account must
    // present a valid, unused single-use code — unless open registration has
    // been explicitly enabled.
    let count = users::count(&state.db).await.map_err(ApiError::from)?;
    let mut invite_code: Option<String> = None;
    let is_admin = if count == 0 {
        if let Some(want) = &state.config.bootstrap_admin {
            if &handle != want {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "the first account must use the configured HUB_BOOTSTRAP_ADMIN handle",
                ));
            }
        }
        true
    } else if state.config.allow_open_registration {
        false
    } else {
        let code = req.invite_code.as_deref().map(str::trim).unwrap_or("");
        if code.is_empty() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "an invite code is required to register; ask an administrator for one",
            ));
        }
        // Advisory pre-check for a clear error; the code is consumed atomically
        // at finish, which is the authoritative single-use guard.
        if !invites::is_redeemable(&state.db, code)
            .await
            .map_err(ApiError::from)?
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "that invite code is invalid or has already been used",
            ));
        }
        invite_code = Some(code.to_string());
        false
    };

    if users::find_by_handle(&state.db, &handle)
        .await
        .map_err(ApiError::from)?
        .is_some()
    {
        return Err(ApiError::new(StatusCode::CONFLICT, "that handle is taken"));
    }

    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &handle, &display_name, None)
        .map_err(|e| bad(format!("could not start registration: {e}")))?;

    let cid = crate::util::new_id();
    insert_ceremony(
        &state.reg_states,
        cid.clone(),
        RegCeremony {
            state: reg_state,
            user_id,
            handle,
            display_name,
            purpose: RegPurpose::NewUser {
                is_admin,
                invite_code,
            },
            created_at: crate::util::now_unix(),
        },
    )?;

    let jar = jar.add(ceremony_cookie(cid, state.config.cookie_secure()));
    Ok((jar, Json(ccr)))
}

/// Shared body for the two "enroll a passkey onto an existing account" flows:
/// a logged-in user adding a backup key, and an admin-issued recovery. Builds
/// the ceremony (excluding already-registered authenticators) and sets the
/// ceremony cookie.
async fn start_add_credential(
    state: &AppState,
    jar: SignedCookieJar,
    user: &users::User,
    recovery_code: Option<String>,
) -> Result<(SignedCookieJar, Json<CreationChallengeResponse>), ApiError> {
    let user_id = Uuid::parse_str(&user.id)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;

    // Exclude existing credentials so the same authenticator is not enrolled
    // twice (the browser will refuse and prompt for a different key).
    let existing = users::passkeys_for_user(&state.db, &user.id)
        .await
        .map_err(ApiError::from)?;
    let exclude: Vec<_> = existing.iter().map(|p| p.cred_id().clone()).collect();

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &user.handle, &user.display_name, Some(exclude))
        .map_err(|e| bad(format!("could not start enrollment: {e}")))?;

    let cid = crate::util::new_id();
    insert_ceremony(
        &state.reg_states,
        cid.clone(),
        RegCeremony {
            state: reg_state,
            user_id,
            handle: user.handle.clone(),
            display_name: user.display_name.clone(),
            purpose: RegPurpose::AddCredential { recovery_code },
            created_at: crate::util::now_unix(),
        },
    )?;

    let jar = jar.add(ceremony_cookie(cid, state.config.cookie_secure()));
    Ok((jar, Json(ccr)))
}

/// `POST /account/passkeys/add/start` — a logged-in user enrolls another passkey.
pub async fn add_passkey_start(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    jar: SignedCookieJar,
) -> Result<(SignedCookieJar, Json<CreationChallengeResponse>), ApiError> {
    start_add_credential(&state, jar, &user, None).await
}

/// Request body for starting account recovery.
#[derive(Deserialize)]
pub struct RecoverStart {
    pub handle: String,
    pub code: String,
}

/// `POST /auth/recover/start` — bind a new passkey to an existing account using
/// an admin-issued recovery code (for a user who has lost their authenticators).
pub async fn recover_start(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(req): Json<RecoverStart>,
) -> Result<(SignedCookieJar, Json<CreationChallengeResponse>), ApiError> {
    let handle = req.handle.trim();
    let code = req.code.trim();
    // One generic error for unknown handle / wrong code so recovery cannot be
    // used to probe which handles exist.
    let invalid = || ApiError::new(StatusCode::FORBIDDEN, "invalid handle or recovery code");
    let user = users::find_by_handle(&state.db, handle)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(invalid)?;
    if user.disabled {
        return Err(invalid());
    }
    if code.is_empty()
        || !invites::is_recovery_redeemable(&state.db, code, &user.id)
            .await
            .map_err(ApiError::from)?
    {
        return Err(invalid());
    }
    start_add_credential(&state, jar, &user, Some(code.to_string())).await
}

pub async fn register_finish(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> Result<(SignedCookieJar, Json<FinishResponse>), ApiError> {
    let info = super::RequestInfo::from_headers(&headers);
    let cid = ceremony_id(&jar).ok_or_else(|| bad("no registration in progress"))?;
    let ceremony = state
        .reg_states
        .lock()
        .unwrap()
        .remove(&cid)
        .ok_or_else(|| bad("registration expired; please try again"))?;

    let passkey: Passkey = state
        .webauthn
        .finish_passkey_registration(&cred, &ceremony.state)
        .map_err(|e| bad(format!("registration failed: {e}")))?;

    // Resolve the account this passkey belongs to, branching on the ceremony's
    // purpose: create a new account, or enroll onto an existing one.
    let user_id = match &ceremony.purpose {
        RegPurpose::NewUser {
            is_admin,
            invite_code,
        } => {
            // Guard against the handle being taken between start and finish.
            if users::find_by_handle(&state.db, &ceremony.handle)
                .await
                .map_err(ApiError::from)?
                .is_some()
            {
                return Err(ApiError::new(StatusCode::CONFLICT, "that handle is taken"));
            }
            // Decide admin atomically at insert time: the grant happens only if
            // this is still the first account (closes the bootstrap race).
            let user = if *is_admin {
                users::create_admin_if_first(
                    &state.db,
                    &ceremony.user_id.to_string(),
                    &ceremony.handle,
                    &ceremony.display_name,
                )
                .await
            } else {
                users::create(
                    &state.db,
                    &ceremony.user_id.to_string(),
                    &ceremony.handle,
                    &ceremony.display_name,
                    false,
                )
                .await
            }
            .map_err(ApiError::from)?;

            // Consume the invite now that the user row exists (used_by references
            // it). The conditional UPDATE is the single-use guard: a concurrent
            // registration that claimed the same code wins, and we roll this user
            // back so neither a duplicate account nor a double-spend occurs.
            if let Some(code) = invite_code {
                if let Err(e) = invites::redeem(&state.db, code, &user.id).await {
                    let _ = users::delete(&state.db, &user.id).await;
                    return Err(ApiError::new(StatusCode::CONFLICT, e.to_string()));
                }
            }
            crate::audit::event("auth.register")
                .actor(&user.handle)
                .actor_id(&user.id)
                .request(&info)
                .object(if user.is_admin { "admin" } else { "user" })
                .ok();
            user.id
        }
        RegPurpose::AddCredential { recovery_code } => {
            let user_id = ceremony.user_id.to_string();
            // For recovery, consume the code first (single-use); the account
            // already exists, so there is nothing to roll back on contention.
            if let Some(code) = recovery_code {
                invites::redeem(&state.db, code, &user_id)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::CONFLICT, e.to_string()))?;
                crate::audit::event("recovery.use")
                    .actor(&ceremony.handle)
                    .actor_id(&user_id)
                    .request(&info)
                    .ok();
            } else {
                crate::audit::event("passkey.add")
                    .actor(&ceremony.handle)
                    .actor_id(&user_id)
                    .request(&info)
                    .ok();
            }
            user_id
        }
    };

    users::insert_credential(&state.db, &user_id, &passkey, "passkey")
        .await
        .map_err(ApiError::from)?;

    let sid = session::create(&state.db, &user_id, &info)
        .await
        .map_err(ApiError::from)?;
    let secure = state.config.cookie_secure();
    let redirect = session::take_next(&jar);
    let jar = jar
        .add(session::session_cookie(sid, secure))
        .add(clear_ceremony_cookie(secure))
        .add(session::clear_next_cookie(secure));
    Ok((jar, Json(FinishResponse { ok: true, redirect })))
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct LoginStart {
    pub handle: String,
}

pub async fn login_start(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(req): Json<LoginStart>,
) -> Result<(SignedCookieJar, Json<RequestChallengeResponse>), ApiError> {
    let handle = req.handle.trim();
    // Use one generic error for both "unknown handle" and "no passkeys" so the
    // endpoint does not reveal which handles exist (user enumeration).
    let unknown = || ApiError::new(StatusCode::UNAUTHORIZED, "could not start sign-in");
    let user = users::find_by_handle(&state.db, handle)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(unknown)?;
    // A disabled account cannot sign in (same generic error, so being disabled
    // is not distinguishable from not existing).
    if user.disabled {
        return Err(unknown());
    }

    let passkeys = users::passkeys_for_user(&state.db, &user.id)
        .await
        .map_err(ApiError::from)?;
    if passkeys.is_empty() {
        return Err(unknown());
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| bad(format!("could not start authentication: {e}")))?;

    let cid = crate::util::new_id();
    insert_ceremony(
        &state.auth_states,
        cid.clone(),
        AuthCeremony {
            state: auth_state,
            user_id: user.id.clone(),
            created_at: crate::util::now_unix(),
        },
    )?;

    let jar = jar.add(ceremony_cookie(cid, state.config.cookie_secure()));
    Ok((jar, Json(rcr)))
}

pub async fn login_finish(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Json(cred): Json<PublicKeyCredential>,
) -> Result<(SignedCookieJar, Json<FinishResponse>), ApiError> {
    let info = super::RequestInfo::from_headers(&headers);
    let cid = ceremony_id(&jar).ok_or_else(|| bad("no login in progress"))?;
    let ceremony = state
        .auth_states
        .lock()
        .unwrap()
        .remove(&cid)
        .ok_or_else(|| bad("login expired; please try again"))?;

    let result = match state
        .webauthn
        .finish_passkey_authentication(&cred, &ceremony.state)
    {
        Ok(r) => r,
        Err(e) => {
            crate::audit::event("auth.login_failed")
                .actor_id(&ceremony.user_id)
                .request(&info)
                .denied("bad_assertion");
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                format!("login failed: {e}"),
            ));
        }
    };

    // Advance the stored signature counter if the authenticator reports a change.
    if result.needs_update() {
        if let Ok(passkeys) = users::passkeys_for_user(&state.db, &ceremony.user_id).await {
            if let Some(mut pk) = passkeys
                .into_iter()
                .find(|pk| pk.cred_id().as_ref() == result.cred_id().as_ref())
            {
                pk.update_credential(&result);
                let _ = users::update_credential(&state.db, &pk).await;
            }
        }
    }

    // Record where this passkey was last used (best-effort; failure is non-fatal).
    let _ = users::touch_credential(
        &state.db,
        result.cred_id().as_ref(),
        &info,
    )
    .await;

    let sid = session::create(&state.db, &ceremony.user_id, &info)
        .await
        .map_err(ApiError::from)?;
    let handle = users::find_by_id(&state.db, &ceremony.user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.handle)
        .unwrap_or_default();
    crate::audit::event("auth.login")
        .actor(&handle)
        .actor_id(&ceremony.user_id)
        .request(&info)
        .ok();
    let secure = state.config.cookie_secure();
    let redirect = session::take_next(&jar);
    let jar = jar
        .add(session::session_cookie(sid, secure))
        .add(clear_ceremony_cookie(secure))
        .add(session::clear_next_cookie(secure));
    Ok((jar, Json(FinishResponse { ok: true, redirect })))
}

/// Form body for logout (carries the CSRF token).
#[derive(serde::Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    pub csrf: String,
}

/// Log out: delete the session and clear the cookie.
pub async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    axum::Form(form): axum::Form<LogoutForm>,
) -> axum::response::Response {
    if !session::check_csrf(&jar, &state.config.master_key, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid security token").into_response();
    }
    let info = super::RequestInfo::from_headers(&headers);
    if let Some(sid) = jar.get(session::SESSION_COOKIE).map(|c| c.value().to_string()) {
        // Resolve the actor before deleting the session, for the audit log.
        let user = session::user_for_session(&state.db, &sid).await.ok().flatten();
        let _ = session::delete(&state.db, &sid).await;
        if let Some(u) = user {
            crate::audit::event("auth.logout")
                .actor(&u.handle)
                .actor_id(&u.id)
                .request(&info)
                .ok();
        }
    }
    let jar = jar.add(session::clear_session_cookie(state.config.cookie_secure()));
    (jar, axum::response::Redirect::to("/login")).into_response()
}
