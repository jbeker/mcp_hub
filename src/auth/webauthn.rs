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
use axum::http::StatusCode;
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
use crate::users;
use crate::AppState;

/// Name of the short-lived signed cookie tracking an in-flight ceremony.
const CEREMONY_COOKIE: &str = "hub_ceremony";
const CEREMONY_TTL_SECS: i64 = 300;
/// Hard cap on simultaneously in-flight ceremonies (a memory-DoS backstop).
const CEREMONY_CAP: usize = 4096;

/// In-flight registration ceremony state.
pub struct RegCeremony {
    pub state: PasskeyRegistration,
    pub user_id: Uuid,
    pub handle: String,
    pub display_name: String,
    pub is_admin: bool,
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

    // Registration policy: first user bootstraps admin; later users only if open.
    let count = users::count(&state.db).await.map_err(ApiError::from)?;
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
    } else {
        if !state.config.allow_open_registration {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "registration is closed; ask an administrator for an account",
            ));
        }
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
            is_admin,
            created_at: crate::util::now_unix(),
        },
    )?;

    let jar = jar.add(ceremony_cookie(cid, state.config.cookie_secure()));
    Ok((jar, Json(ccr)))
}

pub async fn register_finish(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> Result<(SignedCookieJar, Json<FinishResponse>), ApiError> {
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

    // Guard against a race where the handle was taken between start and finish.
    if users::find_by_handle(&state.db, &ceremony.handle)
        .await
        .map_err(ApiError::from)?
        .is_some()
    {
        return Err(ApiError::new(StatusCode::CONFLICT, "that handle is taken"));
    }

    let user = users::create(
        &state.db,
        &ceremony.user_id.to_string(),
        &ceremony.handle,
        &ceremony.display_name,
        ceremony.is_admin,
    )
    .await
    .map_err(ApiError::from)?;
    users::insert_credential(&state.db, &user.id, &passkey, "passkey")
        .await
        .map_err(ApiError::from)?;

    tracing::info!(handle = %user.handle, is_admin = user.is_admin, "registered new user");

    let sid = session::create(&state.db, &user.id)
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
    Json(cred): Json<PublicKeyCredential>,
) -> Result<(SignedCookieJar, Json<FinishResponse>), ApiError> {
    let cid = ceremony_id(&jar).ok_or_else(|| bad("no login in progress"))?;
    let ceremony = state
        .auth_states
        .lock()
        .unwrap()
        .remove(&cid)
        .ok_or_else(|| bad("login expired; please try again"))?;

    let result = state
        .webauthn
        .finish_passkey_authentication(&cred, &ceremony.state)
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, format!("login failed: {e}")))?;

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

    let sid = session::create(&state.db, &ceremony.user_id)
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

/// Log out: delete the session and clear the cookie.
pub async fn logout(State(state): State<AppState>, jar: SignedCookieJar) -> impl IntoResponse {
    if let Some(sid) = jar.get(session::SESSION_COOKIE).map(|c| c.value().to_string()) {
        let _ = session::delete(&state.db, &sid).await;
    }
    let jar = jar.add(session::clear_session_cookie(state.config.cookie_secure()));
    (jar, axum::response::Redirect::to("/login"))
}
