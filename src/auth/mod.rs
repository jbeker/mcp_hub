//! Authentication: WebAuthn passkeys and browser sessions.

pub mod session;
pub mod webauthn;

pub use session::{AuthUser, MaybeUser};
