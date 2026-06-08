//! Structured audit logging.
//!
//! Every meaningful admin or client action funnels through [`event`] so the
//! emitted fields are identical across the web and MCP surfaces and a log
//! aggregator (Datadog, …) can index them. Events use the `audit` tracing
//! target and carry a consistent field set:
//!
//! `action` (dotted verb, e.g. `server.add`), `actor` (user handle), `actor_id`
//! (user id), `client_id` (OAuth client, empty for browser sessions / PATs),
//! `ip`, `user_agent`, `object` (the thing acted on), `outcome`
//! (`ok`/`denied`/`error`) and `detail`.
//!
//! All fields are always present; absent ones are logged as empty strings
//! (tracing has no `Value` impl for `Option`, and a fixed field set keeps the
//! output uniform).

use crate::auth::RequestInfo;

enum Level {
    Info,
    Warn,
}

/// A pending audit event. Build it with the fluent setters, then finish with
/// [`ok`](Event::ok), [`denied`](Event::denied) or [`failed`](Event::failed),
/// which emit a single structured tracing event.
#[must_use = "an audit event is only logged once .ok()/.denied()/.failed() is called"]
pub struct Event<'a> {
    action: &'a str,
    actor: &'a str,
    actor_id: &'a str,
    client_id: &'a str,
    ip: &'a str,
    user_agent: &'a str,
    object: &'a str,
}

/// Start an audit event for `action` (a dotted verb, e.g. `"server.add"`).
pub fn event(action: &str) -> Event<'_> {
    Event {
        action,
        actor: "",
        actor_id: "",
        client_id: "",
        ip: "",
        user_agent: "",
        object: "",
    }
}

impl<'a> Event<'a> {
    /// The human handle of the user performing the action.
    pub fn actor(mut self, handle: &'a str) -> Self {
        self.actor = handle;
        self
    }

    /// The stable id of the user performing the action.
    pub fn actor_id(mut self, id: &'a str) -> Self {
        self.actor_id = id;
        self
    }

    /// The OAuth client the action came through (empty for browser/PAT actions).
    pub fn client_id(mut self, id: Option<&'a str>) -> Self {
        self.client_id = id.unwrap_or("");
        self
    }

    /// The object acted on (a namespace, handle, token id, invite id, …).
    pub fn object(mut self, object: &'a str) -> Self {
        self.object = object;
        self
    }

    /// Fill `ip` and `user_agent` from a request's [`RequestInfo`].
    pub fn request(mut self, info: &'a RequestInfo) -> Self {
        self.ip = info.ip.as_deref().unwrap_or("");
        self.user_agent = info.user_agent.as_deref().unwrap_or("");
        self
    }

    /// A successful action.
    pub fn ok(self) {
        self.emit(Level::Info, "ok", "");
    }

    /// A refused action (authz/CSRF/validation), with a short machine reason.
    pub fn denied(self, reason: &str) {
        self.emit(Level::Warn, "denied", reason);
    }

    /// An action that errored, with a short detail.
    pub fn failed(self, detail: &str) {
        self.emit(Level::Warn, "error", detail);
    }

    fn emit(&self, level: Level, outcome: &str, detail: &str) {
        match level {
            Level::Info => tracing::info!(
                target: "audit",
                action = self.action,
                actor = self.actor,
                actor_id = self.actor_id,
                client_id = self.client_id,
                ip = self.ip,
                user_agent = self.user_agent,
                object = self.object,
                outcome = outcome,
                detail = detail,
            ),
            Level::Warn => tracing::warn!(
                target: "audit",
                action = self.action,
                actor = self.actor,
                actor_id = self.actor_id,
                client_id = self.client_id,
                ip = self.ip,
                user_agent = self.user_agent,
                object = self.object,
                outcome = outcome,
                detail = detail,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    fn capture(f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn emits_expected_fields() {
        let info = RequestInfo {
            ip: Some("1.2.3.4".into()),
            user_agent: Some("Claude".into()),
        };
        let out = capture(|| {
            event("server.add")
                .actor("alice")
                .actor_id("u1")
                .client_id(Some("hub_x"))
                .request(&info)
                .object("zbx")
                .ok();
        });
        for needle in [
            "server.add",
            "alice",
            "u1",
            "hub_x",
            "1.2.3.4",
            "zbx",
            "outcome",
            "\"ok\"",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in: {out}");
        }
    }

    #[test]
    fn denied_logs_reason_and_empty_optionals() {
        let out = capture(|| event("server.add").actor("bob").denied("csrf"));
        assert!(out.contains("csrf"));
        assert!(out.contains("denied"));
        // client_id was never set: present but empty.
        assert!(out.contains("client_id"));
    }
}
