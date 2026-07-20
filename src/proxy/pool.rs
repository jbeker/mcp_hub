//! The per-user pool of live backend connections.
//!
//! Backends used to be owned by the MCP session that spawned them, so every
//! new session paid the full cold start (and clients that reconnect per
//! conversation — claude.ai — paid it constantly). The pool shares one set of
//! backends across all of a user's sessions: sessions *borrow* `Arc<Backend>`
//! snapshots, and the backends live until the idle reaper
//! (`HUB_BACKEND_IDLE_SECS`) retires them.
//!
//! Binds are budgeted (`HUB_BIND_BUDGET_SECS`): a (re)bind answers with
//! whatever connected inside the budget, and backends that miss it keep
//! connecting in the background, announcing themselves via
//! `notifications/tools/list_changed` when they arrive — so a slow backend can
//! no longer stall the first `tools/list` past the client's patience.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::instances;
use crate::proxy::backend::Backend;
use crate::AppState;

/// How long a backend that failed, crashed, or was skipped waits before the
/// pool tries to spawn it again. An explicit Restart (reload-epoch bump)
/// bypasses this. Keeps a crash-looping server from being respawned on every
/// request.
const RESPAWN_BACKOFF: Duration = Duration::from_secs(30);

/// All users' pooled backends. One per hub, held in [`AppState`].
#[derive(Default)]
pub struct BackendPool {
    users: Mutex<HashMap<String, Arc<UserBackends>>>,
}

/// One user's pooled backends plus the bookkeeping to keep them converged.
struct UserBackends {
    user_id: String,
    /// Serializes (re)binds so concurrent sessions of the same user never
    /// spawn duplicate backends. Never held across the `inner` lock's guard.
    bind_lock: tokio::sync::Mutex<()>,
    /// Brief, non-async critical sections only — never held across an await.
    inner: Mutex<Inner>,
}

struct Inner {
    /// A first bind has completed (possibly with pending background connects).
    initialized: bool,
    /// The user's server set changed (add/enable/disable/delete); the next
    /// request must reconcile against the DB.
    dirty: bool,
    backends: Vec<Arc<Backend>>,
    /// instance_id -> reload epoch applied, for every enabled instance seen at
    /// the last reconcile (running or not). Drives surgical restarts, and
    /// marks failed spawns as "tried at this epoch" so they are only retried
    /// after [`RESPAWN_BACKOFF`] or an explicit Restart.
    applied_epochs: HashMap<String, u64>,
    /// Instances whose spawn task is still connecting in the background.
    connecting: HashSet<String>,
    /// Last spawn attempt per instance, for [`RESPAWN_BACKOFF`].
    last_attempt: HashMap<String, Instant>,
    /// Consecutive failed heartbeats per instance (see [`exercise_all`]);
    /// cleared on a passing heartbeat and on respawn.
    heartbeat_failures: HashMap<String, u32>,
    /// Slides forward on every borrow; the idle reaper compares against it.
    last_used: Instant,
}

impl Inner {
    fn new() -> Self {
        Self {
            initialized: false,
            dirty: false,
            backends: Vec::new(),
            applied_epochs: HashMap::new(),
            connecting: HashSet::new(),
            last_attempt: HashMap::new(),
            heartbeat_failures: HashMap::new(),
            last_used: Instant::now(),
        }
    }

    /// Whether the pooled set can be served as-is, without touching the DB.
    /// This is the per-request hot path: a cheap in-memory scan.
    fn is_fresh(&self, state: &AppState) -> bool {
        if !self.initialized || self.dirty {
            return false;
        }
        for (id, applied) in &self.applied_epochs {
            if state.reload_epoch(id) != *applied {
                return false; // Restart button: respawn now
            }
            if self.connecting.contains(id) {
                continue; // already on its way
            }
            let healthy = self
                .backends
                .iter()
                .any(|b| &b.instance_id == id && !b.is_closed());
            if !healthy && self.retry_due(id) {
                return false; // dead or never started, and its backoff elapsed
            }
        }
        true
    }

    fn retry_due(&self, id: &str) -> bool {
        self.last_attempt
            .get(id)
            .is_none_or(|t| t.elapsed() >= RESPAWN_BACKOFF)
    }
}

impl BackendPool {
    /// The current live backends for `user_id`, (re)binding first if the
    /// pooled set is stale. The returned `Arc`s keep their backends alive for
    /// the duration of the caller's request even if the pool drops them.
    pub async fn backends_for(&self, state: &AppState, user_id: &str) -> Vec<Arc<Backend>> {
        let ub = self.entry(user_id);
        {
            let mut inner = ub.inner.lock().unwrap();
            inner.last_used = Instant::now();
            if inner.is_fresh(state) {
                return inner.backends.clone();
            }
        }
        // Slow path. Whoever wins the bind lock reconciles; the others see a
        // fresh set on their re-check and return immediately.
        let _bind = ub.bind_lock.lock().await;
        {
            let inner = ub.inner.lock().unwrap();
            if inner.is_fresh(state) {
                return inner.backends.clone();
            }
        }
        ub.clone().reconcile(state).await;
        let backends = ub.inner.lock().unwrap().backends.clone();
        backends
    }

    /// Flag a user's pooled set as stale after their server list changed
    /// (add/enable/disable/delete), so the next request reconciles against the
    /// DB. A user with no pooled entry needs nothing — their next bind reads
    /// the DB anyway.
    pub fn mark_dirty(&self, user_id: &str) {
        if let Some(ub) = self.users.lock().unwrap().get(user_id) {
            ub.inner.lock().unwrap().dirty = true;
        }
    }

    /// Drop every user entry idle for longer than `idle` (last borrow, not
    /// last spawn). Dropping the entry drops its `Arc<Backend>`s, which kills
    /// the stdio children once in-flight borrows finish. Returns
    /// `(users, backends)` reaped.
    pub fn reap_idle(&self, idle: Duration) -> (usize, usize) {
        let mut reaped = Vec::new();
        {
            let mut users = self.users.lock().unwrap();
            users.retain(|_, ub| {
                let inner = ub.inner.lock().unwrap();
                if inner.last_used.elapsed() >= idle {
                    reaped.push(ub.clone());
                    false
                } else {
                    true
                }
            });
        }
        let backends = reaped
            .iter()
            .map(|ub| ub.inner.lock().unwrap().backends.len())
            .sum();
        (reaped.len(), backends) // drop of `reaped` tears the backends down
    }

    /// Live pool counts for the stats page: `(users, backends)`.
    pub fn counts(&self) -> (usize, usize) {
        let users = self.users.lock().unwrap();
        let backends = users
            .values()
            .map(|ub| ub.inner.lock().unwrap().backends.len())
            .sum();
        (users.len(), backends)
    }

    fn entry(&self, user_id: &str) -> Arc<UserBackends> {
        self.users
            .lock()
            .unwrap()
            .entry(user_id.to_string())
            .or_insert_with(|| {
                Arc::new(UserBackends {
                    user_id: user_id.to_string(),
                    bind_lock: tokio::sync::Mutex::new(()),
                    inner: Mutex::new(Inner::new()),
                })
            })
            .clone()
    }
}

impl UserBackends {
    /// Converge the pooled set on the DB: drop disabled/deleted backends,
    /// respawn dead or Restart-bumped ones, spawn new ones — waiting at most
    /// the bind budget before returning what's ready. Callers hold
    /// `bind_lock`.
    async fn reconcile(self: Arc<Self>, state: &AppState) {
        let t0 = Instant::now();
        let first_bind = !self.inner.lock().unwrap().initialized;

        let all = match instances::list_for_user(&state.db, &self.user_id).await {
            Ok(i) => i,
            Err(e) => {
                // Leave the entry untouched (and a first bind uninitialized)
                // so the next request retries.
                tracing::error!(error = %e, "listing instances failed");
                return;
            }
        };
        let enabled: Vec<instances::Instance> = all.into_iter().filter(|i| i.enabled).collect();

        // The per-user sandbox identity for stdio subprocesses. Fail closed:
        // if sandboxing is configured but unavailable, spawn nothing new
        // (existing live backends are left alone) rather than running user
        // commands as root. `last_attempt` is stamped below so the retry
        // cadence is RESPAWN_BACKOFF, not every request.
        let sandbox = match state.sandbox_or_fail(&self.user_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "bind skipped: sandbox unavailable");
                let now = Instant::now();
                {
                    let mut inner = self.inner.lock().unwrap();
                    inner.dirty = false;
                    inner.initialized = true;
                    for inst in &enabled {
                        inner
                            .applied_epochs
                            .insert(inst.id.clone(), state.reload_epoch(&inst.id));
                        inner.last_attempt.insert(inst.id.clone(), now);
                    }
                }
                mark_skipped(state, &enabled, &format!("sandbox unavailable: {e:#}"));
                return;
            }
        };

        // Decide fates under one brief lock: keep healthy current backends,
        // drop the rest, and claim (connecting + slot permit) what to spawn.
        let per_user_cap = state.config.limits.max_backends_per_user;
        let enabled_ids: HashSet<&str> = enabled.iter().map(|i| i.id.as_str()).collect();
        let mut to_spawn: Vec<(instances::Instance, tokio::sync::OwnedSemaphorePermit)> = Vec::new();
        let mut skipped: Vec<(instances::Instance, &'static str)> = Vec::new();
        {
            let mut inner = self.inner.lock().unwrap();
            inner.dirty = false;
            // Disabled/deleted instances: backend dropped (child killed once
            // the last borrow ends), tracking removed.
            inner
                .backends
                .retain(|b| enabled_ids.contains(b.instance_id.as_str()));
            inner
                .applied_epochs
                .retain(|id, _| enabled_ids.contains(id.as_str()));
            inner
                .heartbeat_failures
                .retain(|id, _| enabled_ids.contains(id.as_str()));
            for inst in &enabled {
                if inner.connecting.contains(&inst.id) {
                    continue;
                }
                let cur = state.reload_epoch(&inst.id);
                let epoch_ok = inner.applied_epochs.get(&inst.id) == Some(&cur);
                let pos = inner
                    .backends
                    .iter()
                    .position(|b| b.instance_id == inst.id);
                if epoch_ok && pos.is_some_and(|p| !inner.backends[p].is_closed()) {
                    continue; // healthy and current
                }
                if epoch_ok && !inner.retry_due(&inst.id) {
                    // Crashed/failed recently; keep it out of rotation until
                    // the backoff elapses (a Restart bump bypasses this).
                    continue;
                }
                if inner.backends.len() + inner.connecting.len() + to_spawn.len() >= per_user_cap {
                    tracing::warn!(cap = per_user_cap, "per-user backend cap reached");
                    // Track skipped instances too (epoch + attempt stamp) so a
                    // Restart bump — or the backoff elapsing once capacity
                    // frees up — retries them.
                    inner.applied_epochs.insert(inst.id.clone(), cur);
                    inner.last_attempt.insert(inst.id.clone(), Instant::now());
                    skipped.push((inst.clone(), "per-user backend cap reached"));
                    continue;
                }
                let permit = match state.backend_slots.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("global backend capacity reached");
                        inner.applied_epochs.insert(inst.id.clone(), cur);
                        inner.last_attempt.insert(inst.id.clone(), Instant::now());
                        skipped.push((inst.clone(), "global backend capacity reached"));
                        continue;
                    }
                };
                if let Some(p) = pos {
                    inner.backends.remove(p); // stale/dead; Drop kills it
                }
                inner.applied_epochs.insert(inst.id.clone(), cur);
                inner.last_attempt.insert(inst.id.clone(), Instant::now());
                inner.heartbeat_failures.remove(&inst.id);
                inner.connecting.insert(inst.id.clone());
                to_spawn.push((inst.clone(), permit));
            }
        }
        for (inst, reason) in &skipped {
            mark_status(state, inst, crate::status::RuntimeState::Skipped, Some(reason));
        }

        // Spawn concurrently as detached tasks: each pushes itself into the
        // pool when it connects, and — if the bind budget has already expired
        // (`late`) — announces itself with tools/list_changed so clients
        // re-fetch. The `late` flag is set *before* the final snapshot below,
        // so a backend either makes the snapshot or sees the flag; none fall
        // through the gap silently.
        let attempted = to_spawn.len();
        let late = Arc::new(AtomicBool::new(false));
        let handles: Vec<_> = to_spawn
            .into_iter()
            .map(|(inst, permit)| {
                let state = state.clone();
                let ub = self.clone();
                let late = late.clone();
                let sandbox = sandbox.clone();
                tokio::spawn(async move {
                    let backend = spawn_one(&state, &inst, sandbox.as_ref(), permit).await;
                    let announce = {
                        let mut inner = ub.inner.lock().unwrap();
                        inner.connecting.remove(&inst.id);
                        match backend {
                            // Untracked means the instance was disabled or
                            // deleted while we were connecting: drop it.
                            Some(b) if inner.applied_epochs.contains_key(&inst.id) => {
                                inner.backends.push(Arc::new(b));
                                late.load(Ordering::SeqCst)
                            }
                            _ => false,
                        }
                    };
                    if announce {
                        state.notify_tools_changed(&ub.user_id);
                    }
                })
            })
            .collect();

        let budget = state.config.limits.bind_budget_secs;
        let wait = futures::future::join_all(handles);
        if budget == 0 {
            let _ = wait.await;
        } else if tokio::time::timeout(Duration::from_secs(budget), wait).await.is_err() {
            late.store(true, Ordering::SeqCst); // stragglers announce themselves
        }

        let (connected, pending) = {
            let mut inner = self.inner.lock().unwrap();
            inner.initialized = true;
            (inner.backends.len(), inner.connecting.len())
        };
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        if first_bind {
            tracing::info!(
                user = %self.user_id,
                connected,
                attempted,
                pending,
                elapsed_ms,
                "bound MCP session backends"
            );
        } else if attempted > 0 {
            tracing::info!(
                user = %self.user_id,
                connected,
                attempted,
                pending,
                elapsed_ms,
                "reconciled user backends"
            );
        }
    }
}

/// Resolve, launch, and initialize a single backend, recording its connection
/// outcome. Returns the live [`Backend`] on success, or `None` (with the
/// instance's status marked) on any failure — so a bad backend can't take
/// down the pool.
async fn spawn_one(
    state: &AppState,
    inst: &instances::Instance,
    sandbox: Option<&crate::sandbox::Sandbox>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Option<Backend> {
    let mut def = match instances::resolve_def(&state.db, inst).await {
        Ok(d) => d,
        Err(e) => {
            mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("resolve failed: {e:#}")));
            return None;
        }
    };
    if def.transport == "http" {
        let url = def.url.as_deref().unwrap_or("").trim();
        if url.is_empty() {
            mark_status(state, inst, crate::status::RuntimeState::Error, Some("no remote URL set"));
            return None;
        }
        // Re-resolve the host at connect time (not just at save) so the
        // SSRF guard also defeats DNS rebinding.
        if let Err(e) =
            instances::check_backend_host(url, state.config.block_private_backend_ips)
        {
            mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("{e}")));
            return None;
        }
    }
    // Git-sourced backends run from their prebuilt virtualenv. Rewrite
    // the def to a direct stdio exec; skip if it has not been built yet.
    if crate::gitsrc::is_git_source(&def) {
        let ready = inst.build_status == "ready"
            && crate::gitsrc::env_path(&state.config.env_dir, &inst.id).exists();
        // A venv from before the interpreter relocation can't exec under
        // the sandbox. Don't launch it (that yields a cryptic EACCES);
        // point the user at the one-click heal instead. Rebuilding here
        // would block every MCP connection on a slow build.
        if ready && crate::gitsrc::venv_is_stale(&state.config.env_dir, inst, &def) {
            mark_status(
                state,
                inst,
                crate::status::RuntimeState::Unbuilt,
                Some("needs rebuild after upgrade — open its page and click “Test connection”"),
            );
            return None;
        }
        if ready {
            match crate::gitsrc::launch_command(&state.config.env_dir, &inst.id, &def) {
                Ok((program, args)) => {
                    def.transport = "stdio".into();
                    def.command = Some(program);
                    def.args = args;
                }
                Err(e) => {
                    mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("git launch failed: {e:#}")));
                    return None;
                }
            }
        } else {
            mark_status(state, inst, crate::status::RuntimeState::Unbuilt, Some("not built yet; run hub__update_server"));
            return None;
        }
    }
    let env = match instances::resolved_env(&state.db, &state.secrets, inst).await {
        Ok(e) => e,
        Err(e) => {
            mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("config error: {e:#}")));
            return None;
        }
    };
    let config_file =
        match instances::resolved_config_file(&state.db, &state.secrets, &inst.id).await {
            Ok(c) => c,
            Err(e) => {
                mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("config error: {e:#}")));
                return None;
            }
        };
    let t0 = Instant::now();
    let result = Backend::spawn(
        &def,
        &env,
        inst.id.clone(),
        inst.namespace.clone(),
        inst.display_name.clone(),
        permit,
        sandbox,
        &state.config.env_dir,
        config_file.as_deref(),
        state.config.child_limits,
        state.config.limits.backend_connect_timeout_secs,
    )
    .await;
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    match result {
        Ok(b) => {
            tracing::info!(
                namespace = %inst.namespace,
                transport = %def.transport,
                elapsed_ms,
                "backend connected"
            );
            mark_status(state, inst, crate::status::RuntimeState::Ok, None);
            Some(b)
        }
        Err(e) => {
            tracing::info!(
                namespace = %inst.namespace,
                transport = %def.transport,
                elapsed_ms,
                error = %format!("{e:#}"),
                "backend connect failed"
            );
            mark_status(state, inst, crate::status::RuntimeState::Error, Some(&format!("failed to start: {e:#}")));
            None
        }
    }
}

/// Bind (or re-touch) the pooled backends of every non-disabled user with at
/// least one enabled server, so new connections always find hot tools. One
/// pass of the keep-warm loop (`HUB_KEEP_WARM`): the underlying
/// [`BackendPool::backends_for`] call does all the work — cold-binds missing
/// backends, respawns crashed ones after their backoff, reconciles dirty
/// pools, and slides `last_used` so the idle reaper leaves warmed pools
/// alone. Users warm sequentially (each user's backends already spawn
/// concurrently, bounded by the bind budget; stragglers finish in
/// background). Returns `(users_warmed, live_backends)`.
pub async fn warm_all(state: &AppState) -> (usize, usize) {
    let users = crate::users::list(&state.db).await.unwrap_or_default();
    let instances = instances::list_all(&state.db).await.unwrap_or_default();
    // Prune status entries for instances that no longer exist — a spawn task's
    // status write can race a delete's remove and re-insert an orphan.
    state
        .runtime_status
        .retain(&instances.iter().map(|i| i.id.clone()).collect());
    let with_enabled: HashSet<&str> = instances
        .iter()
        .filter(|i| i.enabled)
        .map(|i| i.user_id.as_str())
        .collect();
    let mut warmed = 0;
    let mut backends = 0;
    for user in users.iter().filter(|u| !u.disabled) {
        if !with_enabled.contains(user.id.as_str()) {
            continue;
        }
        backends += state.backend_pool.backends_for(state, &user.id).await.len();
        warmed += 1;
    }
    (warmed, backends)
}

/// How many consecutive failed heartbeats a backend may accumulate before
/// [`exercise_all`] drops it from the pool for respawn. One or two misses are
/// forgiven — a busy host can make a healthy child slow — but a genuinely
/// wedged child never recovers on its own.
const HEARTBEAT_MAX_STRIKES: u32 = 3;

/// Send one real `tools/list` to every pooled backend (the deep half of the
/// keep-warm loop, on the `HUB_KEEP_WARM_SECS` cadence). [`warm_all`] only
/// proves the child *exists*; this proves it *answers* — and the request
/// itself keeps the child's pages resident, so the first client request after
/// hours of idle doesn't stall on paging the process back in under host
/// memory/IO pressure. A backend that fails [`HEARTBEAT_MAX_STRIKES`]
/// heartbeats in a row is dropped from the pool; the next reconcile respawns
/// it (its last spawn attempt is long past [`RESPAWN_BACKOFF`]). Returns
/// `(ok, failed)` backend counts.
pub async fn exercise_all(state: &AppState) -> (usize, usize) {
    let users: Vec<Arc<UserBackends>> = state
        .backend_pool
        .users
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect();
    let secs = state.config.limits.backend_list_timeout_secs;
    let (mut ok, mut failed) = (0, 0);
    // Status writes for dropped backends, recorded after `inner` is released
    // so this function only ever holds one lock at a time.
    let mut dropped: Vec<String> = Vec::new();
    for ub in users {
        let backends = ub.inner.lock().unwrap().backends.clone();
        let results = futures::future::join_all(backends.iter().map(|b| async move {
            let fut = b.list_namespaced_tools();
            if secs == 0 {
                fut.await.map(|_| ())
            } else {
                match tokio::time::timeout(Duration::from_secs(secs), fut).await {
                    Ok(r) => r.map(|_| ()),
                    Err(_) => Err(anyhow::anyhow!("heartbeat timed out after {secs}s")),
                }
            }
        }))
        .await;
        let mut inner = ub.inner.lock().unwrap();
        for (b, r) in backends.iter().zip(results) {
            match r {
                Ok(()) => {
                    ok += 1;
                    inner.heartbeat_failures.remove(&b.instance_id);
                }
                Err(e) => {
                    failed += 1;
                    let strikes = inner
                        .heartbeat_failures
                        .entry(b.instance_id.clone())
                        .and_modify(|s| *s += 1)
                        .or_insert(1);
                    let strikes = *strikes;
                    tracing::warn!(
                        namespace = %b.namespace,
                        error = %format!("{e:#}"),
                        strikes,
                        "backend heartbeat failed"
                    );
                    if strikes >= HEARTBEAT_MAX_STRIKES {
                        inner.heartbeat_failures.remove(&b.instance_id);
                        // Drop exactly the Arc we heartbeated — never a fresh
                        // respawn that raced in while we were listing.
                        if let Some(p) = inner.backends.iter().position(|x| Arc::ptr_eq(x, b)) {
                            inner.backends.remove(p);
                            dropped.push(b.instance_id.clone());
                            tracing::info!(
                                namespace = %b.namespace,
                                "dropping wedged backend for respawn"
                            );
                        }
                    }
                }
            }
        }
    }
    for id in dropped {
        state.runtime_status.set(
            &id,
            crate::status::RuntimeState::Error,
            Some("heartbeat failed; dropped for respawn"),
        );
    }
    (ok, failed)
}

/// Record a backend's connection outcome so the UI / hub__ tools can show
/// why it is (not) running. In-memory ([`crate::status::StatusRegistry`]):
/// this fires on every spawn attempt across all backends, and keeping it off
/// the database's write lock is what lets the OAuth path stay uncontended.
fn mark_status(
    state: &AppState,
    inst: &instances::Instance,
    status: crate::status::RuntimeState,
    detail: Option<&str>,
) {
    if status != crate::status::RuntimeState::Ok {
        tracing::warn!(namespace = %inst.namespace, status = status.as_str(), detail, "backend not running");
    }
    state.runtime_status.set(&inst.id, status, detail);
}

/// Mark a run of instances skipped (capacity or sandbox kept them down).
fn mark_skipped(state: &AppState, insts: &[instances::Instance], reason: &str) {
    for inst in insts {
        mark_status(state, inst, crate::status::RuntimeState::Skipped, Some(reason));
    }
}
