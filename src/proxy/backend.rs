//! A single upstream backend connection (stdio subprocess or remote HTTP),
//! wrapped as an MCP client whose tools the hub re-exports under a namespace.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use rmcp::model::{
    CallToolRequestParam, CallToolResult, GetPromptRequestParam, GetPromptResult, Prompt,
    ReadResourceRequestParam, ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
    Tool,
};
use rmcp::service::{serve_client, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{ConfigureCommandExt, StreamableHttpClientTransport, TokioChildProcess};
use rmcp::RoleClient;
use tokio::sync::OwnedSemaphorePermit;

use crate::instances::ServerDef;

/// A live connection to one backend MCP server.
pub struct Backend {
    /// The owning instance's stable id (for per-credential access control).
    pub instance_id: String,
    pub namespace: String,
    pub display_name: String,
    peer: RunningService<RoleClient, ()>,
    /// Released when the backend shuts down, freeing a global slot.
    _permit: OwnedSemaphorePermit,
}

impl Backend {
    /// Establish a connection for `def`, injecting `env` (decrypted secrets +
    /// non-secret config). The `permit` (a global backend slot) is held for the
    /// life of the connection. The backend is initialized and ready on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        def: &ServerDef,
        env: &BTreeMap<String, String>,
        instance_id: String,
        namespace: String,
        display_name: String,
        permit: OwnedSemaphorePermit,
        sandbox: Option<&crate::sandbox::Sandbox>,
        env_dir: &str,
        config_file: Option<&str>,
        child_limits: crate::config::ChildLimits,
    ) -> Result<Backend> {
        let peer = match def.transport.as_str() {
            "stdio" => {
                let cmd = stdio_command(
                    def,
                    env,
                    sandbox,
                    env_dir,
                    &instance_id,
                    config_file,
                    child_limits,
                )
                .with_context(|| format!("backend '{namespace}'"))?;
                let transport = TokioChildProcess::new(cmd)
                    .with_context(|| format!("spawning backend '{namespace}'"))?;
                serve_client((), transport)
                    .await
                    .with_context(|| format!("initializing stdio backend '{namespace}'"))?
            }
            "http" => {
                let config =
                    http_config(def, env).with_context(|| format!("backend '{namespace}'"))?;
                let transport = StreamableHttpClientTransport::from_config(config);
                serve_client((), transport)
                    .await
                    .with_context(|| format!("connecting http backend '{namespace}'"))?
            }
            other => bail!("unsupported transport '{other}' for backend '{namespace}'"),
        };
        Ok(Backend {
            instance_id,
            namespace,
            display_name,
            peer,
            _permit: permit,
        })
    }

    /// Try to start the backend once, complete the MCP `initialize` handshake,
    /// capture what the server advertises (a [`CapabilitiesSnapshot`]), then
    /// shut it straight back down — reporting why it failed. Unlike
    /// [`spawn`](Self::spawn), a failing stdio child's **stderr is captured** and
    /// folded into the error, so the caller sees the subprocess's own crash
    /// output (e.g. a Python traceback) rather than just "connection closed".
    /// Used by the "Test connection" and "Refresh capabilities" buttons so a
    /// user can verify a server starts without opening a fresh MCP client
    /// connection.
    ///
    /// [`CapabilitiesSnapshot`]: crate::instances::CapabilitiesSnapshot
    pub async fn probe(
        def: &ServerDef,
        env: &BTreeMap<String, String>,
        sandbox: Option<&crate::sandbox::Sandbox>,
        env_dir: &str,
        instance_id: &str,
        config_file: Option<&str>,
        child_limits: crate::config::ChildLimits,
    ) -> Result<crate::instances::CapabilitiesSnapshot> {
        match def.transport.as_str() {
            "stdio" => {
                let cmd =
                    stdio_command(def, env, sandbox, env_dir, instance_id, config_file, child_limits)?;
                // Pipe stderr so we can surface the child's own error output if
                // it dies before answering `initialize`.
                let (transport, stderr) = TokioChildProcess::builder(cmd)
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .context("spawning backend")?;
                match serve_client((), transport).await {
                    Ok(peer) => {
                        let snap = capture_snapshot(&peer).await;
                        let _ = peer.cancel().await;
                        Ok(snap)
                    }
                    Err(e) => {
                        let tail = match stderr {
                            Some(s) => read_stderr_tail(s).await,
                            None => String::new(),
                        };
                        if tail.is_empty() {
                            Err(anyhow::Error::new(e).context("initializing backend"))
                        } else {
                            Err(anyhow!("{e}\n--- server stderr ---\n{tail}"))
                        }
                    }
                }
            }
            "http" => {
                let transport = StreamableHttpClientTransport::from_config(http_config(def, env)?);
                let peer = serve_client((), transport)
                    .await
                    .context("connecting http backend")?;
                let snap = capture_snapshot(&peer).await;
                let _ = peer.cancel().await;
                Ok(snap)
            }
            other => bail!("unsupported transport '{other}'"),
        }
    }

    /// List this backend's tools, renamed into the hub namespace
    /// (`<namespace>__<tool>`).
    pub async fn list_namespaced_tools(&self) -> Result<Vec<Tool>> {
        let tools = self
            .peer
            .list_all_tools()
            .await
            .with_context(|| format!("listing tools for '{}'", self.namespace))?;
        Ok(tools
            .into_iter()
            .map(|mut t| {
                t.name = format!("{}__{}", self.namespace, t.name).into();
                t
            })
            .collect())
    }

    /// List this backend's resources, with each URI wrapped so it routes back
    /// here (`hub://<namespace>/<original-uri>`). A backend that exposes no
    /// resources (capability absent) contributes none rather than erroring.
    pub async fn list_namespaced_resources(&self) -> Result<Vec<Resource>> {
        let resources = self.peer.list_all_resources().await?;
        Ok(resources
            .into_iter()
            .map(|mut r| {
                r.uri = wrap_uri(&self.namespace, &r.uri);
                r
            })
            .collect())
    }

    /// List this backend's resource templates, with the URI template wrapped so
    /// that a filled-in URI still routes back here.
    pub async fn list_namespaced_resource_templates(&self) -> Result<Vec<ResourceTemplate>> {
        let templates = self.peer.list_all_resource_templates().await?;
        Ok(templates
            .into_iter()
            .map(|mut t| {
                t.uri_template = wrap_uri(&self.namespace, &t.uri_template);
                t
            })
            .collect())
    }

    /// Read a resource by its *original* (un-wrapped) URI. The URIs in the
    /// returned contents are re-wrapped so the client sees consistent identifiers.
    pub async fn read_resource(&self, original_uri: String) -> Result<ReadResourceResult> {
        let mut result = self
            .peer
            .read_resource(ReadResourceRequestParam { uri: original_uri })
            .await
            .with_context(|| format!("reading resource on '{}'", self.namespace))?;
        for c in &mut result.contents {
            match c {
                ResourceContents::TextResourceContents { uri, .. }
                | ResourceContents::BlobResourceContents { uri, .. } => {
                    let wrapped = wrap_uri(&self.namespace, uri);
                    *uri = wrapped;
                }
            }
        }
        Ok(result)
    }

    /// List this backend's prompts, renamed into the hub namespace.
    pub async fn list_namespaced_prompts(&self) -> Result<Vec<Prompt>> {
        let prompts = self.peer.list_all_prompts().await?;
        Ok(prompts
            .into_iter()
            .map(|mut p| {
                p.name = format!("{}__{}", self.namespace, p.name);
                p
            })
            .collect())
    }

    /// Get a prompt by its *original* (un-namespaced) name.
    pub async fn get_prompt(
        &self,
        original_name: String,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<GetPromptResult> {
        self.peer
            .get_prompt(GetPromptRequestParam {
                name: original_name,
                arguments,
            })
            .await
            .with_context(|| format!("getting prompt on '{}'", self.namespace))
    }

    /// Call a tool on this backend by its *original* (un-namespaced) name.
    pub async fn call_tool(
        &self,
        original_name: String,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult> {
        self.peer
            .call_tool(CallToolRequestParam {
                name: original_name.into(),
                arguments,
            })
            .await
            .with_context(|| format!("calling tool on '{}'", self.namespace))
    }

    /// Cleanly shut down the backend connection.
    pub async fn shutdown(self) {
        let _ = self.peer.cancel().await;
    }
}

/// Read everything the just-initialized backend advertises. Each list call is
/// gated on the advertised capability *and* error-tolerant: a server that
/// doesn't support prompts/resources (or errors mid-list) contributes empty
/// lists rather than failing the probe — the probe's job is still "did it
/// start"; the snapshot is best-effort extra.
async fn capture_snapshot(
    peer: &RunningService<RoleClient, ()>,
) -> crate::instances::CapabilitiesSnapshot {
    let server = peer.peer_info().cloned().unwrap_or_default();
    let caps = server.capabilities.clone();
    let tools = if caps.tools.is_some() {
        peer.list_all_tools().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "listing tools for snapshot");
            Vec::new()
        })
    } else {
        Vec::new()
    };
    let prompts = if caps.prompts.is_some() {
        peer.list_all_prompts().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "listing prompts for snapshot");
            Vec::new()
        })
    } else {
        Vec::new()
    };
    let (resources, resource_templates) = if caps.resources.is_some() {
        (
            peer.list_all_resources().await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "listing resources for snapshot");
                Vec::new()
            }),
            peer.list_all_resource_templates().await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "listing resource templates for snapshot");
                Vec::new()
            }),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    crate::instances::CapabilitiesSnapshot {
        fetched_at: crate::util::now_unix(),
        server,
        tools,
        prompts,
        resources,
        resource_templates,
    }
}

/// Build the `Command` for an stdio backend: the configured command + args, a
/// cleared environment with only the injected vars (+ `PATH`), and — when a
/// sandbox is active — a drop to the per-user UID with caches/HOME pointed at a
/// writable per-UID directory.
///
/// When `config_file` is set, its contents are written into a fresh per-instance
/// working directory (which becomes the child's `cwd`), and its absolute path is
/// injected as `MCP_CONFIG_FILE` — available both for `${MCP_CONFIG_FILE}`
/// expansion in the command line and to the child's environment.
fn stdio_command(
    def: &ServerDef,
    env: &BTreeMap<String, String>,
    sandbox: Option<&crate::sandbox::Sandbox>,
    env_dir: &str,
    instance_id: &str,
    config_file: Option<&str>,
    child_limits: crate::config::ChildLimits,
) -> Result<tokio::process::Command> {
    let program = def
        .command
        .clone()
        .ok_or_else(|| anyhow!("stdio backend has no command"))?;

    let mut env = env.clone();

    // If a config file is attached, write it into a fresh working directory and
    // expose its path before expanding `${MCP_CONFIG_FILE}` in the command line.
    let workdir = match config_file {
        Some(content) => {
            let path = write_config_file(env_dir, instance_id, content, sandbox)
                .context("writing config file")?;
            env.insert(
                crate::instances::CONFIG_FILE_ENV.to_string(),
                path.0.to_string_lossy().into_owned(),
            );
            Some(path.1)
        }
        None => None,
    };

    // Substitute `${VAR}` references in the command line and in env-var *values*
    // against the configured env (secrets + non-secret config + MCP_CONFIG_FILE),
    // so a user can write e.g. `${TOOL_HOME}/bin/server` as the command or
    // `GOOGLE_APPLICATION_CREDENTIALS=${MCP_CONFIG_FILE}` as an env var. Each
    // value expands against the whole map in a single pass; unknown references
    // are left literal (see `expand_vars`).
    let program = crate::util::expand_vars(&program, &env);
    let args: Vec<String> = def
        .args
        .iter()
        .map(|a| crate::util::expand_vars(a, &env))
        .collect();
    let sandbox = sandbox.cloned();
    Ok(tokio::process::Command::new(&program).configure(|c| {
        c.args(&args);
        // Don't leak the hub's own environment into the child.
        c.env_clear();
        for (k, v) in &env {
            c.env(k, crate::util::expand_vars(v, &env));
        }
        // Preserve PATH so `uvx`/`npx` can find interpreters.
        if let Ok(path) = std::env::var("PATH") {
            c.env("PATH", path);
        }
        // Run from the per-instance working directory so a config file written
        // there is discoverable by tools that look in their cwd.
        if let Some(dir) = &workdir {
            c.current_dir(dir);
        }
        // Apply per-child resource caps in the forked child, before the uid
        // drop below (std runs user `pre_exec` hooks before its own uid/gid
        // change). Setting limits while still privileged is what lets them
        // hold against the unprivileged sandbox UID. No-op when nothing is set.
        if child_limits.any() {
            // SAFETY: the closure only calls `setrlimit`, which is a single
            // async-signal-safe syscall — valid in the post-fork/pre-exec child.
            unsafe {
                c.pre_exec(move || apply_child_limits(child_limits));
            }
        }
        // Drop the child to its per-user sandbox UID and point its caches/HOME
        // at a writable per-UID directory.
        if let Some(sb) = &sandbox {
            c.uid(sb.uid);
            c.gid(sb.gid);
            c.env("HOME", &sb.cache_dir);
            c.env("USER", "mcp-sandbox");
            c.env("XDG_CACHE_HOME", &sb.cache_dir);
            c.env("UV_CACHE_DIR", format!("{}/uv", sb.cache_dir));
            c.env("npm_config_cache", format!("{}/npm", sb.cache_dir));
        }
    }))
}

/// Apply the configured `setrlimit` caps. Runs in the forked child between
/// `fork` and `exec`, so it must stay async-signal-safe: it does nothing but
/// issue `setrlimit` syscalls. A failure aborts the spawn (the child reports
/// the errno back through the standard `pre_exec` channel).
#[cfg(unix)]
fn apply_child_limits(limits: crate::config::ChildLimits) -> std::io::Result<()> {
    // The resource-id type differs across platforms (glibc `__rlimit_resource_t`
    // vs `c_int`); leave it for the closure to infer from the `RLIMIT_*`
    // constants so this compiles on the dev host and the Linux target alike.
    let set = |resource, value: u64| -> std::io::Result<()> {
        let rl = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: `rl` is a valid, fully-initialized rlimit for the duration
        // of the call.
        if unsafe { libc::setrlimit(resource, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    if let Some(n) = limits.max_procs {
        set(libc::RLIMIT_NPROC, n)?;
    }
    if let Some(mb) = limits.max_mem_mb {
        set(libc::RLIMIT_DATA, mb.saturating_mul(1024 * 1024))?;
    }
    if let Some(s) = limits.max_cpu_secs {
        set(libc::RLIMIT_CPU, s)?;
    }
    if let Some(mb) = limits.max_file_mb {
        set(libc::RLIMIT_FSIZE, mb.saturating_mul(1024 * 1024))?;
    }
    Ok(())
}

/// The per-instance working directory used to host a config file.
fn workdir_path(env_dir: &str, instance_id: &str) -> std::path::PathBuf {
    std::path::Path::new(env_dir).join("workdir").join(instance_id)
}

/// (Re)create the instance's working directory and write `content` into it under
/// the fixed config-file name. Returns `(file_path, workdir)`. The directory is
/// recreated from scratch on every spawn so a stale file is never left behind.
/// When a sandbox is active the directory and file are chowned to the sandbox
/// UID and the directory locked to `0700`, so only that UID can read it.
fn write_config_file(
    env_dir: &str,
    instance_id: &str,
    content: &str,
    sandbox: Option<&crate::sandbox::Sandbox>,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let workdir = workdir_path(env_dir, instance_id);
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir)?;
    let file = workdir.join(crate::instances::CONFIG_FILE_NAME);
    std::fs::write(&file, content)?;
    if let Some(sb) = sandbox {
        crate::sandbox::chown(&workdir, sb.uid, sb.gid)?;
        crate::sandbox::chown(&file, sb.uid, sb.gid)?;
        crate::sandbox::set_private(&workdir)?;
    }
    Ok((file, workdir))
}

/// Best-effort removal of an instance's working directory (e.g. on delete), so a
/// decrypted config file does not linger on disk after the instance is gone.
pub fn remove_workdir(env_dir: &str, instance_id: &str) {
    let _ = std::fs::remove_dir_all(workdir_path(env_dir, instance_id));
}

/// Build the Streamable-HTTP transport config for an http backend, applying the
/// `AUTHORIZATION` env var as the bearer credential if present. (Returns the
/// config rather than the transport so the concrete reqwest-backed type need not
/// be named at the call sites.)
fn http_config(
    def: &ServerDef,
    env: &BTreeMap<String, String>,
) -> Result<StreamableHttpClientTransportConfig> {
    let url = def
        .url
        .clone()
        .ok_or_else(|| anyhow!("http backend has no url"))?;
    let mut config = StreamableHttpClientTransportConfig::with_uri(url);
    if let Some(auth) = env.get("AUTHORIZATION").filter(|v| !v.is_empty()) {
        config = config.auth_header(strip_bearer(auth));
    }
    Ok(config)
}

/// Drain a failed child's stderr (bounded in time and size) and return the tail
/// — the end of a traceback is the useful part. Char-safe truncation.
async fn read_stderr_tail(mut stderr: tokio::process::ChildStderr) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stderr.read_to_end(&mut buf),
    )
    .await;
    let text = String::from_utf8_lossy(&buf);
    // Keep the last ~3000 characters without splitting a UTF-8 boundary.
    let kept: Vec<char> = text.trim().chars().rev().take(3000).collect();
    kept.into_iter().rev().collect()
}

/// Wrap a backend resource URI so it routes back to its namespace.
///
/// Resources are identified by opaque URI (unlike tools/prompts, which have
/// names), so to fan `read_resource` back to the right backend we prefix the
/// URI with `hub://<namespace>/`. The client round-trips the wrapped string
/// verbatim — including after filling in a URI template — so [`unwrap_uri`]
/// always recovers the namespace and the original URI.
pub(crate) fn wrap_uri(namespace: &str, original: &str) -> String {
    format!("hub://{namespace}/{original}")
}

/// Recover `(namespace, original_uri)` from a wrapped URI. Returns `None` if the
/// URI was not produced by [`wrap_uri`]. Namespaces never contain `/`, so the
/// first segment is unambiguous.
pub(crate) fn unwrap_uri(wrapped: &str) -> Option<(&str, &str)> {
    wrapped.strip_prefix("hub://")?.split_once('/')
}

/// Strip a leading `Bearer ` (case-insensitive) since reqwest re-adds it.
fn strip_bearer(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        trimmed[7..].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdio_def(command: &str, args: &[&str]) -> ServerDef {
        ServerDef {
            name: "t".into(),
            description: String::new(),
            transport: "stdio".into(),
            command: Some(command.into()),
            args: args.iter().map(|s| s.to_string()).collect(),
            url: None,
            runtime: "test".into(),
            repo: None,
            git_ref: None,
            entry: None,
            module: None,
        }
    }

    /// A stdio backend that dies before answering `initialize` surfaces its own
    /// stderr in the probe error — this is what the Test-connection button shows.
    #[tokio::test]
    async fn probe_captures_stderr_from_a_crashing_backend() {
        let def = stdio_def("sh", &["-c", "echo BOOM_MARKER >&2; exit 1"]);
        let err = Backend::probe(
            &def,
            &BTreeMap::new(),
            None,
            "/tmp",
            "probe-test",
            None,
            Default::default(),
        )
        .await
        .expect_err("a backend that exits should fail to probe");
        let msg = format!("{err:#}");
        assert!(msg.contains("BOOM_MARKER"), "stderr not captured: {msg}");
    }

    /// A config file is written into the child's working directory and its path
    /// exposed as `$MCP_CONFIG_FILE`. The probe command reads the file via that
    /// var and, on a match, echoes a marker to stderr — which the probe captures.
    #[tokio::test]
    async fn config_file_is_written_and_exposed_via_env() {
        let env_dir = std::env::temp_dir().join(format!("mcphub-cfgtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&env_dir);
        std::fs::create_dir_all(&env_dir).unwrap();

        let def = stdio_def(
            "sh",
            &[
                "-c",
                // Reads the file via $MCP_CONFIG_FILE and via the cwd-relative name.
                "if [ \"$(cat \"$MCP_CONFIG_FILE\")\" = \"FILECONTENT\" ] && \
                  [ \"$(cat config)\" = \"FILECONTENT\" ]; then echo CONFIG_OK >&2; fi; exit 1",
            ],
        );
        let err = Backend::probe(
            &def,
            &BTreeMap::new(),
            None,
            env_dir.to_str().unwrap(),
            "cfg-inst",
            Some("FILECONTENT"),
            Default::default(),
        )
        .await
        .expect_err("the probe command always exits 1");
        let msg = format!("{err:#}");
        assert!(msg.contains("CONFIG_OK"), "config file/env not wired: {msg}");

        // The file landed in the per-instance working directory.
        let file = env_dir.join("workdir").join("cfg-inst").join("config");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "FILECONTENT");
        std::fs::remove_dir_all(&env_dir).ok();
    }

    /// `${VAR}` references in env-var *values* are expanded against the launch
    /// env, including `${MCP_CONFIG_FILE}` — so a tool that reads its config path
    /// from an env var (Google ADC's GOOGLE_APPLICATION_CREDENTIALS) works
    /// without a shell wrapper. The probe command confirms the expanded value
    /// equals the real config path and that a plain cross-reference resolves.
    #[tokio::test]
    async fn env_values_expand_vars_including_config_file_path() {
        let env_dir = std::env::temp_dir().join(format!("mcphub-envexp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&env_dir);
        std::fs::create_dir_all(&env_dir).unwrap();

        let mut env = BTreeMap::new();
        // References the injected config-file path...
        env.insert("GAC".to_string(), "${MCP_CONFIG_FILE}".to_string());
        // ...and a plain cross-reference between two configured vars.
        env.insert("BASE".to_string(), "hello".to_string());
        env.insert("DERIVED".to_string(), "${BASE}-world".to_string());

        let def = stdio_def(
            "sh",
            &[
                "-c",
                "[ \"$GAC\" = \"$MCP_CONFIG_FILE\" ] && [ \"$DERIVED\" = \"hello-world\" ] \
                  && echo ENVEXPAND_OK >&2; exit 1",
            ],
        );
        let err = Backend::probe(
            &def,
            &env,
            None,
            env_dir.to_str().unwrap(),
            "envexp-inst",
            Some("CREDS"),
            Default::default(),
        )
        .await
        .expect_err("the probe command always exits 1");
        let msg = format!("{err:#}");
        assert!(msg.contains("ENVEXPAND_OK"), "env values not expanded: {msg}");
        std::fs::remove_dir_all(&env_dir).ok();
    }

    /// The `pre_exec` `setrlimit` hook actually reaches the subprocess: a child
    /// asked to report its own `RLIMIT_FSIZE` sees the configured cap rather
    /// than "unlimited". Reporting the observed limit is more robust than
    /// relying on SIGXFSZ timing through a shell. Linux-only — the limits are a
    /// no-op on the dev host's non-Linux targets.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn child_resource_limit_reaches_the_subprocess() {
        // `ulimit -f` prints the file-size limit (in blocks) the child runs
        // under; with no cap it would print "unlimited".
        let def = stdio_def(
            "sh",
            &["-c", "printf 'RLIMIT_F=%s\\n' \"$(ulimit -f)\" >&2; exit 1"],
        );
        let limits = crate::config::ChildLimits {
            max_file_mb: Some(1),
            ..Default::default()
        };
        let err = Backend::probe(
            &def,
            &BTreeMap::new(),
            None,
            "/tmp",
            "rlimit-inst",
            None,
            limits,
        )
        .await
        .expect_err("the probe command always exits 1");
        let msg = format!("{err:#}");
        assert!(msg.contains("RLIMIT_F="), "child did not report its limit: {msg}");
        assert!(
            !msg.contains("RLIMIT_F=unlimited"),
            "file-size limit was not applied: {msg}"
        );
    }

    #[test]
    fn strip_bearer_is_case_insensitive() {
        assert_eq!(strip_bearer("Bearer abc"), "abc");
        assert_eq!(strip_bearer("bearer  abc "), "abc");
        assert_eq!(strip_bearer("abc"), "abc");
    }
}
