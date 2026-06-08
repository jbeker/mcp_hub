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
    pub async fn spawn(
        def: &ServerDef,
        env: &BTreeMap<String, String>,
        instance_id: String,
        namespace: String,
        display_name: String,
        permit: OwnedSemaphorePermit,
        sandbox: Option<&crate::sandbox::Sandbox>,
    ) -> Result<Backend> {
        let peer = match def.transport.as_str() {
            "stdio" => {
                let cmd = stdio_command(def, env, sandbox)
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
    /// then shut it straight back down — reporting why it failed. Unlike
    /// [`spawn`](Self::spawn), a failing stdio child's **stderr is captured** and
    /// folded into the error, so the caller sees the subprocess's own crash
    /// output (e.g. a Python traceback) rather than just "connection closed".
    /// Used by the "Test connection" button so a user can verify a server starts
    /// without opening a fresh MCP client connection.
    pub async fn probe(
        def: &ServerDef,
        env: &BTreeMap<String, String>,
        sandbox: Option<&crate::sandbox::Sandbox>,
    ) -> Result<()> {
        match def.transport.as_str() {
            "stdio" => {
                let cmd = stdio_command(def, env, sandbox)?;
                // Pipe stderr so we can surface the child's own error output if
                // it dies before answering `initialize`.
                let (transport, stderr) = TokioChildProcess::builder(cmd)
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .context("spawning backend")?;
                match serve_client((), transport).await {
                    Ok(peer) => {
                        let _ = peer.cancel().await;
                        Ok(())
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
                let _ = peer.cancel().await;
                Ok(())
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

/// Build the `Command` for an stdio backend: the configured command + args, a
/// cleared environment with only the injected vars (+ `PATH`), and — when a
/// sandbox is active — a drop to the per-user UID with caches/HOME pointed at a
/// writable per-UID directory.
fn stdio_command(
    def: &ServerDef,
    env: &BTreeMap<String, String>,
    sandbox: Option<&crate::sandbox::Sandbox>,
) -> Result<tokio::process::Command> {
    let program = def
        .command
        .clone()
        .ok_or_else(|| anyhow!("stdio backend has no command"))?;
    // Substitute `${VAR}` references in the command line against the configured
    // env (secrets + non-secret config) so a user can write e.g.
    // `${TOOL_HOME}/bin/server` or `--token=${API_TOKEN}`. Unknown references
    // are left literal (see `expand_vars`).
    let program = crate::util::expand_vars(&program, env);
    let args: Vec<String> = def
        .args
        .iter()
        .map(|a| crate::util::expand_vars(a, env))
        .collect();
    let env = env.clone();
    let sandbox = sandbox.cloned();
    Ok(tokio::process::Command::new(&program).configure(|c| {
        c.args(&args);
        // Don't leak the hub's own environment into the child.
        c.env_clear();
        for (k, v) in &env {
            c.env(k, v);
        }
        // Preserve PATH so `uvx`/`npx` can find interpreters.
        if let Ok(path) = std::env::var("PATH") {
            c.env("PATH", path);
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
        let err = Backend::probe(&def, &BTreeMap::new(), None)
            .await
            .expect_err("a backend that exits should fail to probe");
        let msg = format!("{err:#}");
        assert!(msg.contains("BOOM_MARKER"), "stderr not captured: {msg}");
    }

    #[test]
    fn strip_bearer_is_case_insensitive() {
        assert_eq!(strip_bearer("Bearer abc"), "abc");
        assert_eq!(strip_bearer("bearer  abc "), "abc");
        assert_eq!(strip_bearer("abc"), "abc");
    }
}
