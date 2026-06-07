//! A single upstream backend connection (stdio subprocess or remote HTTP),
//! wrapped as an MCP client whose tools the hub re-exports under a namespace.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use rmcp::model::{CallToolRequestParam, CallToolResult, Tool};
use rmcp::service::{serve_client, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{ConfigureCommandExt, StreamableHttpClientTransport, TokioChildProcess};
use rmcp::RoleClient;
use tokio::sync::OwnedSemaphorePermit;

use crate::catalog::ServerDef;

/// A live connection to one backend MCP server.
pub struct Backend {
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
        namespace: String,
        display_name: String,
        permit: OwnedSemaphorePermit,
    ) -> Result<Backend> {
        let peer = match def.transport.as_str() {
            "stdio" => {
                let program = def
                    .command
                    .clone()
                    .ok_or_else(|| anyhow!("stdio backend '{namespace}' has no command"))?;
                let args = def.args.clone();
                let env = env.clone();
                let cmd = tokio::process::Command::new(&program).configure(|c| {
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
                });
                let transport = TokioChildProcess::new(cmd)
                    .with_context(|| format!("spawning backend '{namespace}'"))?;
                serve_client((), transport)
                    .await
                    .with_context(|| format!("initializing stdio backend '{namespace}'"))?
            }
            "http" => {
                let url = def
                    .url
                    .clone()
                    .ok_or_else(|| anyhow!("http backend '{namespace}' has no url"))?;
                let mut config = StreamableHttpClientTransportConfig::with_uri(url);
                if let Some(auth) = env.get("AUTHORIZATION").filter(|v| !v.is_empty()) {
                    config = config.auth_header(strip_bearer(auth));
                }
                let transport = StreamableHttpClientTransport::from_config(config);
                serve_client((), transport)
                    .await
                    .with_context(|| format!("connecting http backend '{namespace}'"))?
            }
            other => bail!("unsupported transport '{other}' for backend '{namespace}'"),
        };
        Ok(Backend {
            namespace,
            display_name,
            peer,
            _permit: permit,
        })
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

/// Strip a leading `Bearer ` (case-insensitive) since reqwest re-adds it.
fn strip_bearer(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        trimmed[7..].trim().to_string()
    } else {
        trimmed.to_string()
    }
}
