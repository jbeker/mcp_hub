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
