//! A minimal stdio MCP server used by the proxy integration tests.
//!
//! Exposes one tool, `echo`, which returns its `msg` argument. It also reads an
//! optional `MOCK_PREFIX` environment variable so tests can verify that the hub
//! injects per-instance configuration/secrets into the spawned process.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;

#[derive(Clone)]
struct Mock {
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    msg: String,
}

#[tool_router]
impl Mock {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Echo a message back, optionally prefixed by MOCK_PREFIX")]
    async fn echo(&self, Parameters(args): Parameters<EchoArgs>) -> Result<CallToolResult, McpError> {
        let prefix = std::env::var("MOCK_PREFIX").unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "{prefix}{}",
            args.msg
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for Mock {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Mock::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
