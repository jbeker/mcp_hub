//! A minimal stdio MCP server used by the proxy integration tests.
//!
//! Exposes an `echo` tool (returns its `msg` argument), a `sleep` tool (for
//! call-timeout tests), and a `pid` tool (for backend-pooling tests). Reads
//! optional environment variables so tests can shape its behavior:
//! `MOCK_PREFIX` prefixes echo output (verifies per-instance config injection),
//! `MOCK_INIT_DELAY_MS` stalls startup before serving `initialize` (connect
//! timeout / bind budget tests), and `MOCK_LIST_DELAY_MS` stalls `tools/list`
//! (list timeout tests).

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResult, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, Prompt, PromptMessage,
    ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, Role,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
use serde::Deserialize;

const RES_URI: &str = "mock://greeting";

/// Sleep for the number of milliseconds named by `var`, if set and non-zero.
async fn env_delay(var: &str) {
    let ms = std::env::var(var).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

#[derive(Clone)]
struct Mock {
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    msg: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SleepArgs {
    ms: u64,
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
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{prefix}{}",
            args.msg
        ))]))
    }

    #[tool(description = "Sleep for `ms` milliseconds before replying (used to test call timeouts)")]
    async fn sleep(&self, Parameters(args): Parameters<SleepArgs>) -> Result<CallToolResult, McpError> {
        tokio::time::sleep(std::time::Duration::from_millis(args.ms)).await;
        Ok(CallToolResult::success(vec![ContentBlock::text("slept")]))
    }

    #[tool(description = "Report this server process's PID (used to test backend pooling)")]
    async fn pid(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(
            std::process::id().to_string(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for Mock {
    // Defined by hand (the macro skips it) so `MOCK_LIST_DELAY_MS` can stall
    // the reply — exercising the hub's per-backend list timeout.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        env_delay("MOCK_LIST_DELAY_MS").await;
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            next_cursor: None,
            meta: None,
        })
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_prompts()
            .build();
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![Resource::new(RES_URI, "greeting")],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri != RES_URI {
            return Err(McpError::resource_not_found("no such resource", None));
        }
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            "hello from mock",
            RES_URI,
        )]))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult {
            prompts: vec![Prompt::new("hello", Some("A greeting prompt"), None)],
            next_cursor: None,
            meta: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        if request.name != "hello" {
            return Err(McpError::invalid_params("no such prompt", None));
        }
        Ok(
            GetPromptResult::new(vec![PromptMessage::new_text(
                Role::User,
                "Say hello to the user.",
            )])
            .with_description("A greeting prompt"),
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Stall before answering `initialize`, so tests can simulate a backend
    // with a slow (or hung) startup handshake.
    env_delay("MOCK_INIT_DELAY_MS").await;
    let service = Mock::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
