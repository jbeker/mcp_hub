//! A minimal stdio MCP server used by the proxy integration tests.
//!
//! Exposes one tool, `echo`, which returns its `msg` argument. It also reads an
//! optional `MOCK_PREFIX` environment variable so tests can verify that the hub
//! injects per-instance configuration/secrets into the spawned process.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    AnnotateAble, CallToolResult, Content, GetPromptRequestParam, GetPromptResult,
    ListPromptsResult, ListResourcesResult, PaginatedRequestParam, Prompt, PromptMessage,
    PromptMessageRole, RawResource, ReadResourceRequestParam, ReadResourceResult, ResourceContents,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
use serde::Deserialize;

const RES_URI: &str = "mock://greeting";

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
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
            ..Default::default()
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![RawResource::new(RES_URI, "greeting").no_annotation()],
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri != RES_URI {
            return Err(McpError::resource_not_found("no such resource", None));
        }
        Ok(ReadResourceResult {
            contents: vec![ResourceContents::text("hello from mock", RES_URI)],
        })
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult {
            prompts: vec![Prompt::new("hello", Some("A greeting prompt"), None)],
            next_cursor: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        if request.name != "hello" {
            return Err(McpError::invalid_params("no such prompt", None));
        }
        Ok(GetPromptResult {
            description: Some("A greeting prompt".into()),
            messages: vec![PromptMessage::new_text(
                PromptMessageRole::User,
                "Say hello to the user.",
            )],
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Mock::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
