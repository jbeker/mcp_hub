//! End-to-end proxy tests: a real MCP client connects to the hub over Streamable
//! HTTP with an OAuth bearer token. Covers backend aggregation and the built-in
//! `hub__` management interface.

use mcp_hub::catalog::ServerDef;
use mcp_hub::config::{Config, Limits};
use mcp_hub::{build_router, db, instances, users, AppState};
use rmcp::model::CallToolRequestParam;
use rmcp::service::{serve_client, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::RoleClient;

fn mock_server_path() -> String {
    format!(
        "{}/target/debug/examples/mock_mcp_server",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Bind an ephemeral port, build + serve a hub, and return its base URL + state.
async fn spawn_hub() -> (String, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // `localhost` resolves to 127.0.0.1; WebAuthn rejects bare IPs as RP ids.
    let base = format!("http://localhost:{}", addr.port());

    let path = std::env::temp_dir().join(format!("mcp_hub_e2e_{}.db", uuid::Uuid::new_v4()));
    let pool = db::connect(path.to_str().unwrap()).await.unwrap();
    let config = Config {
        base_url: base.clone(),
        rp_id: "localhost".into(),
        listen: addr,
        db_path: String::new(),
        env_dir: std::env::temp_dir().join(format!("mcp_hub_envs_{}", uuid::Uuid::new_v4())).to_string_lossy().into_owned(),
        master_key: [1u8; 32],
        bootstrap_admin: None,
        allow_open_registration: false,
        limits: Limits::default(),
    };
    let state = AppState::new(config, pool).await.unwrap();

    let app = build_router(state.clone(), "static");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, state)
}

/// Connect an MCP client to the hub's `/mcp` endpoint with a bearer token.
async fn connect(base: &str, token: String) -> RunningService<RoleClient, ()> {
    let config =
        StreamableHttpClientTransportConfig::with_uri(format!("{base}/mcp")).auth_header(token);
    serve_client((), StreamableHttpClientTransport::from_config(config))
        .await
        .expect("MCP client should initialize through the proxy")
}

fn args(v: serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
    Some(v.as_object().unwrap().clone())
}

#[tokio::test]
async fn unbuilt_git_backend_is_skipped() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    // A git-sourced instance that has never been built.
    let def = ServerDef {
        name: "Git Server".into(),
        description: String::new(),
        transport: "git".into(),
        command: None,
        args: vec![],
        url: None,
        runtime: "python".into(),
        secret_schema: vec![],
        repo: Some("https://github.com/example/mcp".into()),
        git_ref: Some("main".into()),
        entry: Some("example-mcp".into()),
        module: None,
    };
    instances::create(&state.db, &user.id, None, Some(&def), "git", "Git Server")
        .await
        .unwrap();

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // The unbuilt backend contributes no tools (it is skipped, not fatal).
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("git__")), "got {names:?}");
    assert!(names.contains(&"hub__whoami".to_string()));

    // ...and it is reported as unbuilt so the user knows to run hub__update_server.
    let listed = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_my_servers".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"build_status\":\"unbuilt\""), "got {json}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn proxy_aggregates_a_stdio_backend() {
    let exe = mock_server_path();
    assert!(
        std::path::Path::new(&exe).exists(),
        "build the example first: cargo build --example mock_mcp_server"
    );

    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let def = ServerDef {
        name: "Mock".into(),
        description: String::new(),
        transport: "stdio".into(),
        command: Some(exe),
        args: vec![],
        url: None,
        runtime: "binary".into(),
        secret_schema: vec![],
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "mock", "Mock")
        .await
        .unwrap();
    instances::set_config_value(&state.db, &inst.id, "MOCK_PREFIX", "PFX:")
        .await
        .unwrap();

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");
    // Management tools are always present.
    assert!(names.contains(&"hub__whoami".to_string()));

    let result = client
        .call_tool(CallToolRequestParam {
            name: "mock__echo".into(),
            arguments: args(serde_json::json!({ "msg": "hello" })),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&result.content).unwrap();
    assert!(rendered.contains("PFX:hello"), "got {rendered}");

    let bad = client
        .call_tool(CallToolRequestParam {
            name: "nope__tool".into(),
            arguments: None,
        })
        .await;
    assert!(bad.is_err());

    let _ = client.cancel().await;
}

#[tokio::test]
async fn management_tools_over_mcp() {
    let (base, state) = spawn_hub().await;
    // Admin user so admin-only tools are exposed.
    let user = users::create(&state.db, "admin1", "alice", "Alice", true)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "client", &format!("{base}/mcp"), "mcp", true, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // Admin sees admin-only tools.
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"hub__whoami".to_string()));
    assert!(names.contains(&"hub__list_users".to_string()));

    // whoami returns the structured identity.
    let who = client
        .call_tool(CallToolRequestParam {
            name: "hub__whoami".into(),
            arguments: None,
        })
        .await
        .unwrap();
    assert_eq!(who.structured_content.unwrap()["handle"], "alice");

    // The catalog is reachable over MCP.
    let cat = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_catalog".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let cat_json = serde_json::to_string(&cat.structured_content).unwrap();
    assert!(cat_json.contains("zabbix"), "catalog: {cat_json}");

    // Add a server, configure a secret, then list it back.
    let added = client
        .call_tool(CallToolRequestParam {
            name: "hub__add_server".into(),
            arguments: args(serde_json::json!({"catalog_slug": "zabbix", "namespace": "zbx", "display_name": "My Zabbix"})),
        })
        .await
        .unwrap();
    assert_eq!(added.structured_content.unwrap()["added"], true);

    client
        .call_tool(CallToolRequestParam {
            name: "hub__set_secret".into(),
            arguments: args(serde_json::json!({"namespace": "zbx", "key": "ZABBIX_TOKEN", "value": "s3cr3t"})),
        })
        .await
        .unwrap();

    let listed = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_my_servers".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let listed_json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(listed_json.contains("zbx"));
    assert!(listed_json.contains("ZABBIX_TOKEN")); // secret name listed, value not
    assert!(!listed_json.contains("s3cr3t")); // value never returned

    // An env key outside the server's schema is refused (no PYTHONSTARTUP etc.).
    let injected = client
        .call_tool(CallToolRequestParam {
            name: "hub__set_secret".into(),
            arguments: args(serde_json::json!({"namespace": "zbx", "key": "LD_PRELOAD", "value": "/tmp/x.so"})),
        })
        .await;
    let blocked = match injected {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(blocked, "undeclared env key must be rejected");

    // Reserved namespace cannot be claimed via the management interface.
    let reserved = client
        .call_tool(CallToolRequestParam {
            name: "hub__add_server".into(),
            arguments: args(serde_json::json!({"catalog_slug": "zabbix", "namespace": "hub"})),
        })
        .await;
    let rejected = match reserved {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(rejected, "reserved namespace must be rejected");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn non_admin_cannot_use_admin_tools() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u2", "bob", "Bob", false)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // Admin tools are not even listed for a non-admin.
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.contains(&"hub__list_users".to_string()));

    // And invoking one directly is refused.
    let res = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_users".into(),
            arguments: None,
        })
        .await;
    let refused = match res {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(refused, "non-admin must be refused hub__list_users");

    let _ = client.cancel().await;
}
