//! End-to-end proxy tests: a real MCP client connects to the hub over Streamable
//! HTTP with an OAuth bearer token. Covers backend aggregation and the built-in
//! `hub__` management interface.

use mcp_hub::catalog::ServerDef;
use mcp_hub::config::{Config, Limits};
use mcp_hub::{build_router, db, instances, users, AppState};
use rmcp::model::{CallToolRequestParam, GetPromptRequestParam, ReadResourceRequestParam};
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

/// Try to connect an MCP client; returns the error instead of panicking so
/// tests can assert that authentication is rejected.
async fn try_connect(
    base: &str,
    token: String,
) -> Result<RunningService<RoleClient, ()>, Box<dyn std::error::Error>> {
    let config =
        StreamableHttpClientTransportConfig::with_uri(format!("{base}/mcp")).auth_header(token);
    Ok(serve_client((), StreamableHttpClientTransport::from_config(config)).await?)
}

/// Connect an MCP client to the hub's `/mcp` endpoint with a bearer token.
async fn connect(base: &str, token: String) -> RunningService<RoleClient, ()> {
    try_connect(base, token)
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
async fn failed_backend_reports_error_status() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    // An enabled stdio backend whose command does not exist: it must fail to
    // start, be skipped from the aggregate, and report an error status.
    let def = ServerDef {
        name: "Broken".into(),
        description: String::new(),
        transport: "stdio".into(),
        command: Some("/nonexistent/mcp-binary-xyz".into()),
        args: vec![],
        url: None,
        runtime: "binary".into(),
        secret_schema: vec![],
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    instances::create(&state.db, &user.id, None, Some(&def), "broken", "Broken")
        .await
        .unwrap();

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // The broken backend contributes no tools but does not fail the session.
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("broken__")));

    // ...and its failure is reported so the user can diagnose it.
    let listed = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_my_servers".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"runtime_status\":\"error\""), "got {json}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn proxy_aggregates_resources_and_prompts() {
    let exe = mock_server_path();
    assert!(std::path::Path::new(&exe).exists(), "build mock_mcp_server first");

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
    instances::create(&state.db, &user.id, None, Some(&def), "mock", "Mock")
        .await
        .unwrap();

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // Resources are aggregated with namespaced URIs (hub://<ns>/<original>).
    let resources = client.list_all_resources().await.unwrap();
    let wrapped_uri = "hub://mock/mock://greeting";
    assert!(
        resources.iter().any(|r| r.uri == wrapped_uri),
        "got {:?}",
        resources.iter().map(|r| &r.uri).collect::<Vec<_>>()
    );

    // Reading the wrapped URI routes back to the mock and returns its content.
    let read = client
        .read_resource(ReadResourceRequestParam {
            uri: wrapped_uri.to_string(),
        })
        .await
        .unwrap();
    let read_json = serde_json::to_string(&read.contents).unwrap();
    assert!(read_json.contains("hello from mock"), "got {read_json}");
    // The returned content URI is re-wrapped so the client sees a consistent id.
    assert!(read_json.contains(wrapped_uri), "got {read_json}");

    // An unknown namespace is rejected, not silently routed.
    let bad = client
        .read_resource(ReadResourceRequestParam {
            uri: "hub://nope/x".to_string(),
        })
        .await;
    assert!(bad.is_err());

    // Prompts are aggregated and namespaced like tools.
    let prompts = client.list_all_prompts().await.unwrap();
    assert!(
        prompts.iter().any(|p| p.name == "mock__hello"),
        "got {:?}",
        prompts.iter().map(|p| &p.name).collect::<Vec<_>>()
    );

    let got = client
        .get_prompt(GetPromptRequestParam {
            name: "mock__hello".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let got_json = serde_json::to_string(&got.messages).unwrap();
    assert!(got_json.contains("Say hello"), "got {got_json}");

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
async fn admin_invite_tools_round_trip() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "admin1", "alice", "Alice", true)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "client", &format!("{base}/mcp"), "mcp", true, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // Generate an invite; the plaintext code is returned exactly once.
    let created = client
        .call_tool(CallToolRequestParam {
            name: "hub__create_invite".into(),
            arguments: args(serde_json::json!({"note": "for bob"})),
        })
        .await
        .unwrap();
    let created = created.structured_content.unwrap();
    let code = created["code"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();
    assert!(!code.is_empty());

    // It is redeemable and shows up as unused in the listing.
    assert!(mcp_hub::invites::is_redeemable(&state.db, &code)
        .await
        .unwrap());
    let listed = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_invites".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let listed_json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(listed_json.contains(&id));
    assert!(listed_json.contains("\"used\":false"));
    // The plaintext code is never echoed back by the listing.
    assert!(!listed_json.contains(&code));

    // Revoke it; afterwards it is no longer redeemable.
    client
        .call_tool(CallToolRequestParam {
            name: "hub__revoke_invite".into(),
            arguments: args(serde_json::json!({"id": id})),
        })
        .await
        .unwrap();
    assert!(!mcp_hub::invites::is_redeemable(&state.db, &code)
        .await
        .unwrap());

    let _ = client.cancel().await;
}

#[tokio::test]
async fn admin_can_disable_and_delete_users() {
    let (base, state) = spawn_hub().await;
    let admin = users::create(&state.db, "admin1", "alice", "Alice", true)
        .await
        .unwrap();
    let bob = users::create(&state.db, "u2", "bob", "Bob", false)
        .await
        .unwrap();

    let admin_token = state
        .signer
        .issue_access_token(&admin.id, "c", &format!("{base}/mcp"), "mcp", true, 3600)
        .unwrap()
        .0;
    let bob_token = state
        .signer
        .issue_access_token(&bob.id, "c", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap()
        .0;

    // Bob can connect to start with.
    assert!(try_connect(&base, bob_token.clone()).await.is_ok());

    let admin_client = connect(&base, admin_token).await;

    // The admin cannot disable themselves (last admin + self guard).
    let self_disable = admin_client
        .call_tool(CallToolRequestParam {
            name: "hub__disable_user".into(),
            arguments: args(serde_json::json!({"handle": "alice"})),
        })
        .await;
    let blocked = match self_disable {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(blocked, "admin must not disable their own/last-admin account");

    // Disabling Bob revokes his proxy access immediately.
    admin_client
        .call_tool(CallToolRequestParam {
            name: "hub__disable_user".into(),
            arguments: args(serde_json::json!({"handle": "bob"})),
        })
        .await
        .unwrap();
    assert!(
        try_connect(&base, bob_token.clone()).await.is_err(),
        "disabled user's token must be rejected"
    );

    // Re-enabling restores access.
    admin_client
        .call_tool(CallToolRequestParam {
            name: "hub__enable_user".into(),
            arguments: args(serde_json::json!({"handle": "bob"})),
        })
        .await
        .unwrap();
    assert!(try_connect(&base, bob_token).await.is_ok());

    // Deleting Bob removes the account.
    admin_client
        .call_tool(CallToolRequestParam {
            name: "hub__delete_user".into(),
            arguments: args(serde_json::json!({"handle": "bob"})),
        })
        .await
        .unwrap();
    assert!(users::find_by_handle(&state.db, "bob")
        .await
        .unwrap()
        .is_none());

    let _ = admin_client.cancel().await;
}

#[tokio::test]
async fn http_remote_url_is_configurable() {
    let (base, state) = spawn_hub().await;
    let admin = users::create(&state.db, "admin1", "alice", "Alice", true)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&admin.id, "c", &format!("{base}/mcp"), "mcp", true, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // 'memory' is a built-in http remote.
    client
        .call_tool(CallToolRequestParam {
            name: "hub__add_server".into(),
            arguments: args(serde_json::json!({"catalog_slug": "memory", "namespace": "mem"})),
        })
        .await
        .unwrap();

    // The per-instance remote URL is settable via MCP_URL even though it is not
    // in the catalog's secret_schema.
    let set_url = client
        .call_tool(CallToolRequestParam {
            name: "hub__configure".into(),
            arguments: args(serde_json::json!({
                "namespace": "mem",
                "values": {"MCP_URL": "https://my-memory.example.net/mcp"}
            })),
        })
        .await
        .unwrap();
    assert_ne!(set_url.is_error, Some(true));

    // A non-URL value is rejected...
    let bad_url = client
        .call_tool(CallToolRequestParam {
            name: "hub__configure".into(),
            arguments: args(serde_json::json!({
                "namespace": "mem", "values": {"MCP_URL": "not-a-url"}
            })),
        })
        .await;
    assert!(bad_url.is_err() || bad_url.unwrap().is_error == Some(true));

    // ...and an undeclared, non-URL key is still rejected (schema restriction).
    let injected = client
        .call_tool(CallToolRequestParam {
            name: "hub__configure".into(),
            arguments: args(serde_json::json!({
                "namespace": "mem", "values": {"PYTHONSTARTUP": "/tmp/x"}
            })),
        })
        .await;
    assert!(injected.is_err() || injected.unwrap().is_error == Some(true));

    // The URL shows up in the instance config.
    let listed = client
        .call_tool(CallToolRequestParam {
            name: "hub__list_my_servers".into(),
            arguments: None,
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("my-memory.example.net"), "got {json}");

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
