//! End-to-end proxy tests: a real MCP client connects to the hub over Streamable
//! HTTP with an OAuth bearer token. Covers backend aggregation and the built-in
//! `hub__` management interface.
//!
//! Endpoint model: the base `/mcp` endpoint serves only the `hub__*` management
//! tools; backend tools/prompts/resources are served on connector-group
//! endpoints at `/mcp/<slug>`. Tests that exercise backends create a group
//! (slug "g" by convention) and connect there with a matching-audience token.

use mcp_hub::config::{Config, Limits};
use mcp_hub::instances::ServerDef;
use mcp_hub::oauth::store;
use mcp_hub::{build_router, db, instances, users, AppState};
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams};
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
    spawn_hub_with_limits(Limits::default()).await
}

/// As [`spawn_hub`], but with caller-chosen backend limits (e.g. a short
/// `backend_call_timeout_secs` to exercise the proxied-call timeout).
async fn spawn_hub_with_limits(limits: Limits) -> (String, AppState) {
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
        env_dir: std::env::temp_dir()
            .join(format!("mcp_hub_envs_{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
        master_key: [1u8; 32],
        bootstrap_admin: None,
        allow_open_registration: false,
        sandbox_uid_base: None,
        // Tests drive warming explicitly via `pool::warm_all` (the warmer task
        // only runs in the real binary anyway).
        keep_warm: false,
        keep_warm_interval_secs: 0,
        limits,
        child_limits: Default::default(),

        block_private_backend_ips: false,
        allowed_hosts: Vec::new(),
        session_idle_ttl_secs: 1800,
        session_absolute_ttl_secs: 43200,
    };
    let state = AppState::new(config, pool).await.unwrap();

    let app = build_router(state.clone(), "static");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, state)
}

/// Try to connect an MCP client to an endpoint path (`/mcp` or `/mcp/<slug>`);
/// returns the error instead of panicking so tests can assert rejection.
async fn try_connect_at(
    base: &str,
    path: &str,
    token: String,
) -> Result<RunningService<RoleClient, ()>, Box<dyn std::error::Error>> {
    let config =
        StreamableHttpClientTransportConfig::with_uri(format!("{base}{path}")).auth_header(token);
    Ok(serve_client((), StreamableHttpClientTransport::from_config(config)).await?)
}

/// As [`try_connect_at`] for the base `/mcp` endpoint.
async fn try_connect(
    base: &str,
    token: String,
) -> Result<RunningService<RoleClient, ()>, Box<dyn std::error::Error>> {
    try_connect_at(base, "/mcp", token).await
}

/// Connect an MCP client to the hub's base `/mcp` (management) endpoint.
async fn connect(base: &str, token: String) -> RunningService<RoleClient, ()> {
    try_connect(base, token)
        .await
        .expect("MCP client should initialize through the proxy")
}

/// Connect an MCP client to a connector-group endpoint.
async fn connect_at(base: &str, path: &str, token: String) -> RunningService<RoleClient, ()> {
    try_connect_at(base, path, token)
        .await
        .expect("MCP client should initialize through the proxy")
}

/// Create a connector group with the given member instance ids.
async fn make_group(state: &AppState, user_id: &str, slug: &str, instance_ids: &[String]) {
    let g = mcp_hub::groups::create(&state.db, user_id, slug, slug)
        .await
        .unwrap();
    mcp_hub::groups::set_members(&state.db, user_id, &g.id, instance_ids)
        .await
        .unwrap();
}

/// Issue an OAuth access token whose audience is the group endpoint `/mcp/g`.
fn group_token(state: &AppState, base: &str, user_id: &str, client: &str) -> String {
    state
        .signer
        .issue_access_token(
            user_id,
            client,
            &format!("{base}/mcp/g"),
            "mcp",
            false,
            3600,
        )
        .unwrap()
        .0
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
        transport: "stdio".into(),
        command: Some("example-mcp".into()),
        args: vec![],
        url: None,
        runtime: "python".into(),
        repo: Some("https://github.com/example/mcp".into()),
        git_ref: Some("main".into()),
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "git", "Git Server")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    // The unbuilt backend contributes no tools to its group (skipped, not fatal).
    let gclient = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;
    let names: Vec<String> = gclient
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with("git__")),
        "got {names:?}"
    );

    // ...and it is reported as unbuilt (on the management endpoint) so the user
    // knows to run hub__update_server.
    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;
    let listed = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"build_status\":\"unbuilt\""), "got {json}");

    let _ = gclient.cancel().await;
    let _ = client.cancel().await;
}

/// Git credentials are write-only over MCP: storing one echoes the host back,
/// and nothing — not the set result, the listing, nor the server listing — ever
/// carries the token. A regression here is a silent secret disclosure.
#[tokio::test]
async fn git_credential_tools_never_echo_the_token() {
    const TOKEN: &str = "ghp_e2e_secret_token_value";
    let (base, state) = spawn_hub().await;
    users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    // A git-sourced server on the same host, to exercise git_credential_host.
    let def = ServerDef {
        name: "Git Server".into(),
        description: String::new(),
        transport: "stdio".into(),
        command: Some("example-mcp".into()),
        args: vec![],
        url: None,
        runtime: "python".into(),
        repo: Some("https://github.com/example/private".into()),
        git_ref: Some("main".into()),
        entry: None,
        module: None,
    };
    instances::create(&state.db, "u1", None, Some(&def), "git", "Git Server")
        .await
        .unwrap();

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;
    let call = |name: &'static str, a: Option<serde_json::Map<String, serde_json::Value>>| {
        let client = &client;
        async move {
            let res = client
                .call_tool({
                    let mut p = CallToolRequestParams::new(name);
                    p.arguments = a;
                    p
                })
                .await
                .unwrap();
            serde_json::to_string(&res).unwrap()
        }
    };

    let stored = call(
        "hub__set_git_credential",
        args(serde_json::json!({"host": "https://github.com/example/private", "token": TOKEN, "label": "e2e"})),
    )
    .await;
    assert!(stored.contains("github.com"), "got {stored}");
    assert!(!stored.contains(TOKEN), "set echoed the token: {stored}");

    let listed = call("hub__list_git_credentials", None).await;
    assert!(listed.contains("github.com"), "got {listed}");
    assert!(
        listed.contains("x-access-token"),
        "blank username should default: {listed}"
    );
    assert!(!listed.contains(TOKEN), "list leaked the token: {listed}");

    // The server listing names the matching host so a failed build is
    // diagnosable, but still carries no secret.
    let servers = call("hub__list_my_servers", None).await;
    assert!(
        servers.contains("\"git_credential_host\":\"github.com\""),
        "got {servers}"
    );
    assert!(
        !servers.contains(TOKEN),
        "server list leaked the token: {servers}"
    );

    let deleted = call(
        "hub__delete_git_credential",
        args(serde_json::json!({"host": "github.com"})),
    )
    .await;
    assert!(deleted.contains("\"deleted\":true"), "got {deleted}");
    let listed = call("hub__list_git_credentials", None).await;
    assert!(
        !listed.contains("github.com"),
        "credential survived deletion: {listed}"
    );

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
    make_group(&state, &user.id, "g", &[inst.id]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");
    // Management tools live on the base endpoint, not on groups.
    assert!(
        !names.iter().any(|n| n.starts_with("hub__")),
        "got {names:?}"
    );

    let result = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("mock__echo");
            __p.arguments = args(serde_json::json!({ "msg": "hello" }));
            __p
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&result.content).unwrap();
    assert!(rendered.contains("PFX:hello"), "got {rendered}");

    let bad = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("nope__tool");
            __p.arguments = None;
            __p
        })
        .await;
    assert!(bad.is_err());

    // The exact launch command is reported for stdio backends (management endpoint).
    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let mclient = connect(&base, token).await;
    let listed = mclient
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"command\""), "got {json}");
    assert!(json.contains("mock_mcp_server"), "got {json}");

    let _ = client.cancel().await;
    let _ = mclient.cancel().await;
}

/// A proxied tool call that outruns `backend_call_timeout_secs` is aborted by
/// the hub and surfaced to the client as an error, rather than hanging forever.
/// Exercises `with_call_timeout` end-to-end (including the timeout warn path).
#[tokio::test]
async fn slow_backend_call_times_out() {
    let exe = mock_server_path();
    assert!(
        std::path::Path::new(&exe).exists(),
        "build the example first: cargo build --example mock_mcp_server"
    );

    let limits = Limits {
        backend_call_timeout_secs: 1,
        ..Limits::default()
    };
    let (base, state) = spawn_hub_with_limits(limits).await;
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
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "mock", "Mock")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

    // A 5s sleep under a 1s cap must come back as an error to the client.
    let result = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("mock__sleep");
            __p.arguments = args(serde_json::json!({ "ms": 5000 }));
            __p
        })
        .await;
    assert!(result.is_err(), "slow call should time out, got {result:?}");
    assert!(
        format!("{:?}", result.unwrap_err()).contains("timed out"),
        "error should mention the timeout"
    );

    // A fast call on the same backend still succeeds (the cap is per-call).
    let ok = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("mock__sleep");
            __p.arguments = args(serde_json::json!({ "ms": 0 }));
            __p
        })
        .await
        .unwrap();
    assert!(serde_json::to_string(&ok.content)
        .unwrap()
        .contains("slept"));

    let _ = client.cancel().await;
}

/// Bumping a server's reload epoch (what the web Restart button does) relaunches
/// just that backend in a live session, so a configuration change takes effect
/// without reconnecting the MCP client — and a config change alone does NOT
/// reload (the action is explicit, by design).
#[tokio::test]
async fn restart_reloads_backend_config_in_a_live_session() {
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
    make_group(&state, &user.id, "g", std::slice::from_ref(&inst.id)).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

    async fn echo(client: &RunningService<RoleClient, ()>) -> String {
        let result = client
            .call_tool({
                let mut __p = CallToolRequestParams::new("mock__echo");
                __p.arguments = args(serde_json::json!({ "msg": "hi" }));
                __p
            })
            .await
            .unwrap();
        serde_json::to_string(&result.content).unwrap()
    }

    // First call binds the backend with the original prefix.
    assert!(echo(&client).await.contains("PFX:hi"));

    // Change the config but do NOT restart: the live session keeps the old
    // process, so the prefix is unchanged (config edits don't auto-reload).
    instances::set_config_value(&state.db, &inst.id, "MOCK_PREFIX", "NEW:")
        .await
        .unwrap();
    let still_old = echo(&client).await;
    assert!(
        still_old.contains("PFX:hi"),
        "should not auto-reload: {still_old}"
    );

    // Bump the reload epoch (the Restart button) — the next request respawns
    // just this backend with the new config, over the same MCP session.
    state.bump_reload(&inst.id);
    let reloaded = echo(&client).await;
    assert!(
        reloaded.contains("NEW:hi"),
        "should reload after restart: {reloaded}"
    );

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
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "broken", "Broken")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    // The broken backend contributes no tools but does not fail the session.
    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("broken__")));

    // ...and its failure is reported so the user can diagnose it.
    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let mclient = connect(&base, token).await;
    let listed = mclient
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"runtime_status\":\"error\""), "got {json}");

    let _ = client.cancel().await;
    let _ = mclient.cancel().await;
}

#[tokio::test]
async fn proxy_aggregates_resources_and_prompts() {
    let exe = mock_server_path();
    assert!(
        std::path::Path::new(&exe).exists(),
        "build mock_mcp_server first"
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
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "mock", "Mock")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

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
        .read_resource(ReadResourceRequestParams::new(wrapped_uri.to_string()))
        .await
        .unwrap();
    let read_json = serde_json::to_string(&read.contents).unwrap();
    assert!(read_json.contains("hello from mock"), "got {read_json}");
    // The returned content URI is re-wrapped so the client sees a consistent id.
    assert!(read_json.contains(wrapped_uri), "got {read_json}");

    // An unknown namespace is rejected, not silently routed.
    let bad = client
        .read_resource(ReadResourceRequestParams::new("hub://nope/x".to_string()))
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
        .get_prompt({
            let mut __p = GetPromptRequestParams::new("mock__hello");
            __p.arguments = None;
            __p
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
        .issue_access_token(
            &user.id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            true,
            3600,
        )
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
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__whoami");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    assert_eq!(who.structured_content.unwrap()["handle"], "alice");

    // Add a user-defined stdio server, set its env, then list it back.
    let added = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__add_server");
            __p.arguments = args(serde_json::json!({
                "namespace": "zbx", "transport": "stdio",
                "command": "uvx zabbix-mcp-server", "display_name": "My Zabbix",
                "env": {"ZABBIX_TOKEN": "s3cr3t"}
            }));
            __p
        })
        .await
        .unwrap();
    assert_eq!(added.structured_content.unwrap()["added"], true);

    let listed = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let listed_json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(listed_json.contains("zbx"));
    assert!(listed_json.contains("zabbix-mcp-server")); // command is shown
    assert!(listed_json.contains("ZABBIX_TOKEN")); // env key name listed...
    assert!(!listed_json.contains("s3cr3t")); // ...value never returned

    // Replacing the env keeps only the new keys.
    client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__set_env");
            __p.arguments = args(
                serde_json::json!({"namespace": "zbx", "env": {"ZABBIX_URL": "https://z/api"}}),
            );
            __p
        })
        .await
        .unwrap();
    let relisted = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let relisted_json = serde_json::to_string(&relisted.structured_content).unwrap();
    assert!(relisted_json.contains("ZABBIX_URL"));
    assert!(!relisted_json.contains("ZABBIX_TOKEN"));

    // Reserved namespace cannot be claimed via the management interface.
    let reserved = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__add_server");
            __p.arguments =
                args(serde_json::json!({"namespace": "hub", "transport": "stdio", "command": "x"}));
            __p
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
        .issue_access_token(
            &user.id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            true,
            3600,
        )
        .unwrap();
    let client = connect(&base, token).await;

    // Generate an invite; the plaintext code is returned exactly once.
    let created = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__create_invite");
            __p.arguments = args(serde_json::json!({"note": "for bob"}));
            __p
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
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_invites");
            __p.arguments = None;
            __p
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
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__revoke_invite");
            __p.arguments = args(serde_json::json!({"id": id}));
            __p
        })
        .await
        .unwrap();
    assert!(!mcp_hub::invites::is_redeemable(&state.db, &code)
        .await
        .unwrap());

    let _ = client.cancel().await;
}

#[tokio::test]
async fn personal_access_token_tools_round_trip() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(
            &user.id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let client = connect(&base, token).await;

    // A token is minted out of band (web UI only); it shows up in the listing.
    let (pat, secret) = mcp_hub::tokens::create(&state.db, &user.id, "laptop", 3600)
        .await
        .unwrap();
    let listed = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_tokens");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let listed_json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(listed_json.contains(&pat.id));
    assert!(listed_json.contains("laptop"));
    // The secret is never echoed back.
    assert!(!listed_json.contains(&secret));

    // Revoke it over MCP; afterwards it no longer authenticates.
    let revoked = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__revoke_token");
            __p.arguments = args(serde_json::json!({"token_id": pat.id}));
            __p
        })
        .await
        .unwrap();
    assert_eq!(revoked.structured_content.unwrap()["revoked"], true);
    let hash = mcp_hub::oauth::token_hash(&secret);
    assert!(mcp_hub::tokens::resolve_valid(&state.db, &hash)
        .await
        .unwrap()
        .is_none());

    let _ = client.cancel().await;
}

/// Register two OAuth clients for one user with a live connection each.
async fn seed_client(state: &AppState, user_id: &str, client_id: &str, name: &str) {
    store::create_client(
        &state.db,
        client_id,
        None,
        &[],
        &serde_json::json!({ "client_name": name }),
    )
    .await
    .unwrap();
    store::insert_refresh(
        &state.db,
        &format!("hash-{client_id}"),
        client_id,
        user_id,
        "mcp",
        None,
        "fam",
        3600,
        &Default::default(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn client_can_label_only_itself() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();

    // Two clients on the SAME account. client-b already has a label.
    seed_client(&state, &user.id, "client-a", "Claude A").await;
    seed_client(&state, &user.id, "client-b", "Claude B").await;
    store::set_client_label(&state.db, &user.id, "client-b", "B custom", "b note")
        .await
        .unwrap();

    // Connect as client-a.
    let (token, _) = state
        .signer
        .issue_access_token(
            &user.id,
            "client-a",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let client = connect(&base, token).await;

    // get_my_client returns client-a's own (empty) label + its registered name,
    // and never leaks client-b's label.
    let got = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__get_my_client");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let g = got.structured_content.unwrap();
    assert_eq!(g["client_id"], "client-a");
    assert_eq!(g["registered_name"], "Claude A");
    assert_eq!(g["name"], "");
    assert!(!serde_json::to_string(&g).unwrap().contains("B custom"));

    // set_my_client updates only client-a.
    let set = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__set_my_client");
            __p.arguments = args(serde_json::json!({"name": "My Laptop", "note": "personal"}));
            __p
        })
        .await
        .unwrap();
    assert_eq!(set.structured_content.unwrap()["name"], "My Laptop");

    // client-a's label changed; client-b's is untouched. The tool exposes no
    // argument to target another client, so client-b is unreachable from here.
    assert_eq!(
        store::get_client_label(&state.db, &user.id, "client-a")
            .await
            .unwrap(),
        ("My Laptop".to_string(), "personal".to_string())
    );
    assert_eq!(
        store::get_client_label(&state.db, &user.id, "client-b")
            .await
            .unwrap(),
        ("B custom".to_string(), "b note".to_string())
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn self_service_client_tools_reject_personal_access_tokens() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    // A PAT is not tied to an OAuth client, so it cannot use the *_my_client tools.
    let (_pat, secret) = mcp_hub::tokens::create(&state.db, &user.id, "laptop", 3600)
        .await
        .unwrap();
    let client = connect(&base, secret).await;

    let res = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__set_my_client");
            __p.arguments = args(serde_json::json!({"name": "x"}));
            __p
        })
        .await;
    let rejected = match res {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(
        rejected,
        "a personal access token must not set a client label"
    );

    let _ = client.cancel().await;
}

/// Create a user with the mock stdio backend under namespace "mock", in a
/// connector group with slug "g"; returns (base, state, user_id, instance_id).
async fn hub_with_mock_backend() -> (String, AppState, String, String) {
    let exe = mock_server_path();
    assert!(
        std::path::Path::new(&exe).exists(),
        "build the mock example first"
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
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "mock", "Mock")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", std::slice::from_ref(&inst.id)).await;
    (base, state, user.id, inst.id)
}

#[tokio::test]
async fn denied_backend_is_hidden_from_oauth_client() {
    let (base, state, user_id, inst_id) = hub_with_mock_backend().await;
    let token = state
        .signer
        .issue_access_token(
            &user_id,
            "client-x",
            &format!("{base}/mcp/g"),
            "mcp",
            false,
            3600,
        )
        .unwrap()
        .0;
    let client = connect_at(&base, "/mcp/g", token).await;

    // Full access by default.
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");

    // Deny this client the mock backend.
    mcp_hub::access::set_denials(
        &state.db,
        &user_id,
        mcp_hub::access::OAUTH,
        "client-x",
        &[inst_id],
    )
    .await
    .unwrap();

    // The backend's tool is now gone even though it is still a group member
    // (denials compose with group scoping).
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.contains(&"mock__echo".to_string()),
        "still listed: {names:?}"
    );

    // And a direct call is refused.
    let blocked = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("mock__echo");
            __p.arguments = args(serde_json::json!({ "msg": "hi" }));
            __p
        })
        .await;
    assert!(blocked.is_err(), "denied backend call should fail");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn denied_backend_is_hidden_from_pat() {
    let (base, state, user_id, inst_id) = hub_with_mock_backend().await;
    let (pat, secret) = mcp_hub::tokens::create(&state.db, &user_id, "laptop", 3600)
        .await
        .unwrap();
    // PATs carry no audience, so one works on a group endpoint directly.
    let client = connect_at(&base, "/mcp/g", secret).await;

    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");

    // Deny this PAT the mock backend (exercises the pat_id credential path).
    mcp_hub::access::set_denials(
        &state.db,
        &user_id,
        mcp_hub::access::PAT,
        &pat.id,
        &[inst_id],
    )
    .await
    .unwrap();

    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.contains(&"mock__echo".to_string()),
        "still listed: {names:?}"
    );

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
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__disable_user");
            __p.arguments = args(serde_json::json!({"handle": "alice"}));
            __p
        })
        .await;
    let blocked = match self_disable {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(
        blocked,
        "admin must not disable their own/last-admin account"
    );

    // Disabling Bob revokes his proxy access immediately.
    admin_client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__disable_user");
            __p.arguments = args(serde_json::json!({"handle": "bob"}));
            __p
        })
        .await
        .unwrap();
    assert!(
        try_connect(&base, bob_token.clone()).await.is_err(),
        "disabled user's token must be rejected"
    );

    // Re-enabling restores access.
    admin_client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__enable_user");
            __p.arguments = args(serde_json::json!({"handle": "bob"}));
            __p
        })
        .await
        .unwrap();
    assert!(try_connect(&base, bob_token).await.is_ok());

    // Deleting Bob removes the account.
    admin_client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__delete_user");
            __p.arguments = args(serde_json::json!({"handle": "bob"}));
            __p
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
async fn http_server_add_and_edit() {
    let (base, state) = spawn_hub().await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let (token, _) = state
        .signer
        .issue_access_token(&user.id, "c", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let client = connect(&base, token).await;

    // Add an http server with its own URL — a bad URL is rejected.
    let bad = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__add_server");
            __p.arguments = args(
                serde_json::json!({"namespace": "mem", "transport": "http", "url": "not-a-url"}),
            );
            __p
        })
        .await;
    assert!(bad.is_err() || bad.unwrap().is_error == Some(true));

    client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__add_server");
            __p.arguments = args(serde_json::json!({
                "namespace": "mem", "transport": "http",
                "url": "https://memory.example.net/mcp",
                "env": {"AUTHORIZATION": "Bearer t"}
            }));
            __p
        })
        .await
        .unwrap();

    // Edit the URL.
    client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__edit_server");
            __p.arguments = args(
                serde_json::json!({"namespace": "mem", "url": "https://other.example.net/mcp"}),
            );
            __p
        })
        .await
        .unwrap();

    let listed = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("other.example.net"), "got {json}");
    assert!(json.contains("\"transport\":\"http\""), "got {json}");

    let _ = client.cancel().await;
}

/// An http backend authenticates with the scheme it was configured with: with
/// `AUTHORIZATION_METHOD=Basic` the credential must reach the remote verbatim as
/// `Authorization: Basic <credential>`, not re-encoded and not forced onto
/// `Bearer`. Asserted on the wire because the header is written by the transport,
/// below anything the hub's own types can show.
#[tokio::test]
async fn http_backend_sends_the_configured_auth_scheme() {
    use std::sync::{Arc, Mutex};

    // A stand-in for the remote MCP server that records what it was sent. It
    // never completes the handshake — the header lands on the first POST, which
    // is all this test needs.
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!(
        "http://127.0.0.1:{}/mcp",
        listener.local_addr().unwrap().port()
    );
    let app =
        axum::Router::new().fallback(axum::routing::any(move |headers: axum::http::HeaderMap| {
            let captured = captured.clone();
            async move {
                *captured.lock().unwrap() = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .map(|v| v.to_str().unwrap_or_default().to_string());
                axum::http::StatusCode::UNAUTHORIZED
            }
        }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // The stand-in never handshakes, so cap the wait rather than burning the
    // default 20s connect timeout — the header is already captured by then.
    let limits = Limits {
        backend_connect_timeout_secs: 2,
        ..Limits::default()
    };
    let (base, state) = spawn_hub_with_limits(limits).await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let def = ServerDef {
        name: "Remote".into(),
        description: String::new(),
        transport: "http".into(),
        command: None,
        args: vec![],
        url: Some(upstream),
        runtime: "remote".into(),
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&state.db, &user.id, None, Some(&def), "remote", "Remote")
        .await
        .unwrap();
    let env: std::collections::BTreeMap<String, String> = [
        ("AUTHORIZATION".to_string(), "dXNlcjpwYXNz".to_string()),
        ("AUTHORIZATION_METHOD".to_string(), "Basic".to_string()),
    ]
    .into_iter()
    .collect();
    instances::replace_env(&state.db, &state.secrets, &inst.id, &env)
        .await
        .unwrap();
    make_group(&state, &user.id, "g", std::slice::from_ref(&inst.id)).await;

    // Listing tools binds the group's backends, which dials the stand-in. The
    // backend fails to initialize (by design), so the hub just reports no tools.
    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, &user.id, "c")).await;
    let _ = client.list_all_tools().await;
    let _ = client.cancel().await;

    let header = seen.lock().unwrap().clone();
    assert_eq!(
        header.as_deref(),
        Some("Basic dXNlcjpwYXNz"),
        "backend should have been dialed with the Basic scheme"
    );
}

/// The mock backend as a plain stdio ServerDef.
fn mock_def() -> ServerDef {
    ServerDef {
        name: "Mock".into(),
        description: String::new(),
        transport: "stdio".into(),
        command: Some(mock_server_path()),
        args: vec![],
        url: None,
        runtime: "binary".into(),
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    }
}

/// Call the mock's `pid` tool: the OS process id of the backend serving this
/// client, which is what proves (non-)reuse across sessions.
async fn mock_pid(client: &RunningService<RoleClient, ()>, tool: &str) -> String {
    let result = client
        .call_tool({
            let mut __p = CallToolRequestParams::new(tool.to_string());
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    serde_json::to_string(&result.content).unwrap()
}

/// Backends are pooled per user: a second session (after the first is gone)
/// reuses the same live subprocess instead of paying a fresh cold start.
#[tokio::test]
async fn backend_pool_is_shared_across_sessions() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;

    let token = |n: &str| group_token(&state, &base, &user_id, n);
    let a = connect_at(&base, "/mcp/g", token("client-a")).await;
    let pid_a = mock_pid(&a, "mock__pid").await;
    let _ = a.cancel().await;

    let b = connect_at(&base, "/mcp/g", token("client-b")).await;
    let pid_b = mock_pid(&b, "mock__pid").await;
    assert_eq!(
        pid_a, pid_b,
        "second session should reuse the pooled backend"
    );
    let _ = b.cancel().await;
}

/// Two sessions binding at the same time must not double-spawn: the bind lock
/// serializes them onto one backend.
#[tokio::test]
async fn concurrent_sessions_share_one_backend() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;

    let token = |n: &str| group_token(&state, &base, &user_id, n);
    let (a, b) = tokio::join!(
        connect_at(&base, "/mcp/g", token("c-a")),
        connect_at(&base, "/mcp/g", token("c-b"))
    );
    let (pid_a, pid_b) = tokio::join!(mock_pid(&a, "mock__pid"), mock_pid(&b, "mock__pid"));
    assert_eq!(pid_a, pid_b, "concurrent sessions should share one backend");
    let _ = a.cancel().await;
    let _ = b.cancel().await;
}

/// A backend that hangs during its `initialize` handshake is cut off by
/// `HUB_BACKEND_CONNECT_TIMEOUT_SECS` and skipped — the session still gets its
/// other tools promptly, and the failure is reported on the instance.
#[tokio::test]
async fn hung_initialize_is_timed_out_and_skipped() {
    let limits = Limits {
        backend_connect_timeout_secs: 1,
        ..Limits::default()
    };
    let (base, state) = spawn_hub_with_limits(limits).await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let inst = instances::create(&state.db, &user.id, None, Some(&mock_def()), "hang", "Hang")
        .await
        .unwrap();
    instances::set_config_value(&state.db, &inst.id, "MOCK_INIT_DELAY_MS", "30000")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with("hang__")),
        "got {names:?}"
    );

    let (token, _) = state
        .signer
        .issue_access_token("u1", "client", &format!("{base}/mcp"), "mcp", false, 3600)
        .unwrap();
    let mclient = connect(&base, token).await;
    let listed = mclient
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_my_servers");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("timed out"), "timeout not reported: {json}");

    let _ = client.cancel().await;
    let _ = mclient.cancel().await;
}

/// A backend that hangs answering `tools/list` is skipped from the aggregate
/// (after `HUB_BACKEND_LIST_TIMEOUT_SECS`) instead of stalling the client.
#[tokio::test]
async fn hung_tools_list_is_skipped_not_fatal() {
    let limits = Limits {
        backend_list_timeout_secs: 1,
        ..Limits::default()
    };
    let (base, state) = spawn_hub_with_limits(limits).await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let inst = instances::create(
        &state.db,
        &user.id,
        None,
        Some(&mock_def()),
        "slowlist",
        "SlowList",
    )
    .await
    .unwrap();
    instances::set_config_value(&state.db, &inst.id, "MOCK_LIST_DELAY_MS", "30000")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[inst.id]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

    let t0 = std::time::Instant::now();
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with("slowlist__")),
        "got {names:?}"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "list should be cut off by the list timeout, took {:?}",
        t0.elapsed()
    );

    let _ = client.cancel().await;
}

/// The idle reaper retires a user's pooled backends; the next request simply
/// rebinds fresh ones (a new subprocess).
#[tokio::test]
async fn idle_reap_retires_backends_and_next_request_rebinds() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    let client = connect_at(
        &base,
        "/mcp/g",
        group_token(&state, &base, &user_id, "client"),
    )
    .await;

    let pid_before = mock_pid(&client, "mock__pid").await;
    let (users, backends) = state.backend_pool.reap_idle(std::time::Duration::ZERO);
    assert_eq!(
        (users, backends),
        (1, 1),
        "one pooled user with one backend"
    );

    // Same live session: the next request rebinds against a fresh subprocess.
    let pid_after = mock_pid(&client, "mock__pid").await;
    assert_ne!(
        pid_before, pid_after,
        "reap should have retired the old process"
    );

    let _ = client.cancel().await;
}

/// Disabling a server tears its pooled backend down for live sessions on their
/// next request (no reconnect needed), and re-enabling brings it back.
#[tokio::test]
async fn disable_and_enable_converge_in_live_sessions() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    // Backend visibility is observed on the group endpoint; the disable/enable
    // management calls go through the base endpoint.
    let gclient = connect_at(
        &base,
        "/mcp/g",
        group_token(&state, &base, &user_id, "client"),
    )
    .await;
    let (token, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let mclient = connect(&base, token).await;

    async fn list(client: &RunningService<RoleClient, ()>) -> Vec<String> {
        client
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .map(|t| t.name.to_string())
            .collect()
    }
    assert!(list(&gclient).await.contains(&"mock__echo".to_string()));

    mclient
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__disable");
            __p.arguments = args(serde_json::json!({"namespace": "mock"}));
            __p
        })
        .await
        .unwrap();
    let names = list(&gclient).await;
    assert!(
        !names.contains(&"mock__echo".to_string()),
        "still listed: {names:?}"
    );

    mclient
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__enable");
            __p.arguments = args(serde_json::json!({"namespace": "mock"}));
            __p
        })
        .await
        .unwrap();
    let names = list(&gclient).await;
    assert!(
        names.contains(&"mock__echo".to_string()),
        "not back: {names:?}"
    );

    let _ = gclient.cancel().await;
    let _ = mclient.cancel().await;
}

/// Keep-warm binds backends before any client connects, so the first
/// connection finds hot tools — and re-warming never respawns a healthy one.
#[tokio::test]
async fn warm_all_prewarms_backends_before_any_connection() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    // A second user with no servers must not be warmed into an empty entry.
    users::create(&state.db, "u2", "bob", "Bob", false)
        .await
        .unwrap();

    let (users, backends) = mcp_hub::proxy::pool::warm_all(&state).await;
    assert_eq!(
        (users, backends),
        (1, 1),
        "one user with one enabled server"
    );
    assert_eq!(
        state.backend_pool.counts(),
        (1, 1),
        "backend live before any client"
    );

    // The pre-warmed subprocess is exactly what a new connection is handed…
    let client = connect_at(
        &base,
        "/mcp/g",
        group_token(&state, &base, &user_id, "client"),
    )
    .await;
    let pid_before = mock_pid(&client, "mock__pid").await;

    // …and a re-warm pass leaves the healthy backend untouched.
    let _ = mcp_hub::proxy::pool::warm_all(&state).await;
    let pid_after = mock_pid(&client, "mock__pid").await;
    assert_eq!(
        pid_before, pid_after,
        "re-warm must not respawn a healthy backend"
    );

    let _ = client.cancel().await;
}

/// A bind budget answers the first `tools/list` with whatever connected in
/// time; a slow-starting backend keeps connecting in the background and shows
/// up on a later list, instead of stalling the first one past the client's
/// patience.
#[tokio::test]
async fn bind_budget_serves_partial_then_adds_late_backend() {
    let limits = Limits {
        bind_budget_secs: 1,
        ..Limits::default()
    };
    let (base, state) = spawn_hub_with_limits(limits).await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    let fast = instances::create(&state.db, &user.id, None, Some(&mock_def()), "fast", "Fast")
        .await
        .unwrap();
    let slow = instances::create(&state.db, &user.id, None, Some(&mock_def()), "slow", "Slow")
        .await
        .unwrap();
    instances::set_config_value(&state.db, &slow.id, "MOCK_INIT_DELAY_MS", "3000")
        .await
        .unwrap();
    make_group(&state, &user.id, "g", &[fast.id, slow.id.clone()]).await;

    let client = connect_at(&base, "/mcp/g", group_token(&state, &base, "u1", "client")).await;

    // The first list respects the budget: fast is in, slow is still pending.
    let t0 = std::time::Instant::now();
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(3),
        "first list should return within the budget, took {:?}",
        t0.elapsed()
    );
    assert!(names.contains(&"fast__echo".to_string()), "got {names:?}");
    assert!(!names.contains(&"slow__echo".to_string()), "got {names:?}");

    // The slow backend finishes connecting in the background and appears.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let names: Vec<String> = client
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        if names.contains(&"slow__echo".to_string()) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "slow backend never arrived: {names:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    let _ = client.cancel().await;
}

/// The deep keep-warm heartbeat (`exercise_all`) sends a real `tools/list` to
/// every pooled backend: healthy ones pass, and one that fails three
/// consecutive heartbeats is dropped from the pool so the reconcile path can
/// respawn it.
#[tokio::test]
async fn heartbeat_drops_wedged_backend_after_three_strikes() {
    let limits = Limits {
        backend_list_timeout_secs: 1,
        ..Limits::default()
    };
    let (_base, state) = spawn_hub_with_limits(limits).await;
    let user = users::create(&state.db, "u1", "alice", "Alice", false)
        .await
        .unwrap();
    instances::create(
        &state.db,
        &user.id,
        None,
        Some(&mock_def()),
        "healthy",
        "Healthy",
    )
    .await
    .unwrap();
    let wedged = instances::create(
        &state.db,
        &user.id,
        None,
        Some(&mock_def()),
        "wedged",
        "Wedged",
    )
    .await
    .unwrap();
    // Initializes fine, but never answers tools/list inside the 1s cap.
    instances::set_config_value(&state.db, &wedged.id, "MOCK_LIST_DELAY_MS", "30000")
        .await
        .unwrap();

    // Bind the pool without any client (the warmer's cheap touch).
    mcp_hub::proxy::pool::warm_all(&state).await;
    assert_eq!(state.backend_pool.counts(), (1, 2), "both backends bound");

    // Two failed heartbeats are forgiven — the wedged backend stays pooled.
    for strike in 1..=2 {
        let (ok, failed) = mcp_hub::proxy::pool::exercise_all(&state).await;
        assert_eq!((ok, failed), (1, 1), "strike {strike}");
        assert_eq!(state.backend_pool.counts(), (1, 2), "strike {strike}");
    }

    // The third strike drops it; the healthy backend is untouched.
    let (ok, failed) = mcp_hub::proxy::pool::exercise_all(&state).await;
    assert_eq!((ok, failed), (1, 1));
    assert_eq!(
        state.backend_pool.counts(),
        (1, 1),
        "wedged backend dropped"
    );
}

/// The base `/mcp` endpoint serves only `hub__*` tools: no backend tools, no
/// prompts/resources, and backend calls are pointed at the group endpoints.
#[tokio::test]
async fn management_endpoint_serves_only_hub_tools() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    let (token, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let client = connect(&base, token).await;

    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        names.iter().all(|n| n.starts_with("hub__")),
        "got {names:?}"
    );
    assert!(names.contains(&"hub__list_groups".to_string()));

    assert!(client.list_all_prompts().await.unwrap().is_empty());
    assert!(client.list_all_resources().await.unwrap().is_empty());

    // A backend tool call on /mcp is refused with a pointer at the groups.
    let res = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("mock__echo");
            __p.arguments = args(serde_json::json!({"msg": "hi"}));
            __p
        })
        .await;
    assert!(
        format!("{:?}", res.unwrap_err()).contains("group"),
        "backend call on /mcp should point at group endpoints"
    );

    let _ = client.cancel().await;
}

/// Group endpoints serve no `hub__*` tools and refuse them outright.
#[tokio::test]
async fn group_endpoint_rejects_hub_tools() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    let client = connect_at(
        &base,
        "/mcp/g",
        group_token(&state, &base, &user_id, "client"),
    )
    .await;

    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with("hub__")),
        "got {names:?}"
    );

    let res = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__whoami");
            __p.arguments = None;
            __p
        })
        .await;
    assert!(
        format!("{:?}", res.unwrap_err()).contains("/mcp"),
        "hub__ call on a group should point at the base endpoint"
    );

    let _ = client.cancel().await;
}

/// A group scopes its endpoint to member backends only; a non-member backend
/// of the same user is invisible and uncallable there.
#[tokio::test]
async fn group_endpoint_scopes_to_members() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    // A second backend NOT in group "g".
    let other = instances::create(
        &state.db,
        &user_id,
        None,
        Some(&mock_def()),
        "other",
        "Other",
    )
    .await
    .unwrap();
    make_group(&state, &user_id, "g2", &[other.id]).await;

    let client = connect_at(
        &base,
        "/mcp/g",
        group_token(&state, &base, &user_id, "client"),
    )
    .await;
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");
    assert!(
        !names.iter().any(|n| n.starts_with("other__")),
        "got {names:?}"
    );

    let blocked = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("other__echo");
            __p.arguments = args(serde_json::json!({"msg": "hi"}));
            __p
        })
        .await;
    assert!(
        blocked.is_err(),
        "non-member backend must be uncallable via this group"
    );

    let _ = client.cancel().await;
}

/// A token minted for one group's endpoint is rejected on siblings and on the
/// base endpoint (audience isolation), and a slug the user doesn't own 404s.
#[tokio::test]
async fn group_tokens_are_audience_isolated() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    let g = group_token(&state, &base, &user_id, "client");

    assert!(try_connect_at(&base, "/mcp/g", g.clone()).await.is_ok());
    assert!(
        try_connect_at(&base, "/mcp", g.clone()).await.is_err(),
        "group token on /mcp"
    );
    // "other" doesn't even exist — but the audience check already rejects it.
    assert!(try_connect_at(&base, "/mcp/other", g).await.is_err());

    let (m, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    assert!(
        try_connect_at(&base, "/mcp/g", m.clone()).await.is_err(),
        "/mcp token on a group"
    );

    // Right audience, but the slug doesn't exist for this user → 404 at bind.
    let (ghost, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp/ghost"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    assert!(try_connect_at(&base, "/mcp/ghost", ghost).await.is_err());
}

/// Full group lifecycle over the management endpoint: create with members,
/// list (connector URL + counts), connect to the new endpoint, shrink it,
/// delete it — after which its endpoint is gone.
#[tokio::test]
async fn group_crud_round_trip_over_mcp() {
    let (base, state, user_id, _inst_id) = hub_with_mock_backend().await;
    let (token, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let client = connect(&base, token).await;

    let created = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__create_group");
            __p.arguments =
                args(serde_json::json!({"slug": "work", "name": "Work", "servers": ["mock"]}));
            __p
        })
        .await
        .unwrap();
    let created = created.structured_content.unwrap();
    assert_eq!(created["created"], true);
    assert_eq!(created["connector_url"], format!("{base}/mcp/work"));

    // A bad slug and an unknown server namespace are rejected.
    let bad = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__create_group");
            __p.arguments = args(serde_json::json!({"slug": "Bad Slug"}));
            __p
        })
        .await;
    assert!(bad.is_err() || bad.unwrap().is_error == Some(true));
    let bad = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__create_group");
            __p.arguments = args(serde_json::json!({"slug": "x1", "servers": ["nope"]}));
            __p
        })
        .await;
    assert!(bad.is_err() || bad.unwrap().is_error == Some(true));

    let listed = client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_groups");
            __p.arguments = None;
            __p
        })
        .await
        .unwrap();
    let json = serde_json::to_string(&listed.structured_content).unwrap();
    assert!(json.contains("\"slug\":\"work\""), "got {json}");
    assert!(json.contains("mock"), "got {json}");

    // The new endpoint works with a matching-audience token.
    let (wt, _) = state
        .signer
        .issue_access_token(
            &user_id,
            "client",
            &format!("{base}/mcp/work"),
            "mcp",
            false,
            3600,
        )
        .unwrap();
    let wclient = connect_at(&base, "/mcp/work", wt.clone()).await;
    let names: Vec<String> = wclient
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"mock__echo".to_string()), "got {names:?}");

    // Emptying the member set removes the backend from the live endpoint.
    client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__update_group");
            __p.arguments = args(serde_json::json!({"slug": "work", "servers": []}));
            __p
        })
        .await
        .unwrap();
    let names: Vec<String> = wclient
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(
        !names.contains(&"mock__echo".to_string()),
        "still listed: {names:?}"
    );

    // Delete: the endpoint 404s for new work afterwards.
    client
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__delete_group");
            __p.arguments = args(serde_json::json!({"slug": "work"}));
            __p
        })
        .await
        .unwrap();
    let _ = wclient.cancel().await;
    assert!(
        try_connect_at(&base, "/mcp/work", wt).await.is_err(),
        "deleted group's endpoint must be gone"
    );

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
        .issue_access_token(
            &user.id,
            "client",
            &format!("{base}/mcp"),
            "mcp",
            false,
            3600,
        )
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
        .call_tool({
            let mut __p = CallToolRequestParams::new("hub__list_users");
            __p.arguments = None;
            __p
        })
        .await;
    let refused = match res {
        Err(_) => true,
        Ok(r) => r.is_error == Some(true),
    };
    assert!(refused, "non-admin must be refused hub__list_users");

    let _ = client.cancel().await;
}
