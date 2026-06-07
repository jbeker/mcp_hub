//! Tests for the user-instance data layer (servers are fully user-defined).

use std::collections::BTreeMap;

use mcp_hub::crypto::SecretBox;
use mcp_hub::instances::{self, ServerDef};
use mcp_hub::{db, users};
use sqlx::SqlitePool;

async fn pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!("mcp_hub_inst_{}.db", uuid::Uuid::new_v4()));
    db::connect(path.to_str().unwrap()).await.unwrap()
}

fn stdio_def(command: &str, args: &[&str]) -> ServerDef {
    ServerDef {
        name: "Test".into(),
        description: String::new(),
        transport: "stdio".into(),
        command: Some(command.into()),
        args: args.iter().map(|s| s.to_string()).collect(),
        url: None,
        runtime: String::new(),
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    }
}

#[tokio::test]
async fn namespace_validation() {
    assert!(instances::validate_namespace("zabbix").is_ok());
    assert!(instances::validate_namespace("home_assistant2").is_ok());
    assert!(instances::validate_namespace("hub").is_err()); // reserved
    assert!(instances::validate_namespace("Bad Name").is_err());
    assert!(instances::validate_namespace("").is_err());
}

#[tokio::test]
async fn create_instance_and_reject_duplicate_namespace() {
    let pool = pool().await;
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let def = stdio_def("uvx", &["some-mcp"]);

    let inst = instances::create(&pool, &user.id, None, Some(&def), "zbx", "My Zabbix")
        .await
        .unwrap();
    assert_eq!(inst.namespace, "zbx");
    assert!(inst.enabled);

    let dup = instances::create(&pool, &user.id, None, Some(&def), "zbx", "Another").await;
    assert!(dup.is_err());

    let reserved = instances::create(&pool, &user.id, None, Some(&def), "hub", "x").await;
    assert!(reserved.is_err());
}

#[tokio::test]
async fn env_is_encrypted_and_round_trips() {
    let pool = pool().await;
    let secrets = SecretBox::new(&[5u8; 32]);
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let inst = instances::create(&pool, &user.id, None, Some(&stdio_def("uvx", &["m"])), "s", "S")
        .await
        .unwrap();

    let mut env = BTreeMap::new();
    env.insert("ZABBIX_URL".to_string(), "https://zbx.example.com/api".to_string());
    env.insert("ZABBIX_TOKEN".to_string(), "s3cr3t-token".to_string());
    instances::replace_env(&pool, &secrets, &inst.id, &env).await.unwrap();

    // Values come back for editing...
    let shown = instances::env_for_edit(&pool, &secrets, &inst.id).await.unwrap();
    assert_eq!(shown, env);

    // ...and resolve into the launch environment.
    let reloaded = instances::get(&pool, &inst.id).await.unwrap().unwrap();
    let resolved = instances::resolved_env(&pool, &secrets, &reloaded).await.unwrap();
    assert_eq!(resolved.get("ZABBIX_TOKEN").unwrap(), "s3cr3t-token");

    // The stored ciphertext must not contain the plaintext.
    let (ct,): (Vec<u8>,) =
        sqlx::query_as("SELECT ciphertext FROM instance_secrets WHERE key_name = 'ZABBIX_TOKEN'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!ct.windows(11).any(|w| w == b"s3cr3t-token"));

    // replace_env is a full replace: a smaller map removes the dropped keys.
    let mut smaller = BTreeMap::new();
    smaller.insert("ZABBIX_TOKEN".to_string(), "new".to_string());
    instances::replace_env(&pool, &secrets, &inst.id, &smaller).await.unwrap();
    let after = instances::env_for_edit(&pool, &secrets, &inst.id).await.unwrap();
    assert_eq!(after, smaller);
}

#[tokio::test]
async fn command_line_round_trips() {
    let (cmd, args) = instances::parse_command("uvx zabbix-mcp-server --url \"a b\"").unwrap();
    assert_eq!(cmd.as_deref(), Some("uvx"));
    assert_eq!(args, vec!["zabbix-mcp-server", "--url", "a b"]);
    let rendered = instances::render_command(&cmd, &args);
    let (cmd2, args2) = instances::parse_command(&rendered).unwrap();
    assert_eq!(cmd2, cmd);
    assert_eq!(args2, args);

    assert!(instances::parse_command("").unwrap().0.is_none());
}

#[tokio::test]
async fn env_parsing_rules() {
    let parsed = instances::parse_env("# comment\nA=1\n\nB = two \nC=ya=ya").unwrap();
    assert_eq!(parsed.get("A").unwrap(), "1");
    assert_eq!(parsed.get("B").unwrap(), "two");
    assert_eq!(parsed.get("C").unwrap(), "ya=ya"); // only the first '=' splits
    assert!(instances::parse_env("1BAD=x").is_err()); // name can't start with a digit
    assert!(instances::parse_env("no equals").is_err());
}

#[tokio::test]
async fn custom_definition_resolves_and_updates() {
    let pool = pool().await;
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let inst = instances::create(&pool, &user.id, None, Some(&stdio_def("uvx", &["some-mcp"])), "c", "C")
        .await
        .unwrap();
    let resolved = instances::resolve_def(&pool, &inst).await.unwrap();
    assert_eq!(resolved.command.as_deref(), Some("uvx"));

    // update_def rewrites the stored definition.
    instances::update_def(&pool, &inst.id, &stdio_def("npx", &["-y", "other"]))
        .await
        .unwrap();
    let reloaded = instances::get(&pool, &inst.id).await.unwrap().unwrap();
    let def = instances::resolve_def(&pool, &reloaded).await.unwrap();
    assert_eq!(def.command.as_deref(), Some("npx"));
    assert_eq!(def.args, vec!["-y", "other"]);
}

#[tokio::test]
async fn wrong_user_cannot_access_instance() {
    let pool = pool().await;
    let a = users::create(&pool, "a", "alice", "Alice", false).await.unwrap();
    let _b = users::create(&pool, "b", "bob", "Bob", false).await.unwrap();
    let inst = instances::create(&pool, &a.id, None, Some(&stdio_def("uvx", &["m"])), "zbx", "A's")
        .await
        .unwrap();
    assert!(instances::get_owned(&pool, &inst.id, "b").await.unwrap().is_none());
    assert!(instances::get_owned(&pool, &inst.id, "a").await.unwrap().is_some());
}

#[tokio::test]
async fn migrates_a_legacy_catalog_instance() {
    let pool = pool().await;
    let secrets = SecretBox::new(&[7u8; 32]);
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();

    // A legacy catalog row + an instance that references it (the dormant table).
    sqlx::query(
        "INSERT INTO catalog_servers (id, slug, name, description, transport, command, args_json, url, runtime, secret_schema_json, is_builtin, supported, created_at) \
         VALUES ('cat1', 'zabbix', 'Zabbix', '', 'stdio', 'uvx', '[\"zabbix-mcp-server\"]', NULL, 'python', '[]', 1, 1, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_server_instances (id, user_id, catalog_server_id, namespace, display_name, enabled, config_json, created_at) \
         VALUES ('inst1', ?, 'cat1', 'zbx', 'My Zabbix', 1, '{\"ZABBIX_URL\":\"https://zbx/api\"}', 0)",
    )
    .bind(&user.id)
    .execute(&pool)
    .await
    .unwrap();

    instances::migrate_catalog_instances(&pool, &secrets).await.unwrap();

    let inst = instances::get(&pool, "inst1").await.unwrap().unwrap();
    let def = instances::resolve_def(&pool, &inst).await.unwrap();
    assert_eq!(def.command.as_deref(), Some("uvx"));
    assert_eq!(def.args, vec!["zabbix-mcp-server"]);
    // The non-secret config became an encrypted env var.
    let env = instances::env_for_edit(&pool, &secrets, "inst1").await.unwrap();
    assert_eq!(env.get("ZABBIX_URL").unwrap(), "https://zbx/api");

    // Idempotent: a second run is a no-op.
    instances::migrate_catalog_instances(&pool, &secrets).await.unwrap();
    let again = instances::env_for_edit(&pool, &secrets, "inst1").await.unwrap();
    assert_eq!(again.len(), 1);
}
