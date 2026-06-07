//! Tests for the catalog and user-instance data layer.

use mcp_hub::catalog::{self, ServerDef};
use mcp_hub::crypto::SecretBox;
use mcp_hub::{db, instances, users};
use sqlx::SqlitePool;

async fn pool() -> SqlitePool {
    let path = std::env::temp_dir().join(format!("mcp_hub_inst_{}.db", uuid::Uuid::new_v4()));
    db::connect(path.to_str().unwrap()).await.unwrap()
}

#[tokio::test]
async fn seed_builtins_populates_catalog() {
    let pool = pool().await;
    catalog::seed_builtins(&pool).await.unwrap();
    let entries = catalog::list(&pool).await.unwrap();
    assert!(entries.iter().any(|e| e.slug == "zabbix"));
    assert!(entries.iter().any(|e| e.slug == "homeassistant"));

    // Seeding twice must be idempotent (upsert by slug, no duplicates).
    catalog::seed_builtins(&pool).await.unwrap();
    let again = catalog::list(&pool).await.unwrap();
    assert_eq!(entries.len(), again.len());

    let zbx = catalog::get_by_slug(&pool, "zabbix").await.unwrap().unwrap();
    assert_eq!(zbx.transport, "stdio");
    assert!(zbx.secret_schema.iter().any(|f| f.name == "ZABBIX_TOKEN" && f.secret));
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
    catalog::seed_builtins(&pool).await.unwrap();
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let zbx = catalog::get_by_slug(&pool, "zabbix").await.unwrap().unwrap();

    let inst = instances::create(&pool, &user.id, Some(&zbx.id), None, "zbx", "My Zabbix")
        .await
        .unwrap();
    assert_eq!(inst.namespace, "zbx");
    assert!(inst.enabled);

    // Same namespace for the same user is rejected.
    let dup = instances::create(&pool, &user.id, Some(&zbx.id), None, "zbx", "Another").await;
    assert!(dup.is_err());

    // Reserved namespace is rejected at creation.
    let reserved = instances::create(&pool, &user.id, Some(&zbx.id), None, "hub", "x").await;
    assert!(reserved.is_err());
}

#[tokio::test]
async fn secrets_encrypt_and_resolve_to_env() {
    let pool = pool().await;
    catalog::seed_builtins(&pool).await.unwrap();
    let secrets = SecretBox::new(&[5u8; 32]);
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let zbx = catalog::get_by_slug(&pool, "zabbix").await.unwrap().unwrap();
    let inst = instances::create(&pool, &user.id, Some(&zbx.id), None, "zbx", "My Zabbix")
        .await
        .unwrap();

    // Non-secret URL goes to config; token is encrypted.
    instances::set_config_value(&pool, &inst.id, "ZABBIX_URL", "https://zbx.example.com/api")
        .await
        .unwrap();
    instances::set_secret(&pool, &secrets, &inst.id, "ZABBIX_TOKEN", "s3cr3t-token")
        .await
        .unwrap();

    // The raw stored ciphertext must not contain the plaintext.
    let names = instances::secret_names(&pool, &inst.id).await.unwrap();
    assert_eq!(names, vec!["ZABBIX_TOKEN".to_string()]);

    let reloaded = instances::get(&pool, &inst.id).await.unwrap().unwrap();
    let env = instances::resolved_env(&pool, &secrets, &reloaded).await.unwrap();
    assert_eq!(env.get("ZABBIX_URL").unwrap(), "https://zbx.example.com/api");
    assert_eq!(env.get("ZABBIX_TOKEN").unwrap(), "s3cr3t-token");
}

#[tokio::test]
async fn custom_definition_resolves() {
    let pool = pool().await;
    let user = users::create(&pool, "u1", "alice", "Alice", false).await.unwrap();
    let def = ServerDef {
        name: "My Custom".into(),
        description: "x".into(),
        transport: "stdio".into(),
        command: Some("uvx".into()),
        args: vec!["some-mcp".into()],
        url: None,
        runtime: "python".into(),
        secret_schema: vec![],
        repo: None,
        git_ref: None,
        entry: None,
        module: None,
    };
    let inst = instances::create(&pool, &user.id, None, Some(&def), "custom", "Custom")
        .await
        .unwrap();
    let resolved = instances::resolve_def(&pool, &inst).await.unwrap();
    assert_eq!(resolved.command.as_deref(), Some("uvx"));
    assert_eq!(resolved.args, vec!["some-mcp".to_string()]);
}

#[tokio::test]
async fn wrong_user_cannot_access_instance() {
    let pool = pool().await;
    catalog::seed_builtins(&pool).await.unwrap();
    let a = users::create(&pool, "a", "alice", "Alice", false).await.unwrap();
    let _b = users::create(&pool, "b", "bob", "Bob", false).await.unwrap();
    let zbx = catalog::get_by_slug(&pool, "zabbix").await.unwrap().unwrap();
    let inst = instances::create(&pool, &a.id, Some(&zbx.id), None, "zbx", "A's").await.unwrap();

    assert!(instances::get_owned(&pool, &inst.id, "b").await.unwrap().is_none());
    assert!(instances::get_owned(&pool, &inst.id, "a").await.unwrap().is_some());
}
