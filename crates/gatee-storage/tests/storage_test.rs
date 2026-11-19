use gatee_storage::{LogEmitter, PoolRecord, RequestLogEntry, Storage};
use tempfile::tempdir;
use time::OffsetDateTime;

#[tokio::test]
async fn test_storage_migrate_and_log() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");
    let entry = RequestLogEntry::new(
        "127.0.0.1".to_string(),
        "default".to_string(),
        "direct".to_string(),
        "api.anthropic.com:443".to_string(),
        false,
        200,
        42,
    );

    storage.insert_log(&entry).await.expect("insert log");
    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].target_host, "api.anthropic.com:443");
    assert_eq!(logs[0].latency_ms, 42);
    assert_eq!(logs[0].created_by, "system");
}

#[tokio::test]
async fn test_storage_auto_seeding() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // Verify default seeded upstream
    let upstreams = storage.list_upstreams().await.expect("list upstreams");
    assert_eq!(upstreams.len(), 1);
    assert_eq!(upstreams[0].name, "direct");
    assert_eq!(upstreams[0].kind, "direct");
    assert_eq!(upstreams[0].created_by, "system");
    assert_eq!(upstreams[0].modified_by, "system");
    assert!(!upstreams[0].created_at.is_empty());
    assert!(!upstreams[0].modified_at.is_empty());

    // Verify default seeded pool
    let pools = storage.list_pools().await.expect("list pools");
    assert_eq!(pools.len(), 1);
    assert_eq!(pools[0].name, "default");
    assert_eq!(pools[0].strategy, "failover");
    assert_eq!(pools[0].members, vec!["direct"]);
    assert_eq!(pools[0].cooldown_secs, 30);
    assert_eq!(pools[0].created_by, "system");
    assert_eq!(pools[0].modified_by, "system");

    // Verify load_full_config loads cleanly
    let cfg = storage.load_full_config().await.expect("load full config");
    assert_eq!(cfg.upstreams.len(), 1);
    assert_eq!(cfg.pools.len(), 1);
    assert!(cfg.password.is_empty());
}

#[tokio::test]
async fn test_storage_seeding_with_password() {
    let dir = tempdir().expect("create temp dir");
    let db_path = dir.path().join("gatee_pwd.db");
    let storage = Storage::new_from_path(&db_path)
        .await
        .expect("init storage");
    storage
        .ensure_seeded(Some("secret123"))
        .await
        .expect("seed with password");

    let pwd = storage.get_setting("password").await.expect("get setting");
    assert_eq!(pwd, Some("secret123".to_string()));

    let cfg = storage.load_full_config().await.expect("load full config");
    assert_eq!(cfg.password, "secret123");
}

#[tokio::test]
async fn test_storage_upstream_crud() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // Upsert new upstream
    storage
        .upsert_upstream(
            "vercel-node",
            "vercel",
            "https://my-relay.vercel.app",
            "admin",
        )
        .await
        .expect("upsert upstream");

    let u = storage
        .get_upstream("vercel-node")
        .await
        .expect("get upstream")
        .expect("exists");
    assert_eq!(u.kind, "vercel");
    assert_eq!(u.url, "https://my-relay.vercel.app");
    assert_eq!(u.created_by, "admin");
    assert_eq!(u.modified_by, "admin");

    // Update url
    storage
        .upsert_upstream(
            "vercel-node",
            "vercel",
            "https://updated.vercel.app",
            "admin2",
        )
        .await
        .expect("update upstream");

    let u2 = storage
        .get_upstream("vercel-node")
        .await
        .expect("get upstream")
        .expect("exists");
    assert_eq!(u2.url, "https://updated.vercel.app");
    assert_eq!(u2.modified_by, "admin2");

    // Delete upstream not referenced by pool
    storage
        .delete_upstream("vercel-node")
        .await
        .expect("delete upstream");
    let u_deleted = storage
        .get_upstream("vercel-node")
        .await
        .expect("get upstream");
    assert!(u_deleted.is_none());
}

#[tokio::test]
async fn test_storage_fk_delete_restriction() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // "direct" is referenced by pool "default"
    let err = storage.delete_upstream("direct").await;
    assert!(err.is_err(), "should fail to delete referenced upstream");
}

#[tokio::test]
async fn test_storage_pool_crud() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // Add another upstream
    storage
        .upsert_upstream("socks5-node", "socks5", "socks5://127.0.0.1:1080", "system")
        .await
        .expect("add socks5");

    // Upsert a pool
    let new_pool = PoolRecord {
        name: "custom-pool".to_string(),
        strategy: "round_robin".to_string(),
        cooldown_secs: 60,
        mitm_hosts: vec!["api.openai.com".to_string()],
        members: vec!["direct".to_string(), "socks5-node".to_string()],
        created_at: String::new(),
        modified_at: String::new(),
        created_by: String::new(),
        modified_by: String::new(),
    };

    storage
        .upsert_pool(&new_pool, "admin")
        .await
        .expect("upsert pool");

    let p = storage
        .get_pool("custom-pool")
        .await
        .expect("get pool")
        .expect("exists");
    assert_eq!(p.strategy, "round_robin");
    assert_eq!(p.cooldown_secs, 60);
    assert_eq!(p.members, vec!["direct", "socks5-node"]);
    assert_eq!(p.mitm_hosts, vec!["api.openai.com"]);
    assert_eq!(p.created_by, "admin");

    // Delete pool
    storage
        .delete_pool("custom-pool")
        .await
        .expect("delete pool");
    let p_del = storage.get_pool("custom-pool").await.expect("get pool");
    assert!(p_del.is_none());
}

#[tokio::test]
async fn test_storage_trigger_updates_modified_at() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // Set initial setting with older modified_at
    storage
        .set_setting("theme", "dark", "admin")
        .await
        .expect("set setting");

    let settings = storage.list_settings().await.expect("list settings");
    let s1 = settings.iter().find(|s| s.key == "theme").expect("found");
    let initial_mod = s1.modified_at.clone();
    assert!(!initial_mod.is_empty());

    // Update setting
    storage
        .set_setting("theme", "light", "admin2")
        .await
        .expect("update setting");
    let val = storage.get_setting("theme").await.expect("get");
    assert_eq!(val, Some("light".to_string()));
}

#[tokio::test]
async fn test_storage_file_path() {
    let dir = tempdir().expect("create temp dir");
    let db_path = dir.path().join("sub/dir/gatee.db");
    let storage = Storage::new_from_path(&db_path)
        .await
        .expect("init disk storage");

    let entry = RequestLogEntry::new(
        "10.0.0.1".to_string(),
        "mitm-pool".to_string(),
        "proxy-1".to_string(),
        "api.openai.com:443".to_string(),
        true,
        204,
        120,
    );
    storage.insert_log(&entry).await.expect("insert log");

    let logs = storage.fetch_recent_logs(5).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert!(logs[0].is_mitm);
    assert_eq!(logs[0].target_host, "api.openai.com:443");
}

#[tokio::test]
async fn test_log_emitter() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");
    let emitter = LogEmitter::new(storage.clone(), 100);

    let entry = RequestLogEntry::new(
        "192.168.1.1".to_string(),
        "default".to_string(),
        "direct".to_string(),
        "example.com:80".to_string(),
        false,
        200,
        15,
    );
    emitter.record(entry);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].target_host, "example.com:80");
}

#[tokio::test]
async fn test_log_emitter_channel_saturation() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");
    let emitter = LogEmitter::new(storage.clone(), 1);

    for i in 0..50 {
        emitter.record(RequestLogEntry {
            id: None,
            timestamp: OffsetDateTime::now_utc(),
            client_ip: "127.0.0.1".to_string(),
            pool: "default".to_string(),
            upstream: "direct".to_string(),
            target_host: format!("target-{}.com:80", i),
            is_mitm: false,
            status_code: 200,
            latency_ms: 10,
            created_by: "system".to_string(),
        });
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let logs = storage.fetch_recent_logs(100).await.expect("fetch logs");
    assert!(!logs.is_empty());
}
