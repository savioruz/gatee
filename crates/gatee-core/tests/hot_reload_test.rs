use gatee_core::{CoreError, GatewayState};
use gatee_storage::{PoolRecord, Storage};

#[tokio::test]
async fn test_hot_reload_adds_new_pool() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    // Initially seeded: upstream "direct", pool "default"
    let state = GatewayState::new_with_storage(storage.clone())
        .await
        .expect("init gateway state");

    assert!(state.get_pool("default").is_some());
    assert!(state.get_pool("new-pool").is_none());

    // Add new pool into SQLite
    let pool_rec = PoolRecord {
        name: "new-pool".to_string(),
        strategy: "failover".to_string(),
        cooldown_secs: 45,
        mitm_hosts: vec!["api.anthropic.com".to_string()],
        members: vec!["direct".to_string()],
        created_at: String::new(),
        modified_at: String::new(),
        created_by: "test".to_string(),
        modified_by: "test".to_string(),
    };
    storage
        .upsert_pool(&pool_rec, "test")
        .await
        .expect("upsert pool");

    // Before reload, new-pool is still not in memory
    assert!(state.get_pool("new-pool").is_none());

    // Trigger atomic reload
    state
        .reload_from_storage()
        .await
        .expect("reload from storage");

    // Now new-pool is immediately accessible!
    let pool = state.get_pool("new-pool").expect("new-pool now exists");
    assert_eq!(pool.name, "new-pool");
    assert_eq!(pool.cooldown_secs, 45);
    assert!(pool.mitm_hosts.contains("api.anthropic.com"));
    assert_eq!(pool.members.len(), 1);

    // Can authenticate against new pool
    let (auth_pool, _) = state.authenticate("new-pool", "").expect("auth new pool");
    assert_eq!(auth_pool.name, "new-pool");
}

#[tokio::test]
async fn test_hot_reload_preserves_cooldown_timestamp() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    let state = GatewayState::new_with_storage(storage.clone())
        .await
        .expect("init gateway state");

    // Put "direct" upstream into 120-second cooldown
    let direct_upstream = state
        .get_upstream("direct")
        .expect("direct upstream exists");
    direct_upstream.mark_down(120);
    assert!(
        direct_upstream.is_down_now(),
        "direct upstream should be in cooldown"
    );

    // Add a second upstream and pool in SQLite
    storage
        .upsert_upstream("socks-proxy", "socks5", "socks5://127.0.0.1:1080", "test")
        .await
        .expect("add socks-proxy");

    let pool_rec = PoolRecord {
        name: "multi-pool".to_string(),
        strategy: "round_robin".to_string(),
        cooldown_secs: 30,
        mitm_hosts: vec![],
        members: vec!["direct".to_string(), "socks-proxy".to_string()],
        created_at: String::new(),
        modified_at: String::new(),
        created_by: "test".to_string(),
        modified_by: "test".to_string(),
    };
    storage
        .upsert_pool(&pool_rec, "test")
        .await
        .expect("upsert pool");

    // Reload from storage
    state
        .reload_from_storage()
        .await
        .expect("reload from storage");

    // Verify "direct" upstream retained its active cooldown!
    let direct_reloaded = state
        .get_upstream("direct")
        .expect("direct upstream exists after reload");
    assert!(
        direct_reloaded.is_down_now(),
        "direct upstream MUST preserve active cooldown across hot reloads"
    );

    // Socks proxy should be healthy (not down)
    let socks_reloaded = state
        .get_upstream("socks-proxy")
        .expect("socks proxy exists");
    assert!(!socks_reloaded.is_down_now());
}

#[tokio::test]
async fn test_hot_reload_updates_password() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");

    let state = GatewayState::new_with_storage(storage.clone())
        .await
        .expect("init gateway state");

    // Initially no password
    assert!(state.authenticate("default", "").is_ok());

    // Set password in SQLite
    storage
        .set_setting("password", "supersecret", "admin")
        .await
        .expect("set password");

    // Reload
    state.reload_from_storage().await.expect("reload");

    // Empty or wrong password now fails
    assert_eq!(
        state.authenticate("default", "").unwrap_err(),
        CoreError::AuthFailed
    );
    assert_eq!(
        state.authenticate("default", "wrong").unwrap_err(),
        CoreError::AuthFailed
    );

    // Correct password succeeds
    assert!(state.authenticate("default", "supersecret").is_ok());
}
