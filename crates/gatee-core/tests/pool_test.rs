use gatee_config::{Config, PoolCfg, PoolStrategy, UpstreamCfg, UpstreamKind};
use gatee_core::{fnv32a, CoreError, GatewayState, PoolRuntime, UpstreamRuntime};
use gatee_storage::Storage;
use std::collections::HashMap;
use std::sync::Arc;

fn make_upstream(name: &str, kind: UpstreamKind, url: &str) -> Arc<UpstreamRuntime> {
    Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: name.to_string(),
        kind,
        url: url.to_string(),
    }))
}

#[test]
fn test_fnv32a_known_vectors() {
    // Official 32-bit FNV-1a test vectors
    assert_eq!(fnv32a(b""), 0x811c9dc5);
    assert_eq!(fnv32a(b"a"), 0xe40c292c);
    assert_eq!(fnv32a(b"foobar"), 0xbf9cf968);
}

#[test]
fn test_round_robin_selection() {
    let u1 = make_upstream("u1", UpstreamKind::Direct, "");
    let u2 = make_upstream("u2", UpstreamKind::Direct, "");
    let u3 = make_upstream("u3", UpstreamKind::Direct, "");

    let pool = PoolRuntime::new(
        "rr_pool".to_string(),
        PoolCfg {
            members: vec!["u1".to_string(), "u2".to_string(), "u3".to_string()],
            strategy: PoolStrategy::RoundRobin,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
        vec![u1.clone(), u2.clone(), u3.clone()],
    );

    // Call 1 -> start with u1
    let cands1 = pool.candidates("");
    assert_eq!(cands1.len(), 3);
    assert_eq!(cands1[0].name(), "u1");
    assert_eq!(cands1[1].name(), "u2");
    assert_eq!(cands1[2].name(), "u3");

    // Call 2 -> start with u2
    let cands2 = pool.candidates("");
    assert_eq!(cands2[0].name(), "u2");
    assert_eq!(cands2[1].name(), "u3");
    assert_eq!(cands2[2].name(), "u1");

    // Call 3 -> start with u3
    let cands3 = pool.candidates("");
    assert_eq!(cands3[0].name(), "u3");
    assert_eq!(cands3[1].name(), "u1");
    assert_eq!(cands3[2].name(), "u2");

    // Call 4 -> wraps around to u1
    let cands4 = pool.candidates("");
    assert_eq!(cands4[0].name(), "u1");
}

#[test]
fn test_sticky_hashing_consistency() {
    let u1 = make_upstream("u1", UpstreamKind::Direct, "");
    let u2 = make_upstream("u2", UpstreamKind::Direct, "");
    let u3 = make_upstream("u3", UpstreamKind::Direct, "");

    let pool = PoolRuntime::new(
        "sticky_pool".to_string(),
        PoolCfg {
            members: vec!["u1".to_string(), "u2".to_string(), "u3".to_string()],
            strategy: PoolStrategy::Sticky,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
        vec![u1.clone(), u2.clone(), u3.clone()],
    );

    let key = "user-session-12345";
    let first = pool.candidates(key);

    // Multiple calls with identical key must return identical ordering
    for _ in 0..10 {
        let next = pool.candidates(key);
        assert_eq!(first[0].name(), next[0].name());
        assert_eq!(first[1].name(), next[1].name());
        assert_eq!(first[2].name(), next[2].name());
    }

    // Different key hash distribution
    let expected_idx = (fnv32a(key.as_bytes()) as usize) % 3;
    assert_eq!(first[0].name(), pool.members[expected_idx].name());
}

#[test]
fn test_failover_and_cooldown_filtering() {
    let u1 = make_upstream("u1", UpstreamKind::Direct, "");
    let u2 = make_upstream("u2", UpstreamKind::Direct, "");
    let u3 = make_upstream("u3", UpstreamKind::Direct, "");

    let pool = PoolRuntime::new(
        "failover_pool".to_string(),
        PoolCfg {
            members: vec!["u1".to_string(), "u2".to_string(), "u3".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec![],
            cooldown_secs: 10,
        },
        vec![u1.clone(), u2.clone(), u3.clone()],
    );

    // Initially all healthy -> u1 is first
    let cands = pool.candidates("");
    assert_eq!(cands[0].name(), "u1");
    assert_eq!(cands[1].name(), "u2");
    assert_eq!(cands[2].name(), "u3");

    // Mark u1 down
    pool.mark_down(&u1);
    assert!(u1.is_down(chrono::Utc::now().timestamp()));
    assert!(u1.remaining_cooldown_secs(chrono::Utc::now().timestamp()) > 0);

    // Next selection should move u1 to the end (cooling fallback)
    let cands_failover = pool.candidates("");
    assert_eq!(cands_failover.len(), 3);
    assert_eq!(cands_failover[0].name(), "u2");
    assert_eq!(cands_failover[1].name(), "u3");
    assert_eq!(cands_failover[2].name(), "u1"); // cooling candidate at the end

    // Mark u2 down as well
    pool.mark_down(&u2);
    let cands_failover2 = pool.candidates("");
    assert_eq!(cands_failover2[0].name(), "u3");
    assert_eq!(cands_failover2[1].name(), "u1");
    assert_eq!(cands_failover2[2].name(), "u2");

    // Reset u1 cooldown
    u1.reset_cooldown();
    assert!(!u1.is_down(chrono::Utc::now().timestamp()));
    let cands_recovered = pool.candidates("");
    assert_eq!(cands_recovered[0].name(), "u1");
    assert_eq!(cands_recovered[1].name(), "u3");
    assert_eq!(cands_recovered[2].name(), "u2"); // u2 still cooling
}

#[test]
fn test_mitm_host_matching() {
    let pool = PoolRuntime::new(
        "test_pool".to_string(),
        PoolCfg {
            members: vec![],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec![
                "api.openai.com".to_string(),
                "Claude.AI".to_string(),
                "example.com.".to_string(),
            ],
            cooldown_secs: 30,
        },
        vec![],
    );

    // Exact matches
    assert!(pool.mitms("api.openai.com"));
    assert!(pool.mitms("claude.ai"));

    // Case insensitivity
    assert!(pool.mitms("API.OPENAI.COM"));
    assert!(pool.mitms("Claude.Ai"));

    // With port
    assert!(pool.mitms("api.openai.com:443"));
    assert!(pool.mitms("claude.ai:8443"));

    // Trailing dot
    assert!(pool.mitms("api.openai.com."));

    // Non-matching
    assert!(!pool.mitms("other.com"));
    assert!(!pool.mitms("openai.com"));
}

#[tokio::test]
async fn test_gateway_state_auth_and_pool_resolution() {
    let u1 = UpstreamCfg {
        name: "u1".to_string(),
        kind: UpstreamKind::Direct,
        url: "".to_string(),
    };
    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["u1".to_string()],
            strategy: PoolStrategy::RoundRobin,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
    );
    pools.insert(
        "premium".to_string(),
        PoolCfg {
            members: vec!["u1".to_string()],
            strategy: PoolStrategy::Sticky,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
    );

    let config = Config {
        listen: "127.0.0.1:7890".to_string(),
        password: "secret_password".to_string(),
        ca_cert: "ca.pem".to_string(),
        ca_key: "ca-key.pem".to_string(),
        upstreams: vec![u1],
        pools,
    };

    let storage = Storage::new_in_memory().await.unwrap();
    let state = GatewayState::new(config, storage);

    // Auth failure with wrong password
    let err = state.authenticate("default", "wrong_pass").unwrap_err();
    assert_eq!(err, CoreError::AuthFailed);

    // Auth failure with empty password
    let err = state.authenticate("default", "").unwrap_err();
    assert_eq!(err, CoreError::AuthFailed);

    // Auth failure with different length password
    let err = state.authenticate("default", "secret_pass").unwrap_err();
    assert_eq!(err, CoreError::AuthFailed);

    // Success with default pool
    let (pool, key) = state.authenticate("default", "secret_password").unwrap();
    assert_eq!(pool.name, "default");
    assert_eq!(key, "default");

    // Success with empty username -> default pool
    let (pool, key) = state.authenticate("", "secret_password").unwrap();
    assert_eq!(pool.name, "default");
    assert_eq!(key, "default");

    // Success with pool~sticky_key
    let (pool, key) = state
        .authenticate("premium~session_abc", "secret_password")
        .unwrap();
    assert_eq!(pool.name, "premium");
    assert_eq!(key, "session_abc");

    // Success with ~sticky_key (empty pool -> default pool)
    let (pool, key) = state
        .authenticate("~session_xyz", "secret_password")
        .unwrap();
    assert_eq!(pool.name, "default");
    assert_eq!(key, "session_xyz");

    // Success with pool~ (empty key -> pool name as key)
    let (pool, key) = state.authenticate("premium~", "secret_password").unwrap();
    assert_eq!(pool.name, "premium");
    assert_eq!(key, "premium");

    // Unknown pool
    let err = state
        .authenticate("unknown_pool", "secret_password")
        .unwrap_err();
    assert_eq!(err, CoreError::PoolNotFound("unknown_pool".to_string()));

    // Request counter increments
    assert_eq!(
        state
            .total_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    state.inc_requests();
    state.inc_requests();
    assert_eq!(
        state
            .total_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[tokio::test]
async fn test_gateway_state_no_password_required() {
    let u1 = UpstreamCfg {
        name: "u1".to_string(),
        kind: UpstreamKind::Direct,
        url: "".to_string(),
    };
    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["u1".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
    );

    let config = Config {
        listen: "127.0.0.1:7890".to_string(),
        password: "".to_string(), // No password configured
        ca_cert: "ca.pem".to_string(),
        ca_key: "ca-key.pem".to_string(),
        upstreams: vec![u1],
        pools,
    };

    let storage = Storage::new_in_memory().await.unwrap();
    let state = GatewayState::new(config, storage);

    // Any password or empty password should be accepted
    assert!(state.authenticate("default", "").is_ok());
    assert!(state.authenticate("default", "anything").is_ok());
}
