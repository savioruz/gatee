use gatee_config::{Config, ConfigError, PoolStrategy, UpstreamKind};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_parse_valid_config() {
    let json = r#"{
        "listen": "0.0.0.0:7890",
        "password": "secretpassword",
        "ca_cert": "test-ca.pem",
        "ca_key": "test-ca-key.pem",
        "upstreams": [
            { "name": "direct-1", "kind": "direct", "url": "" },
            { "name": "relay-1", "kind": "vercel", "url": "https://relay.vercel.app" }
        ],
        "pools": {
            "default": {
                "members": ["direct-1", "relay-1"],
                "strategy": "round_robin",
                "mitm_hosts": ["api.openai.com"],
                "cooldown_secs": 45
            }
        }
    }"#;

    let cfg = Config::from_json_str(json).expect("should parse config");
    assert_eq!(cfg.listen, "0.0.0.0:7890");
    assert_eq!(cfg.password, "secretpassword");
    assert_eq!(cfg.ca_cert, "test-ca.pem");
    assert_eq!(cfg.ca_key, "test-ca-key.pem");
    assert_eq!(cfg.upstreams.len(), 2);
    assert_eq!(cfg.upstreams[0].kind, UpstreamKind::Direct);
    assert_eq!(cfg.upstreams[1].kind, UpstreamKind::Vercel);
    let pool = cfg.pools.get("default").expect("pool exists");
    assert_eq!(pool.strategy, PoolStrategy::RoundRobin);
    assert_eq!(pool.cooldown_secs, 45);
    assert_eq!(pool.members, vec!["direct-1", "relay-1"]);
    assert_eq!(pool.mitm_hosts, vec!["api.openai.com"]);
}

#[test]
fn test_default_values() {
    let json = r#"{
        "upstreams": [
            { "name": "direct-1", "kind": "direct" }
        ],
        "pools": {
            "default": {
                "members": ["direct-1"]
            }
        }
    }"#;

    let cfg = Config::from_json_str(json).expect("should parse config with defaults");
    assert_eq!(cfg.listen, "127.0.0.1:7890");
    assert_eq!(cfg.password, "");
    assert_eq!(cfg.ca_cert, "ca.pem");
    assert_eq!(cfg.ca_key, "ca-key.pem");
    let pool = cfg.pools.get("default").expect("pool exists");
    assert_eq!(pool.strategy, PoolStrategy::Failover);
    assert_eq!(pool.cooldown_secs, 30);
    assert!(pool.mitm_hosts.is_empty());
}

#[test]
fn test_all_upstream_kinds_and_strategies() {
    let json = r#"{
        "upstreams": [
            { "name": "u-direct", "kind": "direct" },
            { "name": "u-vercel", "kind": "vercel", "url": "https://vercel.example.com" },
            { "name": "u-http", "kind": "http", "url": "http://10.0.0.1:8080" },
            { "name": "u-socks5", "kind": "socks5", "url": "socks5://127.0.0.1:1080" }
        ],
        "pools": {
            "p-rr": {
                "members": ["u-direct"],
                "strategy": "round_robin"
            },
            "p-failover": {
                "members": ["u-vercel"],
                "strategy": "failover"
            },
            "p-sticky": {
                "members": ["u-http", "u-socks5"],
                "strategy": "sticky"
            }
        }
    }"#;

    let cfg = Config::from_json_str(json).expect("should parse all kinds and strategies");
    assert_eq!(cfg.upstreams[0].kind, UpstreamKind::Direct);
    assert_eq!(cfg.upstreams[1].kind, UpstreamKind::Vercel);
    assert_eq!(cfg.upstreams[2].kind, UpstreamKind::Http);
    assert_eq!(cfg.upstreams[3].kind, UpstreamKind::Socks5);

    assert_eq!(
        cfg.pools.get("p-rr").unwrap().strategy,
        PoolStrategy::RoundRobin
    );
    assert_eq!(
        cfg.pools.get("p-failover").unwrap().strategy,
        PoolStrategy::Failover
    );
    assert_eq!(
        cfg.pools.get("p-sticky").unwrap().strategy,
        PoolStrategy::Sticky
    );
}

#[test]
fn test_validation_empty_upstreams() {
    let json = r#"{
        "upstreams": [],
        "pools": {
            "default": { "members": ["direct-1"] }
        }
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("No upstreams defined")),
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_validation_empty_upstream_name() {
    let json = r#"{
        "upstreams": [
            { "name": "  ", "kind": "direct" }
        ],
        "pools": {
            "default": { "members": ["direct-1"] }
        }
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("empty name")),
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_validation_empty_url_for_non_direct() {
    let json = r#"{
        "upstreams": [
            { "name": "relay-1", "kind": "vercel", "url": "  " }
        ],
        "pools": {
            "default": { "members": ["relay-1"] }
        }
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => {
            assert!(msg.contains("requires a valid url"));
        }
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_validation_empty_pools() {
    let json = r#"{
        "upstreams": [
            { "name": "direct-1", "kind": "direct" }
        ],
        "pools": {}
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("No pools defined")),
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_validation_pool_no_members() {
    let json = r#"{
        "upstreams": [
            { "name": "direct-1", "kind": "direct" }
        ],
        "pools": {
            "default": { "members": [] }
        }
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("has no members")),
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_validation_pool_unknown_member() {
    let json = r#"{
        "upstreams": [
            { "name": "direct-1", "kind": "direct" }
        ],
        "pools": {
            "default": { "members": ["non-existent"] }
        }
    }"#;

    let err = Config::from_json_str(json).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("references unknown member")),
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

#[test]
fn test_from_file_success() {
    let json = r#"{
        "upstreams": [
            { "name": "direct-1", "kind": "direct" }
        ],
        "pools": {
            "default": { "members": ["direct-1"] }
        }
    }"#;

    let mut tmp = NamedTempFile::new().expect("create tempfile");
    tmp.write_all(json.as_bytes()).expect("write tempfile");

    let cfg = Config::from_file(tmp.path()).expect("load from file");
    assert_eq!(cfg.upstreams.len(), 1);
    assert_eq!(cfg.upstreams[0].name, "direct-1");
}

#[test]
fn test_from_file_not_found() {
    let err = Config::from_file("non-existent-file-12345.json").unwrap_err();
    match err {
        ConfigError::Io(_) => {}
        other => panic!("expected Io error, got: {:?}", other),
    }
}

#[test]
fn test_json_syntax_error() {
    let bad_json = r#"{ "listen": "invalid json"#;
    let err = Config::from_json_str(bad_json).unwrap_err();
    match err {
        ConfigError::Json(_) => {}
        other => panic!("expected Json error, got: {:?}", other),
    }
}
