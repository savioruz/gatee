use chrono::Utc;
use gatee_storage::{LogEmitter, RequestLogEntry, Storage};
use tempfile::tempdir;

#[tokio::test]
async fn test_storage_migrate_and_log() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");
    let entry = RequestLogEntry {
        id: None,
        timestamp: Utc::now(),
        client_ip: "127.0.0.1".to_string(),
        pool: "default".to_string(),
        upstream: "direct-1".to_string(),
        target_host: "api.anthropic.com:443".to_string(),
        is_mitm: false,
        status_code: 200,
        latency_ms: 42,
    };

    storage.insert_log(&entry).await.expect("insert log");
    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].target_host, "api.anthropic.com:443");
    assert_eq!(logs[0].latency_ms, 42);
}

#[tokio::test]
async fn test_storage_file_path() {
    let dir = tempdir().expect("create temp dir");
    let db_path = dir.path().join("sub/dir/gatee.db");
    let storage = Storage::new_from_path(&db_path)
        .await
        .expect("init disk storage");

    let entry = RequestLogEntry {
        id: None,
        timestamp: Utc::now(),
        client_ip: "10.0.0.1".to_string(),
        pool: "mitm-pool".to_string(),
        upstream: "proxy-1".to_string(),
        target_host: "api.openai.com:443".to_string(),
        is_mitm: true,
        status_code: 204,
        latency_ms: 120,
    };
    storage.insert_log(&entry).await.expect("insert log");

    let logs = storage.fetch_recent_logs(5).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].is_mitm, true);
    assert_eq!(logs[0].target_host, "api.openai.com:443");
}

#[tokio::test]
async fn test_log_emitter() {
    let storage = Storage::new_in_memory()
        .await
        .expect("init in-memory storage");
    let emitter = LogEmitter::new(storage.clone(), 100);

    let entry = RequestLogEntry {
        id: None,
        timestamp: Utc::now(),
        client_ip: "192.168.1.1".to_string(),
        pool: "default".to_string(),
        upstream: "direct".to_string(),
        target_host: "example.com:80".to_string(),
        is_mitm: false,
        status_code: 200,
        latency_ms: 15,
    };
    emitter.record(entry);

    // Give the async task a moment to process the channel
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].target_host, "example.com:80");
}
