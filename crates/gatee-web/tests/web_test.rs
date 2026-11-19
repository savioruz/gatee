use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::Engine;
use gatee_ca::CertificateAuthority;
use gatee_config::{Config, PoolCfg, PoolStrategy, UpstreamCfg, UpstreamKind};
use gatee_core::GatewayState;
use gatee_storage::{RequestLogEntry, Storage};
use gatee_web::build_web_router;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use time::OffsetDateTime;
use tower::ServiceExt;

async fn setup_test_app(
    password: &str,
) -> (
    axum::Router,
    Arc<GatewayState>,
    Storage,
    Arc<CertificateAuthority>,
) {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));

    let storage = Storage::new_in_memory().await.expect("storage");
    storage
        .upsert_upstream("upstream-1", "direct", "", "test")
        .await
        .expect("insert upstream-1");
    storage
        .upsert_upstream("upstream-2", "http", "http://127.0.0.1:8080", "test")
        .await
        .expect("insert upstream-2");
    storage
        .upsert_pool(
            &gatee_storage::PoolRecord {
                name: "default".to_string(),
                strategy: "round_robin".to_string(),
                cooldown_secs: 30,
                mitm_hosts: vec!["api.openai.com".to_string()],
                members: vec!["upstream-1".to_string(), "upstream-2".to_string()],
                created_at: String::new(),
                modified_at: String::new(),
                created_by: "test".to_string(),
                modified_by: "test".to_string(),
            },
            "test",
        )
        .await
        .expect("upsert default pool");

    let upstreams = vec![
        UpstreamCfg {
            name: "upstream-1".to_string(),
            kind: UpstreamKind::Direct,
            url: "".to_string(),
        },
        UpstreamCfg {
            name: "upstream-2".to_string(),
            kind: UpstreamKind::Http,
            url: "http://127.0.0.1:8080".to_string(),
        },
    ];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["upstream-1".to_string(), "upstream-2".to_string()],
            strategy: PoolStrategy::RoundRobin,
            mitm_hosts: vec!["api.openai.com".to_string()],
            cooldown_secs: 30,
        },
    );

    let config = Config {
        listen: "127.0.0.1:7890".to_string(),
        password: password.to_string(),
        ca_cert: cert_path.to_string_lossy().to_string(),
        ca_key: key_path.to_string_lossy().to_string(),
        upstreams,
        pools,
    };

    let state = Arc::new(GatewayState::new(config, storage.clone()));
    let router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    (router, state, storage, ca)
}

async fn body_to_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn basic_auth_header(credentials: &str) -> String {
    format!(
        "Basic {}",
        base64::prelude::BASE64_STANDARD.encode(credentials.as_bytes())
    )
}

#[tokio::test]
async fn test_auth_with_password() {
    let (router, _state, _storage, _ca) = setup_test_app("supersecret").await;

    // 1. Missing Authorization header -> 401
    let resp = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Basic realm=\"gatee\""
    );

    // 2. Invalid password -> 401
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(
                    header::AUTHORIZATION,
                    basic_auth_header("admin:wrongpassword"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Invalid auth format (Bearer token) -> 401
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer some-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Malformed base64 -> 401
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Basic ???not-base64???")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Valid credentials with username -> 200
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(
                    header::AUTHORIZATION,
                    basic_auth_header("admin:supersecret"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Valid credentials without username -> 200
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, basic_auth_header(":supersecret"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Valid credentials raw password without colon -> 200
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, basic_auth_header("supersecret"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_bypassed_when_empty_password() {
    let (router, _state, _storage, _ca) = setup_test_app("").await;

    // No auth header needed
    let resp = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_dashboard_render() {
    let (router, state, storage, _ca) = setup_test_app("gatee_pw").await;

    // Set request count
    state.total_requests.store(1337, Ordering::Relaxed);

    // Insert request logs
    let now = OffsetDateTime::now_utc();
    storage
        .insert_log(&RequestLogEntry {
            id: None,
            timestamp: now,
            client_ip: "127.0.0.1".to_string(),
            pool: "default".to_string(),
            upstream: "upstream-1".to_string(),
            target_host: "api.openai.com:443".to_string(),
            is_mitm: true,
            status_code: 201,
            latency_ms: 45,
            created_by: "system".to_string(),
        })
        .await
        .expect("insert log 1");

    storage
        .insert_log(&RequestLogEntry {
            id: None,
            timestamp: now,
            client_ip: "127.0.0.1".to_string(),
            pool: "default".to_string(),
            upstream: "upstream-2".to_string(),
            target_host: "api.anthropic.com:443".to_string(),
            is_mitm: false,
            status_code: 502,
            latency_ms: 120,
            created_by: "system".to_string(),
        })
        .await
        .expect("insert log 2");

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, basic_auth_header("admin:gatee_pw"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );

    let html = body_to_string(resp.into_body()).await;

    // Verify key sections and details
    assert!(html.contains("Gatee Forward Gateway"));
    assert!(html.contains("Gateway Metrics"));
    assert!(html.contains("Total requests processed: <strong>1337</strong>"));
    assert!(html.contains("Upstream Pools"));
    assert!(html.contains("default"));
    assert!(html.contains("roundrobin") || html.contains("round_robin"));
    assert!(html.contains("upstream-1"));
    assert!(html.contains("upstream-2"));
    assert!(html.contains("Healthy"));
    assert!(html.contains("Recent Proxy Logs"));
    assert!(html.contains("api.openai.com:443"));
    assert!(html.contains("api.anthropic.com:443"));
    assert!(html.contains("45 ms"));
    assert!(html.contains("120 ms"));
    assert!(html.contains("<span class=\"badge badge-green\">201</span>"));
    assert!(html.contains("<span class=\"badge badge-red\">502</span>"));
    assert!(html.contains("<a href=\"/ca.pem\" class=\"btn\" download>"));
}

#[tokio::test]
async fn test_ca_cert_download() {
    let (router, _state, _storage, ca) = setup_test_app("").await;

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/ca.pem")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/x-pem-file"
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"ca.pem\""
    );

    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("-----BEGIN CERTIFICATE-----"));
    assert_eq!(body, ca.cert_pem());
}

#[tokio::test]
async fn test_cooldown_reset_endpoint() {
    let (router, state, _storage, _ca) = setup_test_app("").await;

    let upstream = state.get_upstream("upstream-1").expect("upstream-1 exists");

    // Put upstream-1 in cooldown for 120 seconds
    upstream.mark_down(120);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(upstream.is_down(now));
    assert!(upstream.remaining_cooldown_secs(now) > 0);

    // 1. Check dashboard shows Cooling badge
    let resp = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_to_string(resp.into_body()).await;
    assert!(html.contains("Cooling ("));

    // 2. Trigger cooldown reset
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cooldown/reset?upstream=upstream-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let row_html = body_to_string(resp.into_body()).await;

    // Check updated HTML row returned by HTMX endpoint
    assert!(row_html.contains("id=\"upstream-upstream-1\""));
    assert!(row_html.contains("<span class=\"badge badge-green\">Healthy</span>"));
    assert!(row_html.contains("hx-post=\"/api/cooldown/reset?upstream=upstream-1\""));
    assert!(row_html.contains("hx-target=\"#upstream-upstream-1\""));
    assert!(row_html.contains("hx-swap=\"outerHTML\""));

    // Upstream cooldown is cleared
    let now_after = OffsetDateTime::now_utc().unix_timestamp();
    assert!(!upstream.is_down(now_after));
    assert_eq!(upstream.remaining_cooldown_secs(now_after), 0);

    // 3. Reset non-existent upstream returns 404
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cooldown/reset?upstream=nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_auth_protects_all_endpoints() {
    let (router, _state, _storage, _ca) = setup_test_app("locked").await;

    // Test /ca.pem is protected
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ca.pem")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Test /api/cooldown/reset is protected
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cooldown/reset?upstream=upstream-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_crud_upstream_endpoints() {
    let (router, state, _storage, _ca) = setup_test_app("").await;

    // Add new upstream
    let body = "name=new-upstream&kind=direct&url=";
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/upstreams")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_to_string(resp.into_body()).await;
    assert!(html.contains("new-upstream"));
    assert!(state.get_upstream("new-upstream").is_some());

    // Delete upstream
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/upstreams/new-upstream/delete")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.get_upstream("new-upstream").is_none());
}

#[tokio::test]
async fn test_crud_pool_endpoints() {
    let (router, state, _storage, _ca) = setup_test_app("").await;

    // Add new pool
    let body = "name=dynamic-pool&strategy=round_robin&cooldown_secs=45&members=upstream-1&mitm_hosts=api.openai.com";
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pools")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_to_string(resp.into_body()).await;
    assert!(html.contains("dynamic-pool"));
    assert!(state.get_pool("dynamic-pool").is_some());

    // Delete pool
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pools/dynamic-pool/delete")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.get_pool("dynamic-pool").is_none());
}

#[tokio::test]
async fn test_change_password_endpoint_and_dynamic_auth() {
    let (router, _state, _storage, _ca) = setup_test_app("").await;

    // Initially no password required
    let resp = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Update password
    let body = "password=newsecret123";
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/settings/password")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Now request without auth -> 401
    let resp = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Request with new password -> 200 OK
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(
                    header::AUTHORIZATION,
                    basic_auth_header("admin:newsecret123"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_live_logs_endpoint() {
    let (router, _state, storage, _ca) = setup_test_app("").await;

    storage
        .insert_log(&RequestLogEntry::new(
            "127.0.0.1".to_string(),
            "default".to_string(),
            "direct".to_string(),
            "api.test.com:443".to_string(),
            false,
            200,
            12,
        ))
        .await
        .unwrap();

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_to_string(resp.into_body()).await;
    assert!(html.contains("api.test.com:443"));
}
