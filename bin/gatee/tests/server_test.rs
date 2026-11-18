use base64::Engine;
use gatee::run_server;
use gatee_ca::CertificateAuthority;
use gatee_config::{Config, PoolCfg, PoolStrategy, UpstreamCfg, UpstreamKind};
use gatee_core::GatewayState;
use gatee_storage::{LogEmitter, Storage};
use gatee_web::build_web_router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_test_server(password: &str) -> (SocketAddr, Arc<GatewayState>, Storage) {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));

    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    let upstreams = vec![UpstreamCfg {
        name: "direct-node".to_string(),
        kind: UpstreamKind::Direct,
        url: "".to_string(),
    }];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["direct-node".to_string()],
            strategy: PoolStrategy::RoundRobin,
            mitm_hosts: vec![],
            cooldown_secs: 30,
        },
    );

    let config = Config {
        listen: "127.0.0.1:0".to_string(),
        password: password.to_string(),
        ca_cert: cert_path.to_string_lossy().to_string(),
        ca_key: key_path.to_string_lossy().to_string(),
        upstreams,
        pools,
    };

    let state = Arc::new(GatewayState::new(config));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    (addr, state, storage)
}

#[tokio::test]
async fn test_healthz_endpoint() {
    let (addr, state, _) = spawn_test_server("secret123").await;

    let mut client = TcpStream::connect(addr).await.expect("connect");
    let req = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    client.write_all(req.as_bytes()).await.expect("write");

    let mut resp = String::new();
    client.read_to_string(&mut resp).await.expect("read");

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.ends_with("\r\n\r\nok\n") || resp.contains("ok\n"));
    assert_eq!(
        state
            .total_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_dashboard_auth_protection() {
    let (addr, _, _) = spawn_test_server("topsecret").await;

    // 1. Without credentials -> 401 Unauthorized
    let mut client1 = TcpStream::connect(addr).await.expect("connect");
    let req1 = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    client1.write_all(req1.as_bytes()).await.expect("write");

    let mut resp1 = String::new();
    client1.read_to_string(&mut resp1).await.expect("read");
    assert!(
        resp1.starts_with("HTTP/1.1 401 Unauthorized"),
        "Expected 401, got: {}",
        resp1
    );
    assert!(resp1.to_lowercase().contains("www-authenticate: basic"));

    // 2. With wrong password -> 401 Unauthorized
    let wrong_auth = base64::prelude::BASE64_STANDARD.encode("admin:wrongpass");
    let mut client2 = TcpStream::connect(addr).await.expect("connect");
    let req2 = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        wrong_auth
    );
    client2.write_all(req2.as_bytes()).await.expect("write");

    let mut resp2 = String::new();
    client2.read_to_string(&mut resp2).await.expect("read");
    assert!(resp2.starts_with("HTTP/1.1 401 Unauthorized"));

    // 3. With correct password -> 200 OK
    let good_auth = base64::prelude::BASE64_STANDARD.encode("admin:topsecret");
    let mut client3 = TcpStream::connect(addr).await.expect("connect");
    let req3 = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        good_auth
    );
    client3.write_all(req3.as_bytes()).await.expect("write");

    let mut resp3 = String::new();
    client3.read_to_string(&mut resp3).await.expect("read");
    assert!(
        resp3.starts_with("HTTP/1.1 200 OK"),
        "Expected 200, got: {}",
        resp3
    );
    assert!(resp3.contains("Gatee Gateway"));
}

#[tokio::test]
async fn test_connect_proxy_blind_tcp_tunneling() {
    let (server_addr, _, _) = spawn_test_server("pass123").await;

    // Start a mock TCP echo target
    let mock_target = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let mock_addr = mock_target.local_addr().expect("mock addr");

    tokio::spawn(async move {
        let (mut stream, _) = mock_target.accept().await.expect("accept mock");
        let (mut r, mut w) = stream.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });

    // 1. Test CONNECT without auth -> 407 Proxy Authentication Required
    {
        let mut client = TcpStream::connect(server_addr).await.expect("connect");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            mock_addr, mock_addr
        );
        client.write_all(req.as_bytes()).await.expect("write");

        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 407 Proxy Authentication Required"),
            "Expected 407, got: {}",
            resp
        );
        assert!(resp.to_lowercase().contains("proxy-authenticate: basic"));
    }

    // 2. Test CONNECT with correct proxy auth -> 200 OK -> Bidirectional TCP tunnel
    {
        let mut client = TcpStream::connect(server_addr).await.expect("connect");
        let auth = base64::prelude::BASE64_STANDARD.encode("default:pass123");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            mock_addr, mock_addr, auth
        );
        client.write_all(req.as_bytes()).await.expect("write");

        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "Expected 200 OK, got: {}",
            resp
        );

        // Tunnel is established! Send payload through tunnel and expect echo back
        let test_payload = b"Hello through blind TCP tunnel!\n";
        client.write_all(test_payload).await.expect("write payload");

        let mut echo_buf = vec![0u8; test_payload.len()];
        client.read_exact(&mut echo_buf).await.expect("read echo");
        assert_eq!(&echo_buf, test_payload);
    }
}

#[tokio::test]
async fn test_ca_pem_download() {
    let (addr, _, _) = spawn_test_server("secret123").await;
    let auth = base64::prelude::BASE64_STANDARD.encode("admin:secret123");
    let mut client = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET /ca.pem HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut resp = String::new();
    client.read_to_string(&mut resp).await.expect("read");
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn test_connect_failover_marks_down() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));
    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    // Two upstreams: first is dead HTTP proxy on closed port, second is direct
    let upstreams = vec![
        UpstreamCfg {
            name: "dead-proxy".to_string(),
            kind: UpstreamKind::Http,
            url: "http://127.0.0.1:1".to_string(),
        },
        UpstreamCfg {
            name: "live-direct".to_string(),
            kind: UpstreamKind::Direct,
            url: "".to_string(),
        },
    ];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["dead-proxy".to_string(), "live-direct".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec![],
            cooldown_secs: 60,
        },
    );

    let config = Config {
        listen: "127.0.0.1:0".to_string(),
        password: "secret".to_string(),
        ca_cert: cert_path.to_string_lossy().to_string(),
        ca_key: key_path.to_string_lossy().to_string(),
        upstreams,
        pools,
    };

    let state = Arc::new(GatewayState::new(config));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    // Start mock target
    let mock_target = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let mock_addr = mock_target.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let (mut stream, _) = mock_target.accept().await.expect("accept");
        let (mut r, mut w) = stream.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });

    // Connect via proxy
    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let auth = base64::prelude::BASE64_STANDARD.encode("default:secret");
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        mock_addr, mock_addr, auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    // Tunnel should still work via live-direct!
    let payload = b"Ping through failover\n";
    client.write_all(payload).await.expect("write");
    let mut echo = vec![0u8; payload.len()];
    client.read_exact(&mut echo).await.expect("read");
    assert_eq!(&echo, payload);

    // Verify dead-proxy was marked down
    let dead_upstream = state.upstreams.get("dead-proxy").unwrap();
    assert!(dead_upstream.is_down(chrono::Utc::now().timestamp()));
}
