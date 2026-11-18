use base64::Engine;
use gatee::run_server;
use gatee_ca::CertificateAuthority;
use gatee_config::{Config, PoolCfg, PoolStrategy, UpstreamCfg, UpstreamKind};
use gatee_core::GatewayState;
use gatee_storage::{LogEmitter, PoolRecord, Storage};
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
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
    let dead_upstream = state.get_upstream("dead-proxy").unwrap();
    assert!(dead_upstream.is_down(chrono::Utc::now().timestamp()));
}

#[tokio::test]
async fn test_blind_tunnel_all_upstreams_fail_logs_502() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));
    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    let upstreams = vec![UpstreamCfg {
        name: "dead-http".to_string(),
        kind: UpstreamKind::Http,
        url: "http://127.0.0.1:1".to_string(),
    }];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["dead-http".to_string()],
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let auth = base64::prelude::BASE64_STANDARD.encode("default:secret");
    let req = format!(
        "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
        auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    // Allow time for dialing failure and logger emission
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    let logs = storage.fetch_recent_logs(10).await.expect("logs");
    assert!(!logs.is_empty(), "Expected a log entry");
    let log = &logs[0];
    assert_eq!(log.status_code, 502);
    assert!(!log.is_mitm);
    assert_eq!(log.upstream, "dead-http");
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("---")).collect();
    base64::prelude::BASE64_STANDARD
        .decode(b64)
        .expect("decode pem")
}

fn create_tls_connector(ca_pem: &str) -> tokio_rustls::TlsConnector {
    let der = pem_to_der(ca_pem);
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store
        .add(tokio_rustls::rustls::pki_types::CertificateDer::from(der))
        .expect("add ca to root store");
    let client_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
}

#[tokio::test]
async fn test_mitm_upgrade_websocket_returns_501() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));
    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    let upstreams = vec![UpstreamCfg {
        name: "vercel-relay".to_string(),
        kind: UpstreamKind::Vercel,
        url: "http://127.0.0.1:12345".to_string(),
    }];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["vercel-relay".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec!["mitm.example.com".to_string()],
            cooldown_secs: 30,
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let auth = base64::prelude::BASE64_STANDARD.encode("default:secret");
    let req = format!(
        "CONNECT mitm.example.com:443 HTTP/1.1\r\nHost: mitm.example.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
        auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    // Handshake TLS over the established tunnel
    let connector = create_tls_connector(ca.cert_pem());
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from("mitm.example.com".to_string())
            .unwrap();
    let mut tls_stream = connector.connect(server_name, client).await.expect("tls");

    // Send HTTP request with Upgrade: websocket header
    let ws_req = "GET /ws HTTP/1.1\r\nHost: mitm.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    tls_stream
        .write_all(ws_req.as_bytes())
        .await
        .expect("write ws");

    let mut ws_resp = [0u8; 1024];
    let n = tls_stream.read(&mut ws_resp).await.expect("read ws");
    let resp_str = String::from_utf8_lossy(&ws_resp[..n]);
    assert!(resp_str.starts_with("HTTP/1.1 501 Not Implemented"));
    assert!(resp_str.contains("WebSocket is not supported over Vercel relay"));
}

#[tokio::test]
async fn test_mitm_relay_failure_logs_502() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));
    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    let upstreams = vec![UpstreamCfg {
        name: "dead-relay".to_string(),
        kind: UpstreamKind::Vercel,
        url: "http://127.0.0.1:1".to_string(),
    }];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["dead-relay".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec!["api.openai.com".to_string()],
            cooldown_secs: 30,
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let auth = base64::prelude::BASE64_STANDARD.encode("default:secret");
    let req = format!(
        "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
        auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.expect("read");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 OK"));

    // TLS Handshake
    let connector = create_tls_connector(ca.cert_pem());
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from("api.openai.com".to_string())
            .unwrap();
    let mut tls_stream = connector.connect(server_name, client).await.expect("tls");

    // Send HTTP request to dead relay
    let http_req = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(http_req.as_bytes())
        .await
        .expect("write http");

    let mut http_resp = [0u8; 1024];
    let n = tls_stream.read(&mut http_resp).await.expect("read resp");
    let resp_str = String::from_utf8_lossy(&http_resp[..n]);
    assert!(resp_str.starts_with("HTTP/1.1 502 Bad Gateway"));

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert!(!logs.is_empty());
    let log = &logs[0];
    assert_eq!(log.status_code, 502);
    assert!(log.is_mitm);
    assert_eq!(log.target_host, "api.openai.com");
    assert_eq!(log.upstream, "dead-relay");
}

#[tokio::test]
async fn test_mitm_per_request_latency() {
    // Start mock relay
    let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match mock_listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                    if socket.write_all(resp.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));
    let storage = Storage::new_in_memory().await.expect("storage");
    let logger = LogEmitter::new(storage.clone(), 64);

    let upstreams = vec![UpstreamCfg {
        name: "live-relay".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", mock_addr),
    }];

    let mut pools = HashMap::new();
    pools.insert(
        "default".to_string(),
        PoolCfg {
            members: vec!["live-relay".to_string()],
            strategy: PoolStrategy::Failover,
            mitm_hosts: vec!["api.openai.com".to_string()],
            cooldown_secs: 30,
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

    let state = Arc::new(GatewayState::new(config, storage.clone()));
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let auth = base64::prelude::BASE64_STANDARD.encode("default:secret");
    let req = format!(
        "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
        auth
    );
    client.write_all(req.as_bytes()).await.expect("write");

    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.expect("read");
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 OK"));

    // TLS Handshake
    let connector = create_tls_connector(ca.cert_pem());
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from("api.openai.com".to_string())
            .unwrap();
    let mut tls_stream = connector.connect(server_name, client).await.expect("tls");

    // Request 1
    let req1 = "GET /req1 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    tls_stream
        .write_all(req1.as_bytes())
        .await
        .expect("write req1");

    let mut resp1 = [0u8; 512];
    let n1 = tls_stream.read(&mut resp1).await.expect("read resp1");
    assert!(String::from_utf8_lossy(&resp1[..n1]).starts_with("HTTP/1.1 200 OK"));

    // Wait 150ms before sending Request 2 over keep-alive connection
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Request 2
    let req2 = "GET /req2 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
    tls_stream
        .write_all(req2.as_bytes())
        .await
        .expect("write req2");

    let mut resp2 = [0u8; 512];
    let n2 = tls_stream.read(&mut resp2).await.expect("read resp2");
    assert!(String::from_utf8_lossy(&resp2[..n2]).starts_with("HTTP/1.1 200 OK"));

    // Wait for DB logger
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let logs = storage.fetch_recent_logs(10).await.expect("fetch logs");
    assert_eq!(logs.len(), 2);
    // Request 2 (most recent) should measure around 60ms latency, NOT 60+150+60 (tunnel duration)
    let log_req2 = &logs[0];
    let log_req1 = &logs[1];
    assert!(
        log_req2.latency_ms >= 50 && log_req2.latency_ms < 140,
        "req2 latency was: {}",
        log_req2.latency_ms
    );
    assert!(
        log_req1.latency_ms >= 50 && log_req1.latency_ms < 140,
        "req1 latency was: {}",
        log_req1.latency_ms
    );
}

#[tokio::test]
async fn test_dynamic_pool_creation_and_routing() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");
    let ca = Arc::new(CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("ca"));

    let storage = Storage::new_in_memory().await.expect("storage");
    storage
        .ensure_seeded(Some("dynamicpass"))
        .await
        .expect("seed");

    let logger = LogEmitter::new(storage.clone(), 64);
    let state = Arc::new(
        GatewayState::new_with_storage(storage.clone())
            .await
            .expect("state"),
    );
    let web_router = build_web_router(Arc::clone(&state), storage.clone(), Arc::clone(&ca));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");

    let server_state = Arc::clone(&state);
    let server_ca = Arc::clone(&ca);
    tokio::spawn(async move {
        let _ = run_server(listener, server_state, server_ca, web_router, logger).await;
    });

    // Mock target
    let mock_target = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let mock_addr = mock_target.local_addr().expect("mock addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = mock_target.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // 1. Initial request to non-existent custom pool should fail auth (407)
    {
        let mut client = TcpStream::connect(server_addr).await.expect("connect");
        let auth = base64::prelude::BASE64_STANDARD.encode("new-pool:dynamicpass");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            mock_addr, mock_addr, auth
        );
        client.write_all(req.as_bytes()).await.expect("write");
        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 407 Proxy Authentication Required"));
    }

    // 2. Add upstream and new pool dynamically in storage, then hot-reload
    storage
        .upsert_upstream("dynamic-direct", "direct", "", "admin")
        .await
        .expect("upsert upstream");

    let pool_record = PoolRecord {
        name: "new-pool".to_string(),
        strategy: "round_robin".to_string(),
        cooldown_secs: 30,
        mitm_hosts: vec![],
        members: vec!["dynamic-direct".to_string()],
        created_at: String::new(),
        modified_at: String::new(),
        created_by: String::new(),
        modified_by: String::new(),
    };
    storage
        .upsert_pool(&pool_record, "admin")
        .await
        .expect("upsert pool");

    state.reload_from_storage().await.expect("hot reload");

    // 3. Now request with "new-pool:dynamicpass" should succeed (200 OK) and tunnel
    {
        let mut client = TcpStream::connect(server_addr).await.expect("connect");
        let auth = base64::prelude::BASE64_STANDARD.encode("new-pool:dynamicpass");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            mock_addr, mock_addr, auth
        );
        client.write_all(req.as_bytes()).await.expect("write");
        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));

        let payload = b"Dynamic pool echo works!\n";
        client.write_all(payload).await.expect("write payload");
        let mut echo = vec![0u8; payload.len()];
        client.read_exact(&mut echo).await.expect("read echo");
        assert_eq!(&echo, payload);
    }
}
