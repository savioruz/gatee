use bytes::Bytes;
use gatee_config::{UpstreamCfg, UpstreamKind};
use gatee_core::UpstreamRuntime;
use gatee_proxy::{
    dial_direct, dial_http_proxy, dial_socks5_proxy, dial_upstream, filter_hop_by_hop,
    relay_request, relay_to_vercel, ProxyError, RelayError, MAX_RELAY_BODY,
};
use reqwest::header::{HeaderMap, HeaderValue};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// 1. DIRECT TCP DIALER TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dial_direct_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping!");
        socket.write_all(b"pong!").await.unwrap();
    });

    let mut client = dial_direct(&addr.to_string()).await.unwrap();
    client.write_all(b"ping!").await.unwrap();

    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong!");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_direct_connection_failure() {
    // Dialing an address where nothing is listening should fail with an io::Error
    let result = dial_direct("127.0.0.1:1").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dial_upstream_direct() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"direct-upstream-ok").await.unwrap();
    });

    let upstream = UpstreamRuntime::new(UpstreamCfg {
        name: "test-direct".to_string(),
        kind: UpstreamKind::Direct,
        url: String::new(),
    });

    let mut client = dial_upstream(&upstream, &addr.to_string()).await.unwrap();
    let mut buf = [0u8; 18];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"direct-upstream-ok");
}

// ---------------------------------------------------------------------------
// 2. HTTP CONNECT PROXY DIALER TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dial_http_proxy_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut req_buf = vec![0u8; 1024];
        let n = socket.read(&mut req_buf).await.unwrap();
        let req = String::from_utf8_lossy(&req_buf[..n]);

        assert!(req.starts_with("CONNECT target.com:443 HTTP/1.1\r\n"));
        assert!(req.contains("Host: target.com:443\r\n"));
        assert!(!req.contains("Proxy-Authorization"));

        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Data exchange through tunnel
        socket.write_all(b"tunneled-data").await.unwrap();
    });

    let mut client = dial_http_proxy(&proxy_addr.to_string(), "target.com:443", None)
        .await
        .unwrap();

    let mut buf = [0u8; 13];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"tunneled-data");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_http_proxy_with_auth_argument() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut req_buf = vec![0u8; 1024];
        let n = socket.read(&mut req_buf).await.unwrap();
        let req = String::from_utf8_lossy(&req_buf[..n]);

        // Base64 of "alice:secret123" is "YWxpY2U6c2VjcmV0MTIz"
        assert!(req.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0MTIz\r\n"));

        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        socket.write_all(b"auth-tunneled").await.unwrap();
    });

    let mut client = dial_http_proxy(
        &proxy_addr.to_string(),
        "secure.target:8443",
        Some(("alice", "secret123")),
    )
    .await
    .unwrap();

    let mut buf = [0u8; 13];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"auth-tunneled");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_http_proxy_with_url_embedded_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let url_with_creds = format!("http://bob:password456@{}/", proxy_addr);

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut req_buf = vec![0u8; 1024];
        let n = socket.read(&mut req_buf).await.unwrap();
        let req = String::from_utf8_lossy(&req_buf[..n]);

        // Base64 of "bob:password456" is "Ym9iOnBhc3N3b3JkNDU2"
        assert!(req.contains("Proxy-Authorization: Basic Ym9iOnBhc3N3b3JkNDU2\r\n"));

        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });

    let _client = dial_http_proxy(&url_with_creds, "example.com:443", None)
        .await
        .unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_http_proxy_rejected_407() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
    });

    let res = dial_http_proxy(&proxy_addr.to_string(), "target.com:443", None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("407"));
}

#[tokio::test]
async fn test_dial_http_proxy_rejected_502() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await
            .unwrap();
    });

    let res = dial_http_proxy(&proxy_addr.to_string(), "target.com:443", None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn test_dial_upstream_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });

    let upstream = UpstreamRuntime::new(UpstreamCfg {
        name: "test-http-proxy".to_string(),
        kind: UpstreamKind::Http,
        url: format!("http://{}", proxy_addr),
    });

    let res = dial_upstream(&upstream, "upstream-target.com:443").await;
    assert!(res.is_ok());
}

// ---------------------------------------------------------------------------
// 3. SOCKS5 PROXY DIALER TESTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dial_socks5_proxy_no_auth_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // 1. Read greeting [VER=5, NMETHODS=1, METHOD=0]
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);

        // Select method 0 (No Auth)
        socket.write_all(&[5, 0]).await.unwrap();

        // 2. Read connect request: [VER=5, CMD=1, RSV=0, ATYP=3, LEN, DOMAIN..., PORT (2 bytes)]
        let mut req_header = [0u8; 5]; // [5, 1, 0, 3, len]
        socket.read_exact(&mut req_header).await.unwrap();
        assert_eq!(&req_header[..4], &[5, 1, 0, 3]);
        let domain_len = req_header[4] as usize;

        let mut domain_and_port = vec![0u8; domain_len + 2];
        socket.read_exact(&mut domain_and_port).await.unwrap();
        let domain = String::from_utf8_lossy(&domain_and_port[..domain_len]);
        let port =
            u16::from_be_bytes([domain_and_port[domain_len], domain_and_port[domain_len + 1]]);

        assert_eq!(domain, "api.example.com");
        assert_eq!(port, 443);

        // 3. Send SOCKS5 reply: [VER=5, REP=0 (success), RSV=0, ATYP=1, BND.ADDR (4 bytes), BND.PORT (2 bytes)]
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();

        // Tunneled data
        socket.write_all(b"socks5-payload").await.unwrap();
    });

    let mut client = dial_socks5_proxy(&proxy_addr.to_string(), "api.example.com", 443, None)
        .await
        .unwrap();

    let mut buf = [0u8; 14];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks5-payload");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_socks5_proxy_username_password_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // 1. Read greeting [VER=5, NMETHODS=2, METHODS=0, 2]
        let mut greeting = [0u8; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);

        // Select method 2 (Username/Password)
        socket.write_all(&[5, 2]).await.unwrap();

        // 2. Read auth request: [VER=1, ULEN, USER..., PLEN, PASS...]
        let mut ulen_buf = [0u8; 2];
        socket.read_exact(&mut ulen_buf).await.unwrap();
        assert_eq!(ulen_buf[0], 1); // subneg version 1
        let ulen = ulen_buf[1] as usize;

        let mut user = vec![0u8; ulen];
        socket.read_exact(&mut user).await.unwrap();

        let mut plen_buf = [0u8; 1];
        socket.read_exact(&mut plen_buf).await.unwrap();
        let plen = plen_buf[0] as usize;

        let mut pass = vec![0u8; plen];
        socket.read_exact(&mut pass).await.unwrap();

        assert_eq!(user, b"testuser");
        assert_eq!(pass, b"testpass");

        // Auth success: [VER=1, STATUS=0]
        socket.write_all(&[1, 0]).await.unwrap();

        // 3. Read connect request
        let mut req_header = [0u8; 5];
        socket.read_exact(&mut req_header).await.unwrap();
        let domain_len = req_header[4] as usize;
        let mut rest = vec![0u8; domain_len + 2];
        socket.read_exact(&mut rest).await.unwrap();

        // Reply success with Domain bind addr [VER=5, REP=0, RSV=0, ATYP=3, LEN=9, "localhost", PORT=0]
        let mut reply = vec![5, 0, 0, 3, 9];
        reply.extend_from_slice(b"localhost");
        reply.extend_from_slice(&[0, 0]);
        socket.write_all(&reply).await.unwrap();

        socket.write_all(b"auth-success").await.unwrap();
    });

    let mut client = dial_socks5_proxy(
        &proxy_addr.to_string(),
        "dest.local",
        8080,
        Some(("testuser", "testpass")),
    )
    .await
    .unwrap();

    let mut buf = [0u8; 12];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"auth-success");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_socks5_proxy_url_with_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let socks5_url = format!("socks5://myuser:mypass@{}/", proxy_addr);

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Greeting
        let mut greeting = [0u8; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 2]).await.unwrap();

        // Auth
        let mut auth_head = [0u8; 2];
        socket.read_exact(&mut auth_head).await.unwrap();
        let ulen = auth_head[1] as usize;
        let mut user = vec![0u8; ulen];
        socket.read_exact(&mut user).await.unwrap();

        let mut plen_buf = [0u8; 1];
        socket.read_exact(&mut plen_buf).await.unwrap();
        let plen = plen_buf[0] as usize;
        let mut pass = vec![0u8; plen];
        socket.read_exact(&mut pass).await.unwrap();

        assert_eq!(user, b"myuser");
        assert_eq!(pass, b"mypass");

        socket.write_all(&[1, 0]).await.unwrap();

        // Read connect
        let mut req_header = [0u8; 5];
        socket.read_exact(&mut req_header).await.unwrap();
        let domain_len = req_header[4] as usize;
        let mut rest = vec![0u8; domain_len + 2];
        socket.read_exact(&mut rest).await.unwrap();

        // Reply success
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
    });

    let _client = dial_socks5_proxy(&socks5_url, "target.org", 80, None)
        .await
        .unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_dial_socks5_proxy_ipv4_and_ipv6() {
    // IPv4 test
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let server_task_v4 = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();

        // Read connect: [5, 1, 0, 1 (IPv4), 4 bytes IP, 2 bytes port]
        let mut req = [0u8; 10];
        socket.read_exact(&mut req).await.unwrap();
        assert_eq!(&req[..4], &[5, 1, 0, 1]);
        assert_eq!(&req[4..8], &[192, 168, 1, 1]);
        assert_eq!(&req[8..10], &80u16.to_be_bytes());

        socket
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let _client_v4 = dial_socks5_proxy(&proxy_addr.to_string(), "192.168.1.1", 80, None)
        .await
        .unwrap();
    server_task_v4.await.unwrap();

    // IPv6 test
    let listener6 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr6 = listener6.local_addr().unwrap();

    let server_task_v6 = tokio::spawn(async move {
        let (mut socket, _) = listener6.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();

        // Read connect: [5, 1, 0, 4 (IPv6), 16 bytes IP, 2 bytes port]
        let mut req = [0u8; 22];
        socket.read_exact(&mut req).await.unwrap();
        assert_eq!(&req[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &req[4..20],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        ); // ::1
        assert_eq!(&req[20..22], &443u16.to_be_bytes());

        // Reply with IPv6 bind addr [5, 0, 0, 4, 16 bytes IP, 2 bytes port]
        let mut reply = vec![5, 0, 0, 4];
        reply.extend_from_slice(&[0u8; 16]);
        reply.extend_from_slice(&[0, 0]);
        socket.write_all(&reply).await.unwrap();
    });

    let _client_v6 = dial_socks5_proxy(&proxy_addr6.to_string(), "::1", 443, None)
        .await
        .unwrap();
    server_task_v6.await.unwrap();
}

#[tokio::test]
async fn test_dial_socks5_proxy_auth_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 2]).await.unwrap();

        let mut buf = [0u8; 64];
        let _ = socket.read(&mut buf).await;
        // Auth failure: [1, 1]
        socket.write_all(&[1, 1]).await.unwrap();
    });

    let res = dial_socks5_proxy(
        &proxy_addr.to_string(),
        "target.com",
        80,
        Some(("wrong", "pass")),
    )
    .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn test_dial_socks5_proxy_method_not_accepted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        // 0xFF = no acceptable methods
        socket.write_all(&[5, 0xFF]).await.unwrap();
    });

    let res = dial_socks5_proxy(&proxy_addr.to_string(), "target.com", 80, None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn test_dial_socks5_proxy_error_code_in_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();

        let mut req = [0u8; 10];
        let _ = socket.read(&mut req).await;
        // Reply with error code 5 (Connection refused)
        socket
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let res = dial_socks5_proxy(&proxy_addr.to_string(), "127.0.0.1", 80, None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("code 5"));
}

#[tokio::test]
async fn test_dial_upstream_socks5() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();

        let mut req_header = [0u8; 5];
        socket.read_exact(&mut req_header).await.unwrap();
        let domain_len = req_header[4] as usize;
        let mut rest = vec![0u8; domain_len + 2];
        socket.read_exact(&mut rest).await.unwrap();

        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
    });

    let upstream = UpstreamRuntime::new(UpstreamCfg {
        name: "test-socks5-upstream".to_string(),
        kind: UpstreamKind::Socks5,
        url: format!("socks5://{}", proxy_addr),
    });

    let res = dial_upstream(&upstream, "my-target.com:443").await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_dial_upstream_vercel_fails() {
    let upstream = UpstreamRuntime::new(UpstreamCfg {
        name: "test-vercel-upstream".to_string(),
        kind: UpstreamKind::Vercel,
        url: "https://my-relay.vercel.app".to_string(),
    });

    let res = dial_upstream(&upstream, "my-target.com:443").await;
    assert!(matches!(
        res,
        Err(ProxyError::Unsupported(UpstreamKind::Vercel))
    ));
}

// ---------------------------------------------------------------------------
// 4. VERCEL RELAY FORWARDING TESTS
// ---------------------------------------------------------------------------

async fn run_mock_relay_server<F>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(String, HeaderMap, Bytes) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>)
        + Send
        + Sync
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let handler = handler.clone();

            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut temp = [0u8; 1024];

                // Read until double CRLF
                let mut body_start = 0;
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = match socket.read(&mut temp).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    buf.extend_from_slice(&temp[..n]);
                }

                for (i, w) in buf.windows(4).enumerate() {
                    if w == b"\r\n\r\n" {
                        body_start = i + 4;
                        break;
                    }
                }

                let header_part = String::from_utf8_lossy(&buf[..body_start]);
                let mut lines = header_part.lines();
                let request_line = lines.next().unwrap_or("").to_string();

                let mut headers = HeaderMap::new();
                let mut content_length: usize = 0;

                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_lowercase();
                        let val = v.trim();
                        if key == "content-length" {
                            content_length = val.parse().unwrap_or(0);
                        }
                        if let (Ok(h_key), Ok(h_val)) = (
                            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                            HeaderValue::from_str(val),
                        ) {
                            headers.insert(h_key, h_val);
                        }
                    }
                }

                let mut body = buf[body_start..].to_vec();
                while body.len() < content_length {
                    let n = match socket.read(&mut temp).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    body.extend_from_slice(&temp[..n]);
                }

                let (status_code, resp_headers, resp_body) =
                    handler(request_line, headers, Bytes::from(body));

                let status_text = match status_code {
                    200 => "OK",
                    502 => "Bad Gateway",
                    503 => "Service Unavailable",
                    504 => "Gateway Timeout",
                    _ => "Response",
                };

                let mut response_bytes = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
                    status_code,
                    status_text,
                    resp_body.len()
                );
                for (hk, hv) in resp_headers {
                    response_bytes.push_str(&format!("{}: {}\r\n", hk, hv));
                }
                response_bytes.push_str("\r\n");

                let _ = socket.write_all(response_bytes.as_bytes()).await;
                let _ = socket.write_all(&resp_body).await;
            });
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_vercel_relay_success() {
    let (addr, _handle) = run_mock_relay_server(|req_line, headers, body| {
        assert!(req_line.starts_with("POST "));
        assert_eq!(
            headers.get("x-relay-target").unwrap().to_str().unwrap(),
            "api.openai.com"
        );
        assert_eq!(
            headers.get("x-relay-path").unwrap().to_str().unwrap(),
            "/v1/chat/completions"
        );
        assert_eq!(
            headers.get("accept-encoding").unwrap().to_str().unwrap(),
            "identity"
        );
        // Hop-by-hop headers must be stripped
        assert!(headers.get("connection").is_none());
        assert!(headers.get("proxy-authorization").is_none());
        assert!(headers.get("keep-alive").is_none());
        // Custom headers must be preserved
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer test-key"
        );
        assert_eq!(body, Bytes::from(r#"{"model":"gpt-4"}"#));

        (
            200,
            vec![("Content-Type", "application/json")],
            br#"{"choices":[{"text":"hi"}]}"#.to_vec(),
        )
    })
    .await;

    let client = reqwest::Client::new();
    let relay = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "vercel-relay-1".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", addr),
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer test-key"),
    );
    headers.insert(
        reqwest::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("proxy-authorization"),
        HeaderValue::from_static("Basic dGVzdDp0ZXN0"),
    );

    let resp = relay_request(
        &client,
        &[relay],
        30,
        http::Method::POST,
        "api.openai.com",
        "/v1/chat/completions",
        headers,
        Bytes::from(r#"{"model":"gpt-4"}"#),
    )
    .await
    .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp_bytes = resp.bytes().await.unwrap();
    assert_eq!(&resp_bytes[..], br#"{"choices":[{"text":"hi"}]}"#);
}

fn current_timestamp_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn test_vercel_relay_failover_and_cooldown_on_502() {
    let (addr1, _h1) = run_mock_relay_server(|_req_line, _headers, _body| {
        (502, vec![], b"bad gateway from relay 1".to_vec())
    })
    .await;

    let (addr2, _h2) = run_mock_relay_server(|_req_line, _headers, _body| {
        (200, vec![], b"success from relay 2".to_vec())
    })
    .await;

    let client = reqwest::Client::new();
    let relay1 = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "failing-relay".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", addr1),
    }));
    let relay2 = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "healthy-relay".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", addr2),
    }));

    let relays = vec![relay1.clone(), relay2.clone()];
    let now = current_timestamp_secs();

    assert!(!relay1.is_down(now));
    assert!(!relay2.is_down(now));

    let resp = relay_request(
        &client,
        &relays,
        60,
        http::Method::GET,
        "api.target.com",
        "/status",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(&bytes[..], b"success from relay 2");

    // relay1 should have been marked down
    let check_time = current_timestamp_secs();
    assert!(relay1.is_down(check_time));
    assert!(!relay2.is_down(check_time));
}

#[tokio::test]
async fn test_vercel_relay_all_relays_failed() {
    let (addr1, _h1) = run_mock_relay_server(|_req_line, _headers, _body| {
        (503, vec![], b"service unavailable".to_vec())
    })
    .await;

    // Relay 2 points to an invalid/unbound port
    let client = reqwest::Client::new();
    let relay1 = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "relay-503".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", addr1),
    }));
    let relay2 = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "relay-unreachable".to_string(),
        kind: UpstreamKind::Vercel,
        url: "http://127.0.0.1:1".to_string(),
    }));

    let relays = vec![relay1.clone(), relay2.clone()];
    let res = relay_request(
        &client,
        &relays,
        30,
        http::Method::GET,
        "api.target.com",
        "/test",
        HeaderMap::new(),
        Bytes::new(),
    )
    .await;

    assert!(matches!(res, Err(RelayError::AllRelaysFailed(_))));

    let check_time = current_timestamp_secs();
    assert!(relay1.is_down(check_time));
    assert!(relay2.is_down(check_time));
}

#[tokio::test]
async fn test_vercel_relay_body_exceeds_max_size() {
    let client = reqwest::Client::new();
    let relay = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "relay-1".to_string(),
        kind: UpstreamKind::Vercel,
        url: "http://127.0.0.1:8080".to_string(),
    }));

    // Body larger than 16MB
    let large_body = Bytes::from(vec![0u8; MAX_RELAY_BODY + 1]);
    let res = relay_request(
        &client,
        &[relay],
        30,
        http::Method::POST,
        "api.target.com",
        "/upload",
        HeaderMap::new(),
        large_body,
    )
    .await;

    assert!(matches!(res, Err(RelayError::BodyTooLarge)));
}

#[tokio::test]
async fn test_relay_to_vercel_wrapper() {
    let (addr, _h) =
        run_mock_relay_server(|_req_line, _headers, _body| (200, vec![], b"wrapper-ok".to_vec()))
            .await;

    let client = reqwest::Client::new();
    let relay = Arc::new(UpstreamRuntime::new(UpstreamCfg {
        name: "relay-wrapper".to_string(),
        kind: UpstreamKind::Vercel,
        url: format!("http://{}", addr),
    }));

    let resp = relay_to_vercel(
        &client,
        &[relay],
        "target.host",
        "/path",
        http::Method::GET,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[test]
fn test_filter_hop_by_hop_headers() {
    let mut map = HeaderMap::new();
    map.insert(
        reqwest::header::CONNECTION,
        HeaderValue::from_static("close"),
    );
    map.insert(
        reqwest::header::HeaderName::from_static("proxy-connection"),
        HeaderValue::from_static("keep-alive"),
    );
    map.insert(
        reqwest::header::HeaderName::from_static("keep-alive"),
        HeaderValue::from_static("timeout=5"),
    );
    map.insert(
        reqwest::header::HeaderName::from_static("proxy-authenticate"),
        HeaderValue::from_static("Basic"),
    );
    map.insert(
        reqwest::header::HeaderName::from_static("proxy-authorization"),
        HeaderValue::from_static("Basic creds"),
    );
    map.insert(reqwest::header::TE, HeaderValue::from_static("trailers"));
    map.insert(
        reqwest::header::TRAILER,
        HeaderValue::from_static("x-trailer"),
    );
    map.insert(
        reqwest::header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    map.insert(
        reqwest::header::UPGRADE,
        HeaderValue::from_static("websocket"),
    );
    map.insert(
        reqwest::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer token"),
    );
    map.insert(
        reqwest::header::HeaderName::from_static("x-custom-header"),
        HeaderValue::from_static("value123"),
    );

    let filtered = filter_hop_by_hop(&map);
    assert_eq!(filtered.len(), 2);
    assert_eq!(
        filtered.get("authorization").unwrap().to_str().unwrap(),
        "Bearer token"
    );
    assert_eq!(
        filtered.get("x-custom-header").unwrap().to_str().unwrap(),
        "value123"
    );
}
