use base64::Engine;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parses a proxy address string that may contain a URL scheme or embedded credentials.
/// Returns the host:port string to connect to and optional (username, password).
pub fn parse_http_proxy_addr<'a>(
    proxy_addr: &'a str,
    auth: Option<(&'a str, &'a str)>,
) -> (String, Option<(String, String)>) {
    let clean = proxy_addr
        .strip_prefix("http://")
        .or_else(|| proxy_addr.strip_prefix("https://"))
        .unwrap_or(proxy_addr)
        .trim_end_matches('/');

    if let Some((userinfo, hostport)) = clean.rsplit_once('@') {
        let extracted_auth = if let Some((u, p)) = userinfo.split_once(':') {
            Some((u.to_string(), p.to_string()))
        } else {
            Some((userinfo.to_string(), String::new()))
        };
        let effective_auth = auth
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .or(extracted_auth);
        (hostport.to_string(), effective_auth)
    } else {
        let effective_auth = auth.map(|(u, p)| (u.to_string(), p.to_string()));
        (clean.to_string(), effective_auth)
    }
}

/// Dials a target TCP address via an HTTP CONNECT upstream proxy.
pub async fn dial_http_proxy(
    proxy_addr: &str,
    target_addr: &str,
    auth: Option<(&str, &str)>,
) -> io::Result<TcpStream> {
    let (connect_addr, effective_auth) = parse_http_proxy_addr(proxy_addr, auth);
    let mut stream = TcpStream::connect(&connect_addr).await?;

    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target_addr, target_addr
    );
    if let Some((user, pass)) = effective_auth {
        let creds = format!("{}:{}", user, pass);
        let b64 = base64::prelude::BASE64_STANDARD.encode(creds);
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut header_buf = Vec::new();
    let mut one_byte = [0u8; 1];
    while !header_buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut one_byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP upstream proxy closed connection before sending complete CONNECT response",
            ));
        }
        header_buf.push(one_byte[0]);
        if header_buf.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP upstream proxy response headers too large",
            ));
        }
    }

    let response = String::from_utf8_lossy(&header_buf);
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        let first_line = response.lines().next().unwrap_or(&response);
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP upstream proxy rejected CONNECT: {}", first_line),
        ));
    }
    Ok(stream)
}
