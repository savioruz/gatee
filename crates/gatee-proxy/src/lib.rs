pub mod direct;
pub mod http;
pub mod socks5;
pub mod vercel;

pub use direct::*;
pub use http::*;
pub use socks5::*;
pub use vercel::*;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Relay error: {0}")]
    Relay(#[from] RelayError),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Unsupported upstream kind: {0:?}")]
    Unsupported(gatee_config::UpstreamKind),
}

/// Dials an upstream runtime based on its configured kind.
pub async fn dial_upstream(
    upstream: &gatee_core::UpstreamRuntime,
    target_addr: &str,
) -> Result<tokio::net::TcpStream, ProxyError> {
    match upstream.kind() {
        gatee_config::UpstreamKind::Direct => {
            let stream = dial_direct(target_addr).await?;
            Ok(stream)
        }
        gatee_config::UpstreamKind::Http => {
            let stream = dial_http_proxy(upstream.url(), target_addr, None).await?;
            Ok(stream)
        }
        gatee_config::UpstreamKind::Socks5 => {
            let (host, port) = match target_addr.rsplit_once(':') {
                Some((h, p)) => (
                    h,
                    p.parse::<u16>()
                        .map_err(|e| ProxyError::Config(e.to_string()))?,
                ),
                None => (target_addr, 80),
            };
            let stream = dial_socks5_proxy(upstream.url(), host, port, None).await?;
            Ok(stream)
        }
        gatee_config::UpstreamKind::Vercel => {
            Err(ProxyError::Unsupported(gatee_config::UpstreamKind::Vercel))
        }
    }
}

/// Convenience wrapper for `relay_request` with default 30s cooldown and `ProxyError` return type.
pub async fn relay_to_vercel(
    client: &reqwest::Client,
    relays: &[std::sync::Arc<gatee_core::UpstreamRuntime>],
    target: &str,
    request_uri: &str,
    method: ::http::Method,
    headers: reqwest::header::HeaderMap,
    body: bytes::Bytes,
) -> Result<reqwest::Response, ProxyError> {
    relay_request(
        client,
        relays,
        30,
        method,
        target,
        request_uri,
        headers,
        body,
    )
    .await
    .map_err(ProxyError::from)
}
