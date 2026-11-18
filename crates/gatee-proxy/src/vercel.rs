use bytes::Bytes;
use gatee_core::UpstreamRuntime;
use reqwest::header::{HeaderMap, HeaderValue};
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

pub const MAX_RELAY_BODY: usize = 16 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Body exceeds maximum size of 16MB")]
    BodyTooLarge,
    #[error("All relay upstreams failed: {0}")]
    AllRelaysFailed(String),
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// Forwards an HTTP request to Vercel relays with retries and failover.
pub async fn relay_request(
    client: &reqwest::Client,
    relays: &[Arc<UpstreamRuntime>],
    cooldown_secs: u64,
    method: http::Method,
    target: &str,
    request_uri: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Result<reqwest::Response, RelayError> {
    if body.len() > MAX_RELAY_BODY {
        return Err(RelayError::BodyTooLarge);
    }

    let mut last_err = String::from("no relays available");

    for u in relays {
        let mut req_headers = filter_hop_by_hop(&headers);
        req_headers.remove(http::header::HOST);
        req_headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        if let Ok(v) = HeaderValue::from_str(target) {
            req_headers.insert("x-relay-target", v);
        }
        if let Ok(v) = HeaderValue::from_str(request_uri) {
            req_headers.insert("x-relay-path", v);
        }

        let resp_result = client
            .request(method.clone(), u.url())
            .headers(req_headers)
            .body(body.clone())
            .send()
            .await;

        match resp_result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 502 || status == 503 || status == 504 {
                    warn!("Relay {} returned status {}", u.name(), status);
                    u.mark_down(cooldown_secs);
                    last_err = format!("status {}", status);
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                warn!("Relay {} connection failed: {}", u.name(), e);
                u.mark_down(cooldown_secs);
                last_err = e.to_string();
                continue;
            }
        }
    }

    Err(RelayError::AllRelaysFailed(last_err))
}

/// Filters hop-by-hop headers from the given HeaderMap.
pub fn filter_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let hop_headers = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let mut filtered = HeaderMap::new();
    for (k, v) in headers {
        if !hop_headers.contains(&k.as_str().to_ascii_lowercase().as_str()) {
            filtered.append(k.clone(), v.clone());
        }
    }
    filtered
}
