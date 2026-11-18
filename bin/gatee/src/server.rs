use crate::tunnel::handle_connect;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use gatee_ca::CertificateAuthority;
use gatee_core::GatewayState;
use gatee_storage::LogEmitter;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::Service;
use tracing::error;

pub async fn run_server(
    listener: TcpListener,
    state: Arc<GatewayState>,
    ca: Arc<CertificateAuthority>,
    web_router: Router,
    logger: LogEmitter,
) -> anyhow::Result<()> {
    let http_client = reqwest::Client::builder().use_rustls_tls().build()?;

    loop {
        let (stream, client_ip) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);
        let ca = Arc::clone(&ca);
        let web_router = web_router.clone();
        let logger = logger.clone();
        let http_client = http_client.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state);
                let ca = Arc::clone(&ca);
                let mut web_router = web_router.clone();
                let logger = logger.clone();
                let http_client = http_client.clone();

                async move {
                    state.inc_requests();

                    if req.method() == Method::CONNECT {
                        let (username, password) = extract_proxy_auth(&req);
                        match state.authenticate(&username, &password) {
                            Ok((pool, key)) => {
                                handle_connect(req, pool, key, ca, http_client, logger, client_ip)
                                    .await
                            }
                            Err(_) => {
                                let mut resp =
                                    Response::new(Full::new(Bytes::from("Proxy Auth Required")));
                                *resp.status_mut() = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                                resp.headers_mut().insert(
                                    "Proxy-Authenticate",
                                    hyper::header::HeaderValue::from_static(
                                        "Basic realm=\"relay-gateway\"",
                                    ),
                                );
                                Ok(resp)
                            }
                        }
                    } else if req.method() == Method::GET && req.uri().path() == "/healthz" {
                        let mut resp = Response::new(Full::new(Bytes::from("ok\n")));
                        *resp.status_mut() = StatusCode::OK;
                        Ok(resp)
                    } else {
                        // Route to Axum Web Dashboard
                        let axum_req = req.map(axum::body::Body::new);
                        match web_router.call(axum_req).await {
                            Ok(resp) => {
                                let (parts, body) = resp.into_parts();
                                let body_bytes = match http_body_util::BodyExt::collect(body).await
                                {
                                    Ok(collected) => collected.to_bytes(),
                                    Err(e) => {
                                        error!("Error collecting response body: {}", e);
                                        Bytes::new()
                                    }
                                };
                                Ok(Response::from_parts(parts, Full::new(body_bytes)))
                            }
                            Err(e) => {
                                error!("Web router error: {:?}", e);
                                Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Full::new(Bytes::from("Internal Server Error")))
                                    .unwrap())
                            }
                        }
                    }
                }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                // Client disconnection is expected in proxies
                tracing::debug!("Connection closed: {}", e);
            }
        });
    }
}

fn extract_proxy_auth(req: &Request<Incoming>) -> (String, String) {
    if let Some(auth) = req.headers().get("Proxy-Authorization") {
        if let Ok(s) = auth.to_str() {
            let trimmed = s.trim();
            let b64 = if let Some(rest) = trimmed.strip_prefix("Basic ") {
                Some(rest)
            } else {
                trimmed.strip_prefix("basic ")
            };
            if let Some(b64) = b64 {
                if let Ok(decoded) = base64::prelude::BASE64_STANDARD.decode(b64.trim()) {
                    if let Ok(s) = String::from_utf8(decoded) {
                        let (u, p) = s.split_once(':').unwrap_or((&s, ""));
                        return (u.to_string(), p.to_string());
                    }
                }
            }
        }
    }
    ("".to_string(), "".to_string())
}
