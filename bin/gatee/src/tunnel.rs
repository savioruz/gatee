use gatee_ca::CertificateAuthority;
use gatee_core::{PoolRuntime, UpstreamRuntime};
use gatee_proxy::{dial_direct, dial_http_proxy, dial_socks5_proxy, relay_request};
use gatee_storage::{LogEmitter, RequestLogEntry};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::copy_bidirectional;
use tokio_rustls::TlsAcceptor;
use tracing::{error, warn};

pub struct MitmContext {
    pub hostname: String,
    pub port: u16,
    pub relays: Vec<Arc<UpstreamRuntime>>,
    pub pool: Arc<PoolRuntime>,
    pub ca: Arc<CertificateAuthority>,
    pub client: reqwest::Client,
    pub logger: LogEmitter,
    pub client_ip: SocketAddr,
}

pub async fn handle_connect(
    req: Request<Incoming>,
    pool: Arc<PoolRuntime>,
    sticky_key: String,
    ca: Arc<CertificateAuthority>,
    http_client: reqwest::Client,
    logger: LogEmitter,
    client_ip: SocketAddr,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            let s = req.uri().to_string();
            if s.is_empty() || s == "/" {
                None
            } else {
                Some(s)
            }
        })
        .unwrap_or_default();
    let (hostname, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (host_port.clone(), 443),
    };

    let candidates = pool.candidates(&sticky_key);
    let start_time = Instant::now();

    // Check MITM for Vercel relays
    if pool.mitms(&hostname) {
        let vercel_relays: Vec<Arc<UpstreamRuntime>> = candidates
            .iter()
            .filter(|u| matches!(u.kind(), gatee_config::UpstreamKind::Vercel))
            .cloned()
            .collect();

        if !vercel_relays.is_empty() {
            let mitm_ctx = MitmContext {
                hostname,
                port,
                relays: vercel_relays,
                pool,
                ca,
                client: http_client,
                logger,
                client_ip,
            };
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let io = TokioIo::new(upgraded);
                        serve_mitm(io, mitm_ctx).await;
                    }
                    Err(e) => error!("Upgrade error: {}", e),
                }
            });
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(bytes::Bytes::new()))
                .unwrap());
        }
    }

    // Standard blind tunneling
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                for u in &candidates {
                    if matches!(u.kind(), gatee_config::UpstreamKind::Vercel) {
                        continue;
                    }

                    let dial_result = match u.kind() {
                        gatee_config::UpstreamKind::Direct => {
                            dial_direct(&format!("{}:{}", hostname, port)).await
                        }
                        gatee_config::UpstreamKind::Http => {
                            dial_http_proxy(u.url(), &format!("{}:{}", hostname, port), None).await
                        }
                        gatee_config::UpstreamKind::Socks5 => {
                            dial_socks5_proxy(u.url(), &hostname, port, None).await
                        }
                        gatee_config::UpstreamKind::Vercel => unreachable!(),
                    };

                    match dial_result {
                        Ok(mut upstream_io) => {
                            let _ = copy_bidirectional(&mut client_io, &mut upstream_io).await;
                            logger.record(RequestLogEntry {
                                id: None,
                                timestamp: chrono::Utc::now(),
                                client_ip: client_ip.to_string(),
                                pool: pool.name.clone(),
                                upstream: u.name().to_string(),
                                target_host: format!("{}:{}", hostname, port),
                                is_mitm: false,
                                status_code: 200,
                                latency_ms: start_time.elapsed().as_millis() as i64,
                                created_by: "system".to_string(),
                            });
                            return;
                        }
                        Err(e) => {
                            warn!("Dial failed via {}: {}", u.name(), e);
                            u.mark_down(pool.cooldown_secs);
                        }
                    }
                }

                // If all candidate upstreams fail to dial, emit a 502 RequestLogEntry to logger.record(...)
                logger.record(RequestLogEntry {
                    id: None,
                    timestamp: chrono::Utc::now(),
                    client_ip: client_ip.to_string(),
                    pool: pool.name.clone(),
                    upstream: candidates
                        .first()
                        .map(|u| u.name())
                        .unwrap_or("none")
                        .to_string(),
                    target_host: format!("{}:{}", hostname, port),
                    is_mitm: false,
                    status_code: 502,
                    latency_ms: start_time.elapsed().as_millis() as i64,
                    created_by: "system".to_string(),
                });
            }
            Err(e) => error!("Upgrade error: {}", e),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(bytes::Bytes::new()))
        .unwrap())
}

async fn serve_mitm(io: TokioIo<hyper::upgrade::Upgraded>, ctx: MitmContext) {
    let tls_config = match ctx.ca.server_config_for(&ctx.hostname) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to generate leaf certificate: {}", e);
            return;
        }
    };

    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = match acceptor.accept(io).await {
        Ok(s) => TokioIo::new(s),
        Err(e) => {
            warn!("TLS handshake failed with client: {}", e);
            return;
        }
    };

    let target = format!("https://{}:{}", ctx.hostname, ctx.port);
    let client = ctx.client;
    let relays = Arc::new(ctx.relays);
    let pool = ctx.pool;
    let logger = ctx.logger;
    let client_ip = ctx.client_ip;
    let hostname = ctx.hostname;

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let client = client.clone();
        let relays = Arc::clone(&relays);
        let pool = Arc::clone(&pool);
        let target = target.clone();
        let logger = logger.clone();
        let client_ip = client_ip.to_string();
        let hostname = hostname.clone();

        async move {
            let req_start = Instant::now();
            let (parts, incoming) = req.into_parts();

            // Check for Upgrade: websocket header; if present, return 501 Not Implemented
            if let Some(upgrade) = parts.headers.get(hyper::header::UPGRADE) {
                if upgrade
                    .to_str()
                    .map(|s| {
                        s.split(',')
                            .any(|v| v.trim().eq_ignore_ascii_case("websocket"))
                    })
                    .unwrap_or(false)
                {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_IMPLEMENTED)
                        .body(Full::new(bytes::Bytes::from(
                            "WebSocket is not supported over Vercel relay",
                        )))
                        .unwrap());
                }
            }

            let body_bytes = incoming
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let uri_str = parts.uri.to_string();

            let relay_res = relay_request(
                &client,
                &relays,
                pool.cooldown_secs,
                parts.method,
                &target,
                &uri_str,
                parts.headers,
                body_bytes,
            )
            .await;

            match relay_res {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_headers = resp.headers().clone();
                    let resp_body = resp.bytes().await.unwrap_or_default();

                    logger.record(RequestLogEntry {
                        id: None,
                        timestamp: chrono::Utc::now(),
                        client_ip,
                        pool: pool.name.clone(),
                        upstream: relays
                            .first()
                            .map(|r| r.name())
                            .unwrap_or("unknown")
                            .to_string(),
                        target_host: hostname,
                        is_mitm: true,
                        status_code: status.as_u16() as i32,
                        latency_ms: req_start.elapsed().as_millis() as i64,
                        created_by: "system".to_string(),
                    });

                    let mut builder = Response::builder().status(status);
                    for (k, v) in resp_headers {
                        if let Some(key) = k {
                            builder = builder.header(key, v);
                        }
                    }
                    Ok::<_, hyper::Error>(builder.body(Full::new(resp_body)).unwrap())
                }
                Err(e) => {
                    error!("Relay error: {}", e);
                    logger.record(RequestLogEntry {
                        id: None,
                        timestamp: chrono::Utc::now(),
                        client_ip,
                        pool: pool.name.clone(),
                        upstream: relays
                            .first()
                            .map(|r| r.name())
                            .unwrap_or("unknown")
                            .to_string(),
                        target_host: hostname,
                        is_mitm: true,
                        status_code: 502,
                        latency_ms: req_start.elapsed().as_millis() as i64,
                        created_by: "system".to_string(),
                    });
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(bytes::Bytes::from("Bad Gateway")))
                        .unwrap())
                }
            }
        }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(tls_stream, service)
        .await
    {
        error!("Error serving MITM connection: {}", e);
    }
}
