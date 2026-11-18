use crate::auth::require_basic_auth;
use crate::views::{dashboard_page, upstream_row};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use gatee_ca::CertificateAuthority;
use gatee_core::GatewayState;
use gatee_storage::Storage;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppContext {
    pub state: Arc<GatewayState>,
    pub storage: Storage,
    pub ca: Arc<CertificateAuthority>,
}

#[derive(Deserialize)]
pub struct ResetQuery {
    pub upstream: String,
}

pub fn build_web_router(
    state: Arc<GatewayState>,
    storage: Storage,
    ca: Arc<CertificateAuthority>,
) -> Router {
    let password = state.config.password.clone();
    let ctx = AppContext { state, storage, ca };

    Router::new()
        .route("/", get(dashboard_handler))
        .route("/ca.pem", get(ca_cert_handler))
        .route("/api/cooldown/reset", post(reset_cooldown_handler))
        .layer(middleware::from_fn(move |req, next| {
            require_basic_auth(password.clone(), req, next)
        }))
        .with_state(ctx)
}

async fn dashboard_handler(State(ctx): State<AppContext>) -> Html<String> {
    let recent_logs = ctx.storage.fetch_recent_logs(20).await.unwrap_or_default();
    Html(dashboard_page(&ctx.state, &recent_logs).into_string())
}

async fn ca_cert_handler(State(ctx): State<AppContext>) -> impl IntoResponse {
    let pem = ctx.ca.cert_pem();
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"ca.pem\"",
            ),
        ],
        pem.to_string(),
    )
}

async fn reset_cooldown_handler(
    State(ctx): State<AppContext>,
    Query(query): Query<ResetQuery>,
) -> Response {
    if let Some(u) = ctx.state.upstreams.get(&query.upstream) {
        u.reset_cooldown();
        let markup = upstream_row(u, chrono::Utc::now().timestamp());
        Html(markup.into_string()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
