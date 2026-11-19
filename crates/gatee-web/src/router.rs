use crate::auth::require_basic_auth;
use crate::views::{
    dashboard_page, logs_table_rows, password_card, pools_section, upstreams_section,
};
use axum::{
    extract::{Form, Path, Query, State},
    http::{header, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use gatee_ca::CertificateAuthority;
use gatee_core::GatewayState;
use gatee_storage::{PoolRecord, Storage};
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

#[derive(Deserialize)]
pub struct AddUpstreamForm {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Deserialize)]
pub struct AddPoolForm {
    pub name: String,
    pub strategy: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    pub members: String,
    #[serde(default)]
    pub mitm_hosts: String,
}

fn default_cooldown() -> u64 {
    30
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    #[serde(default)]
    pub password: String,
}

pub fn build_web_router(
    state: Arc<GatewayState>,
    storage: Storage,
    ca: Arc<CertificateAuthority>,
) -> Router {
    let auth_state = Arc::clone(&state);
    let ctx = AppContext { state, storage, ca };

    Router::new()
        .route("/", get(dashboard_handler))
        .route("/ca.pem", get(ca_cert_handler))
        .route("/api/logs", get(logs_handler))
        .route("/api/cooldown/reset", post(reset_cooldown_handler))
        .route("/api/upstreams", post(add_upstream_handler))
        .route(
            "/api/upstreams/{name}/delete",
            post(delete_upstream_handler),
        )
        .route("/api/pools", post(add_pool_handler))
        .route("/api/pools/{name}/delete", post(delete_pool_handler))
        .route("/api/settings/password", post(change_password_handler))
        .layer(middleware::from_fn(move |req, next| {
            let password = auth_state.password();
            require_basic_auth(password, req, next)
        }))
        .with_state(ctx)
}

async fn dashboard_handler(State(ctx): State<AppContext>) -> Html<String> {
    let upstreams = ctx.storage.list_upstreams().await.unwrap_or_default();
    let pools = ctx.storage.list_pools().await.unwrap_or_default();
    let recent_logs = ctx.storage.fetch_recent_logs(20).await.unwrap_or_default();
    Html(dashboard_page(&ctx.state, &upstreams, &pools, &recent_logs, None).into_string())
}

async fn logs_handler(State(ctx): State<AppContext>) -> Html<String> {
    let recent_logs = ctx.storage.fetch_recent_logs(20).await.unwrap_or_default();
    Html(logs_table_rows(&recent_logs).into_string())
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
    if let Some(u) = ctx.state.get_upstream(&query.upstream) {
        u.reset_cooldown();
        let markup = crate::views::upstream_row(&u, chrono::Utc::now().timestamp());
        Html(markup.into_string()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn add_upstream_handler(
    State(ctx): State<AppContext>,
    Form(form): Form<AddUpstreamForm>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = ctx
        .storage
        .upsert_upstream(form.name.trim(), form.kind.trim(), form.url.trim(), "admin")
        .await
    {
        return (
            StatusCode::BAD_REQUEST,
            Html(format!("<div class='alert-error'>Error: {}</div>", e)),
        )
            .into_response();
    }
    let _ = ctx.state.reload_from_storage().await;
    let upstreams = ctx.storage.list_upstreams().await.unwrap_or_default();
    Html(upstreams_section(&upstreams, &ctx.state, now).into_string()).into_response()
}

async fn delete_upstream_handler(
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = ctx.storage.delete_upstream(&name).await {
        return (
            StatusCode::BAD_REQUEST,
            Html(format!("<div class='alert-error'>Error: {}</div>", e)),
        )
            .into_response();
    }
    let _ = ctx.state.reload_from_storage().await;
    let upstreams = ctx.storage.list_upstreams().await.unwrap_or_default();
    Html(upstreams_section(&upstreams, &ctx.state, now).into_string()).into_response()
}

async fn add_pool_handler(
    State(ctx): State<AppContext>,
    Form(form): Form<AddPoolForm>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    let members: Vec<String> = form
        .members
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mitm_hosts: Vec<String> = form
        .mitm_hosts
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let pool_rec = PoolRecord {
        name: form.name.trim().to_string(),
        strategy: form.strategy.trim().to_string(),
        cooldown_secs: form.cooldown_secs,
        mitm_hosts,
        members,
        created_at: String::new(),
        modified_at: String::new(),
        created_by: "admin".to_string(),
        modified_by: "admin".to_string(),
    };

    if let Err(e) = ctx.storage.upsert_pool(&pool_rec, "admin").await {
        return (
            StatusCode::BAD_REQUEST,
            Html(format!("<div class='alert-error'>Error: {}</div>", e)),
        )
            .into_response();
    }

    let _ = ctx.state.reload_from_storage().await;
    let pools = ctx.storage.list_pools().await.unwrap_or_default();
    Html(pools_section(&pools, &ctx.state, now).into_string()).into_response()
}

async fn delete_pool_handler(
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = ctx.storage.delete_pool(&name).await {
        return (
            StatusCode::BAD_REQUEST,
            Html(format!("<div class='alert-error'>Error: {}</div>", e)),
        )
            .into_response();
    }

    let _ = ctx.state.reload_from_storage().await;
    let pools = ctx.storage.list_pools().await.unwrap_or_default();
    Html(pools_section(&pools, &ctx.state, now).into_string()).into_response()
}

async fn change_password_handler(
    State(ctx): State<AppContext>,
    Form(form): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let new_pwd = form.password.trim();
    let _ = ctx.storage.set_setting("password", new_pwd, "admin").await;
    let _ = ctx.state.reload_from_storage().await;
    let is_protected = !new_pwd.is_empty();
    Html(
        password_card(
            is_protected,
            Some("Administrator password updated successfully!"),
        )
        .into_string(),
    )
    .into_response()
}
