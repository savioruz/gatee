use gatee_core::GatewayState;
use gatee_storage::{PoolRecord, RequestLogEntry, UpstreamRecord};
use maud::{html, Markup, DOCTYPE};
use std::sync::atomic::Ordering;
use time::OffsetDateTime;

pub fn layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " - Gatee Gateway" }
                script src="https://unpkg.com/htmx.org@1.9.12" {}
                style {
                    "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #f8fafc; }"
                    ".container { max-width: 1100px; margin: 0 auto; }"
                    ".header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }"
                    ".card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; border: 1px solid #334155; }"
                    "table { width: 100%; border-collapse: collapse; text-align: left; }"
                    "th, td { padding: 12px; border-bottom: 1px solid #334155; }"
                    "th { color: #94a3b8; font-size: 13px; text-transform: uppercase; }"
                    ".badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }"
                    ".badge-green { background: #064e3b; color: #34d399; }"
                    ".badge-red { background: #7f1d1d; color: #f87171; }"
                    ".badge-blue { background: #1e3a8a; color: #60a5fa; }"
                    ".badge-gray { background: #334155; color: #94a3b8; }"
                    ".btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }"
                    ".btn:hover { background: #2563eb; }"
                    ".btn-sm { padding: 4px 10px; font-size: 12px; background: #475569; }"
                    ".btn-sm:hover { background: #64748b; }"
                    ".btn-danger { background: #991b1b; }"
                    ".btn-danger:hover { background: #b91c1c; }"
                    ".form-group { margin-bottom: 12px; }"
                    ".form-inline { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; margin-top: 16px; padding-top: 16px; border-top: 1px solid #334155; }"
                    ".input { background: #0f172a; border: 1px solid #475569; color: #f8fafc; padding: 8px 12px; border-radius: 6px; font-size: 14px; outline: none; }"
                    ".input:focus { border-color: #3b82f6; }"
                    "select.input { height: 35px; }"
                    ".text-muted { color: #94a3b8; font-size: 12px; }"
                    ".alert-success { background: #064e3b; color: #34d399; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 13px; }"
                    ".alert-error { background: #7f1d1d; color: #f87171; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 13px; }"
                }
            }
            body {
                div class="container" {
                    div class="header" {
                        div {
                            h1 style="margin:0; font-size: 24px;" { "Gatee Forward Gateway" }
                            p class="text-muted" style="margin: 4px 0 0 0;" { "High-performance modular proxy & dynamic SQLite appliance" }
                        }
                        div {
                            a href="/ca.pem" class="btn" download { "Download CA Cert (ca.pem)" }
                        }
                    }
                    (content)
                }
            }
        }
    }
}

pub fn upstream_row(u: &gatee_core::UpstreamRuntime, now: i64) -> Markup {
    let cooldown = u.remaining_cooldown_secs(now);
    html! {
        tr id=(format!("upstream-{}", u.name())) {
            td { (u.name()) }
            td { (format!("{:?}", u.kind()).to_lowercase()) }
            td {
                @if cooldown > 0 {
                    span class="badge badge-red" { "Cooling (" (cooldown) "s)" }
                } @else {
                    span class="badge badge-green" { "Healthy" }
                }
            }
            td {
                button class="btn btn-sm" hx-post=(format!("/api/cooldown/reset?upstream={}", u.name())) hx-target=(format!("#upstream-{}", u.name())) hx-swap="outerHTML" {
                    "Reset"
                }
            }
        }
    }
}

pub fn upstreams_section(upstreams: &[UpstreamRecord], state: &GatewayState, now: i64) -> Markup {
    html! {
        div class="card" id="upstreams-card" {
            h2 style="margin-top:0;" { "Upstream Nodes" }
            table {
                thead {
                    tr {
                        th { "Name" }
                        th { "Kind" }
                        th { "Target URL" }
                        th { "Status" }
                        th { "Modified" }
                        th { "Actions" }
                    }
                }
                tbody {
                    @for u in upstreams {
                        tr id=(format!("upstream-{}", u.name)) {
                            td { strong { (u.name) } }
                            td { span class="badge badge-blue" { (u.kind) } }
                            td {
                                @if u.url.is_empty() {
                                    span class="text-muted" { "(direct TCP)" }
                                } @else {
                                    code { (u.url) }
                                }
                            }
                            td {
                                @if let Some(runtime) = state.get_upstream(&u.name) {
                                    @let cooldown = runtime.remaining_cooldown_secs(now);
                                    @if cooldown > 0 {
                                        span class="badge badge-red" { "Cooling (" (cooldown) "s)" }
                                    } @else {
                                        span class="badge badge-green" { "Healthy" }
                                    }
                                } @else {
                                    span class="badge badge-gray" { "Inactive" }
                                }
                            }
                            td { span class="text-muted" { (u.modified_at) " (" (u.modified_by) ")" } }
                            td style="display:flex; gap: 8px;" {
                                @if let Some(runtime) = state.get_upstream(&u.name) {
                                    @if runtime.is_down(now) {
                                        button class="btn btn-sm" hx-post=(format!("/api/cooldown/reset?upstream={}", u.name)) hx-target="#upstreams-card" hx-swap="outerHTML" {
                                            "Reset"
                                        }
                                    }
                                }
                                @if u.name != "direct" {
                                    button class="btn btn-sm btn-danger" hx-post=(format!("/api/upstreams/{}/delete", u.name)) hx-target="#upstreams-card" hx-swap="outerHTML" hx-confirm=(format!("Delete upstream '{}'?", u.name)) {
                                        "Delete"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            form class="form-inline" hx-post="/api/upstreams" hx-target="#upstreams-card" hx-swap="outerHTML" {
                div {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Name" }
                    input class="input" type="text" name="name" placeholder="e.g. vercel-relay" required;
                }
                div {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Kind" }
                    select class="input" name="kind" {
                        option value="direct" { "direct" }
                        option value="vercel" { "vercel" }
                        option value="http" { "http" }
                        option value="socks5" { "socks5" }
                    }
                }
                div style="flex: 1;" {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Target URL (empty for direct)" }
                    input class="input" style="width: 100%; box-sizing: border-box;" type="text" name="url" placeholder="https://... or socks5://...";
                }
                div {
                    button class="btn" type="submit" { "+ Add Upstream" }
                }
            }
        }
    }
}

pub fn pools_section(pools: &[PoolRecord], _state: &GatewayState, _now: i64) -> Markup {
    html! {
        div class="card" id="pools-card" {
            h2 style="margin-top:0;" { "Upstream Pools" }
            table {
                thead {
                    tr {
                        th { "Pool Name" }
                        th { "Strategy" }
                        th { "Cooldown" }
                        th { "Members" }
                        th { "MITM Hosts" }
                        th { "Modified" }
                        th { "Actions" }
                    }
                }
                tbody {
                    @for p in pools {
                        tr {
                            td { strong { (p.name) } }
                            td { span class="badge badge-blue" { (p.strategy) } }
                            td { (p.cooldown_secs) "s" }
                            td {
                                @for m in &p.members {
                                    span class="badge badge-gray" style="margin-right: 4px;" { (m) }
                                }
                            }
                            td {
                                @if p.mitm_hosts.is_empty() {
                                    span class="text-muted" { "none (blind)" }
                                } @else {
                                    @for h in &p.mitm_hosts {
                                        code style="margin-right: 4px;" { (h) }
                                    }
                                }
                            }
                            td { span class="text-muted" { (p.modified_at) " (" (p.modified_by) ")" } }
                            td {
                                @if p.name != "default" {
                                    button class="btn btn-sm btn-danger" hx-post=(format!("/api/pools/{}/delete", p.name)) hx-target="#pools-card" hx-swap="outerHTML" hx-confirm=(format!("Delete pool '{}'?", p.name)) {
                                        "Delete"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            form class="form-inline" hx-post="/api/pools" hx-target="#pools-card" hx-swap="outerHTML" {
                div {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Pool Name" }
                    input class="input" type="text" name="name" placeholder="e.g. stealth" required;
                }
                div {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Strategy" }
                    select class="input" name="strategy" {
                        option value="failover" { "failover" }
                        option value="round_robin" { "round_robin" }
                        option value="sticky" { "sticky" }
                    }
                }
                div style="width: 90px;" {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Cooldown (s)" }
                    input class="input" style="width: 100%; box-sizing: border-box;" type="number" name="cooldown_secs" value="30" min="1" required;
                }
                div style="flex: 1;" {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "Members (comma-separated)" }
                    input class="input" style="width: 100%; box-sizing: border-box;" type="text" name="members" placeholder="e.g. direct, vercel-relay" required;
                }
                div style="flex: 1;" {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "MITM Hosts (comma-separated)" }
                    input class="input" style="width: 100%; box-sizing: border-box;" type="text" name="mitm_hosts" placeholder="e.g. *.anthropic.com, api.openai.com";
                }
                div {
                    button class="btn" type="submit" { "+ Add Pool" }
                }
            }
        }
    }
}

pub fn password_card(is_protected: bool, message: Option<&str>) -> Markup {
    html! {
        div class="card" id="password-card" {
            h2 style="margin-top:0;" { "Security Settings" }
            p {
                "Authentication Status: "
                @if is_protected {
                    span class="badge badge-green" { "Protected (Basic Auth Active)" }
                } @else {
                    span class="badge badge-red" { "Open (No Password Configured)" }
                }
            }

            @if let Some(msg) = message {
                div class="alert-success" { (msg) }
            }

            form class="form-inline" hx-post="/api/settings/password" hx-target="#password-card" hx-swap="outerHTML" {
                div style="flex: 1; max-width: 320px;" {
                    label class="text-muted" style="display:block; margin-bottom:4px;" { "New Administrator Password" }
                    input class="input" style="width: 100%; box-sizing: border-box;" type="password" name="password" placeholder="Leave blank to disable auth";
                }
                div {
                    button class="btn" type="submit" { "Update Password" }
                }
            }
        }
    }
}

pub fn logs_table_rows(recent_logs: &[RequestLogEntry]) -> Markup {
    html! {
        @for log in recent_logs {
            tr {
                td { (format!("{:02}:{:02}:{:02}", log.timestamp.hour(), log.timestamp.minute(), log.timestamp.second())) }
                td { code { (log.target_host) } }
                td { (log.pool) }
                td { (log.upstream) }
                td { (log.latency_ms) " ms" }
                td {
                    @if (200..300).contains(&log.status_code) {
                        span class="badge badge-green" { (log.status_code) }
                    } @else {
                        span class="badge badge-red" { (log.status_code) }
                    }
                }
            }
        }
    }
}

pub fn dashboard_page(
    state: &GatewayState,
    upstreams: &[UpstreamRecord],
    pools: &[PoolRecord],
    recent_logs: &[RequestLogEntry],
    password_msg: Option<&str>,
) -> Markup {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let total_reqs = state.total_requests.load(Ordering::Relaxed);
    let is_protected = !state.password().is_empty();

    layout(
        "Dashboard",
        html! {
            div class="card" {
                h2 style="margin-top:0;" { "Gateway Metrics" }
                div style="display:flex; gap: 24px; font-size: 15px;" {
                    div { "Total requests processed: " strong { (total_reqs) } }
                    div { "Active Pools: " strong { (pools.len()) } }
                    div { "Configured Upstreams: " strong { (upstreams.len()) } }
                }
            }

            (upstreams_section(upstreams, state, now))
            (pools_section(pools, state, now))
            (password_card(is_protected, password_msg))

            div class="card" {
                div style="display:flex; justify-content:space-between; align-items:center;" {
                    h2 style="margin:0;" { "Recent Proxy Logs" }
                    span class="text-muted" { "Live auto-refresh every 3s" }
                }
                table style="margin-top: 16px;" {
                    thead {
                        tr {
                            th { "Time" }
                            th { "Target" }
                            th { "Pool" }
                            th { "Upstream" }
                            th { "Latency" }
                            th { "Status" }
                        }
                    }
                    tbody id="logs-tbody" hx-get="/api/logs" hx-trigger="every 3s" hx-swap="innerHTML" {
                        (logs_table_rows(recent_logs))
                    }
                }
            }
        },
    )
}
