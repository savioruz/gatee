use chrono::Utc;
use gatee_core::{GatewayState, UpstreamRuntime};
use gatee_storage::RequestLogEntry;
use maud::{html, Markup, DOCTYPE};
use std::sync::atomic::Ordering;

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
                    ".btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }"
                    ".btn:hover { background: #2563eb; }"
                    ".btn-sm { padding: 4px 10px; font-size: 12px; background: #475569; }"
                    ".btn-sm:hover { background: #64748b; }"
                }
            }
            body {
                div class="container" {
                    div class="header" {
                        h1 style="margin:0; font-size: 24px;" { "Gatee Forward Gateway" }
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

pub fn upstream_row(u: &UpstreamRuntime, now: i64) -> Markup {
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

pub fn dashboard_page(state: &GatewayState, recent_logs: &[RequestLogEntry]) -> Markup {
    let now = Utc::now().timestamp();
    let total_reqs = state.total_requests.load(Ordering::Relaxed);

    let mut pools: Vec<_> = state.pools.iter().collect();
    pools.sort_by_key(|(name, _)| *name);

    layout(
        "Dashboard",
        html! {
            div class="card" {
                h2 style="margin-top:0;" { "Gateway Metrics" }
                p { "Total requests processed: " strong { (total_reqs) } }
            }

            div class="card" {
                h2 style="margin-top:0;" { "Upstream Pools" }
                table {
                    thead {
                        tr {
                            th { "Pool Name" }
                            th { "Strategy" }
                            th { "Members" }
                        }
                    }
                    tbody {
                        @for (pool_name, pool) in pools {
                            tr {
                                td { strong { (pool_name) } }
                                td { (format!("{:?}", pool.strategy).to_lowercase()) }
                                td {
                                    table {
                                        @for u in &pool.members {
                                            (upstream_row(u, now))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div class="card" {
                h2 style="margin-top:0;" { "Recent Proxy Logs" }
                table {
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
                    tbody {
                        @for log in recent_logs {
                            tr {
                                td { (log.timestamp.format("%H:%M:%S").to_string()) }
                                td { (log.target_host) }
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
            }
        },
    )
}
