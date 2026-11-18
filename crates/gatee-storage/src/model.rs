use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn default_created_by() -> String {
    "system".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: Option<i64>,
    #[serde(alias = "created_at")]
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub pool: String,
    pub upstream: String,
    pub target_host: String,
    pub is_mitm: bool,
    pub status_code: i32,
    pub latency_ms: i64,
    #[serde(default = "default_created_by")]
    pub created_by: String,
}

impl RequestLogEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_ip: String,
        pool: String,
        upstream: String,
        target_host: String,
        is_mitm: bool,
        status_code: i32,
        latency_ms: i64,
    ) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            client_ip,
            pool,
            upstream,
            target_host,
            is_mitm,
            status_code,
            latency_ms,
            created_by: "system".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamRecord {
    pub name: String,
    pub kind: String,
    pub url: String,
    pub created_at: String,
    pub modified_at: String,
    pub created_by: String,
    pub modified_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolRecord {
    pub name: String,
    pub strategy: String,
    pub cooldown_secs: u64,
    pub mitm_hosts: Vec<String>,
    pub members: Vec<String>,
    pub created_at: String,
    pub modified_at: String,
    pub created_by: String,
    pub modified_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettingRecord {
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub modified_at: String,
    pub created_by: String,
    pub modified_by: String,
}
