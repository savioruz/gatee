use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    Direct,
    Vercel,
    Http,
    Socks5,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStrategy {
    #[serde(rename = "round_robin")]
    RoundRobin,
    #[default]
    Failover,
    Sticky,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamCfg {
    pub name: String,
    pub kind: UpstreamKind,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolCfg {
    pub members: Vec<String>,
    #[serde(default)]
    pub strategy: PoolStrategy,
    #[serde(default)]
    pub mitm_hosts: Vec<String>,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_cooldown() -> u64 {
    30
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_ca_cert")]
    pub ca_cert: String,
    #[serde(default = "default_ca_key")]
    pub ca_key: String,
    #[serde(default)]
    pub upstreams: Vec<UpstreamCfg>,
    #[serde(default)]
    pub pools: HashMap<String, PoolCfg>,
}

fn default_listen() -> String {
    "127.0.0.1:7890".to_string()
}

fn default_ca_cert() -> String {
    "ca.pem".to_string()
}

fn default_ca_key() -> String {
    "ca-key.pem".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            password: String::new(),
            ca_cert: default_ca_cert(),
            ca_key: default_ca_key(),
            upstreams: Vec::new(),
            pools: HashMap::new(),
        }
    }
}
