use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use crate::ConfigError;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7890";
pub const DEFAULT_CA_CERT: &str = "ca.pem";
pub const DEFAULT_CA_KEY: &str = "ca-key.pem";
pub const DEFAULT_COOLDOWN_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    Direct,
    Vercel,
    Http,
    Socks5,
}

impl UpstreamKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Vercel => "vercel",
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}

impl fmt::Display for UpstreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for UpstreamKind {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "vercel" => Ok(Self::Vercel),
            "http" => Ok(Self::Http),
            "socks5" => Ok(Self::Socks5),
            other => Err(ConfigError::Validation(format!(
                "Invalid upstream kind '{}'. Supported: direct, vercel, http, socks5",
                other
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStrategy {
    #[serde(rename = "round_robin")]
    RoundRobin,
    #[default]
    Failover,
    Sticky,
}

impl PoolStrategy {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Failover => "failover",
            Self::Sticky => "sticky",
        }
    }
}

impl fmt::Display for PoolStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PoolStrategy {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "round_robin" | "roundrobin" => Ok(Self::RoundRobin),
            "failover" => Ok(Self::Failover),
            "sticky" => Ok(Self::Sticky),
            other => Err(ConfigError::Validation(format!(
                "Invalid pool strategy '{}'. Supported: failover, round_robin, sticky",
                other
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamCfg {
    pub name: String,
    pub kind: UpstreamKind,
    #[serde(default)]
    pub url: String,
}

impl UpstreamCfg {
    pub fn new(name: impl Into<String>, kind: UpstreamKind, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            url: url.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::Validation(
                "Upstream with empty name".to_string(),
            ));
        }
        if self.kind != UpstreamKind::Direct && self.url.trim().is_empty() {
            return Err(ConfigError::Validation(format!(
                "Upstream '{}' requires a valid url",
                self.name
            )));
        }
        Ok(())
    }
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

pub fn default_cooldown() -> u64 {
    DEFAULT_COOLDOWN_SECS
}

impl PoolCfg {
    pub fn new(
        members: Vec<String>,
        strategy: PoolStrategy,
        mitm_hosts: Vec<String>,
        cooldown_secs: u64,
    ) -> Self {
        Self {
            members,
            strategy,
            mitm_hosts,
            cooldown_secs,
        }
    }

    pub fn validate(
        &self,
        pool_name: &str,
        is_valid_upstream: impl Fn(&str) -> bool,
    ) -> Result<(), ConfigError> {
        if self.members.is_empty() {
            return Err(ConfigError::Validation(format!(
                "Pool '{}' has no members",
                pool_name
            )));
        }
        for member in &self.members {
            if !is_valid_upstream(member) {
                return Err(ConfigError::Validation(format!(
                    "Pool '{}' references unknown member '{}'",
                    pool_name, member
                )));
            }
        }
        Ok(())
    }
}

impl Default for PoolCfg {
    fn default() -> Self {
        Self {
            members: Vec::new(),
            strategy: PoolStrategy::default(),
            mitm_hosts: Vec::new(),
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
        }
    }
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

pub fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

pub fn default_ca_cert() -> String {
    DEFAULT_CA_CERT.to_string()
}

pub fn default_ca_key() -> String {
    DEFAULT_CA_KEY.to_string()
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }
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
