use std::path::Path;
use thiserror::Error;

pub mod model;
pub use model::*;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl Config {
    pub fn from_json_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.upstreams.is_empty() {
            return Err(ConfigError::Validation("No upstreams defined".to_string()));
        }
        let mut upstream_names = std::collections::HashSet::new();
        for u in &self.upstreams {
            if u.name.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "Upstream with empty name".to_string(),
                ));
            }
            if !upstream_names.insert(&u.name) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate upstream name '{}'",
                    u.name
                )));
            }
            if u.kind != UpstreamKind::Direct && u.url.trim().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Upstream '{}' requires a valid url",
                    u.name
                )));
            }
        }
        if self.pools.is_empty() {
            return Err(ConfigError::Validation("No pools defined".to_string()));
        }
        for (pool_name, pool) in &self.pools {
            if pool.members.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Pool '{}' has no members",
                    pool_name
                )));
            }
            for member in &pool.members {
                if !upstream_names.contains(&member) {
                    return Err(ConfigError::Validation(format!(
                        "Pool '{}' references unknown member '{}'",
                        pool_name, member
                    )));
                }
            }
        }
        Ok(())
    }
}
