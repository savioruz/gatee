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
            u.validate()?;
            if !upstream_names.insert(u.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate upstream name '{}'",
                    u.name
                )));
            }
        }
        if self.pools.is_empty() {
            return Err(ConfigError::Validation("No pools defined".to_string()));
        }
        for (pool_name, pool) in &self.pools {
            pool.validate(pool_name, |member| upstream_names.contains(member))?;
        }
        Ok(())
    }
}
