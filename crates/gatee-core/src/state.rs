use crate::pool::PoolRuntime;
use crate::upstream::UpstreamRuntime;
use gatee_config::Config;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CoreError {
    #[error("Unknown pool: {0}")]
    PoolNotFound(String),
    #[error("Authentication failed")]
    AuthFailed,
}

#[derive(Debug)]
pub struct GatewayState {
    pub config: Config,
    pub pools: HashMap<String, Arc<PoolRuntime>>,
    pub upstreams: HashMap<String, Arc<UpstreamRuntime>>,
    pub total_requests: AtomicU64,
}

impl GatewayState {
    pub fn new(config: Config) -> Self {
        let mut upstreams = HashMap::new();
        for uc in &config.upstreams {
            upstreams.insert(uc.name.clone(), Arc::new(UpstreamRuntime::new(uc.clone())));
        }

        let mut pools = HashMap::new();
        for (pool_name, pc) in &config.pools {
            let mut members = Vec::new();
            for member_name in &pc.members {
                if let Some(u) = upstreams.get(member_name) {
                    members.push(Arc::clone(u));
                }
            }
            pools.insert(
                pool_name.clone(),
                Arc::new(PoolRuntime::new(pool_name.clone(), pc.clone(), members)),
            );
        }

        Self {
            config,
            pools,
            upstreams,
            total_requests: AtomicU64::new(0),
        }
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(Arc<PoolRuntime>, String), CoreError> {
        if !self.config.password.is_empty() {
            let pass_match: bool = password
                .as_bytes()
                .ct_eq(self.config.password.as_bytes())
                .into();
            if !pass_match {
                return Err(CoreError::AuthFailed);
            }
        }

        let (pool_name, sticky_key) = match username.split_once('~') {
            Some((p, k)) => (if p.is_empty() { "default" } else { p }, k),
            None => (
                if username.is_empty() {
                    "default"
                } else {
                    username
                },
                username,
            ),
        };

        let pool = self
            .pools
            .get(pool_name)
            .ok_or_else(|| CoreError::PoolNotFound(pool_name.to_string()))?;

        let key = if sticky_key.is_empty() {
            pool_name.to_string()
        } else {
            sticky_key.to_string()
        };

        Ok((Arc::clone(pool), key))
    }

    pub fn inc_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }
}
