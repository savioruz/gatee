use arc_swap::ArcSwap;
use gatee_config::Config;
use gatee_storage::Storage;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::pool::PoolRuntime;
use crate::upstream::UpstreamRuntime;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Unknown pool: {0}")]
    PoolNotFound(String),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Storage error: {0}")]
    Storage(#[from] gatee_storage::StorageError),
}

impl PartialEq for CoreError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::PoolNotFound(a), Self::PoolNotFound(b)) => a == b,
            (Self::AuthFailed, Self::AuthFailed) => true,
            _ => false,
        }
    }
}

impl Eq for CoreError {}

#[derive(Debug, Clone)]
pub struct RouterState {
    pub password: String,
    pub pools: HashMap<String, Arc<PoolRuntime>>,
    pub upstreams: HashMap<String, Arc<UpstreamRuntime>>,
}

impl RouterState {
    pub fn from_config(config: &Config) -> Self {
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
            password: config.password.clone(),
            pools,
            upstreams,
        }
    }
}

pub struct GatewayState {
    pub router: ArcSwap<RouterState>,
    pub total_requests: AtomicU64,
    pub storage: Storage,
}

impl GatewayState {
    pub fn new(config: Config, storage: Storage) -> Self {
        let router_state = RouterState::from_config(&config);
        Self {
            router: ArcSwap::from_pointee(router_state),
            total_requests: AtomicU64::new(0),
            storage,
        }
    }

    pub async fn new_with_storage(storage: Storage) -> Result<Self, CoreError> {
        let config = storage.load_full_config().await?;
        Ok(Self::new(config, storage))
    }

    pub fn router(&self) -> arc_swap::Guard<Arc<RouterState>> {
        self.router.load()
    }

    pub fn password(&self) -> String {
        self.router.load().password.clone()
    }

    pub fn pools(&self) -> HashMap<String, Arc<PoolRuntime>> {
        self.router.load().pools.clone()
    }

    pub fn upstreams(&self) -> HashMap<String, Arc<UpstreamRuntime>> {
        self.router.load().upstreams.clone()
    }

    pub fn get_pool(&self, name: &str) -> Option<Arc<PoolRuntime>> {
        self.router.load().pools.get(name).cloned()
    }

    pub fn get_upstream(&self, name: &str) -> Option<Arc<UpstreamRuntime>> {
        self.router.load().upstreams.get(name).cloned()
    }

    pub async fn reload_from_storage(&self) -> Result<(), CoreError> {
        let new_config = self.storage.load_full_config().await?;
        let current_router = self.router.load();

        // Build upstreams while preserving existing cooldowns for unchanged nodes
        let mut new_upstreams = HashMap::new();
        for uc in &new_config.upstreams {
            if let Some(existing) = current_router.upstreams.get(&uc.name) {
                if existing.config().kind == uc.kind && existing.config().url == uc.url {
                    // Reuse existing runtime to retain active cooldown timestamp
                    new_upstreams.insert(uc.name.clone(), Arc::clone(existing));
                    continue;
                }
            }
            new_upstreams.insert(uc.name.clone(), Arc::new(UpstreamRuntime::new(uc.clone())));
        }

        // Build pools with resolved members
        let mut new_pools = HashMap::new();
        for (pool_name, pc) in &new_config.pools {
            let mut members = Vec::new();
            for member_name in &pc.members {
                if let Some(u) = new_upstreams.get(member_name) {
                    members.push(Arc::clone(u));
                }
            }
            new_pools.insert(
                pool_name.clone(),
                Arc::new(PoolRuntime::new(pool_name.clone(), pc.clone(), members)),
            );
        }

        let new_router = RouterState {
            password: new_config.password,
            pools: new_pools,
            upstreams: new_upstreams,
        };

        self.router.store(Arc::new(new_router));
        Ok(())
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(Arc<PoolRuntime>, String), CoreError> {
        let router = self.router.load();
        if !router.password.is_empty() {
            let pass_match: bool = password.as_bytes().ct_eq(router.password.as_bytes()).into();
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

        let pool = router
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
