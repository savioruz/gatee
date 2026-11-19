use crate::upstream::UpstreamRuntime;
use gatee_config::{PoolCfg, PoolStrategy};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Debug)]
pub struct PoolRuntime {
    pub name: String,
    pub members: Vec<Arc<UpstreamRuntime>>,
    pub strategy: PoolStrategy,
    pub mitm_hosts: HashSet<String>,
    pub cooldown_secs: u64,
    rr_counter: AtomicU64,
}

impl PoolRuntime {
    pub fn new(name: String, cfg: PoolCfg, members: Vec<Arc<UpstreamRuntime>>) -> Self {
        let mitm_hosts = cfg
            .mitm_hosts
            .into_iter()
            .map(|h| h.trim().trim_end_matches('.').to_lowercase())
            .collect();
        Self {
            name,
            members,
            strategy: cfg.strategy,
            mitm_hosts,
            cooldown_secs: cfg.cooldown_secs,
            rr_counter: AtomicU64::new(0),
        }
    }

    pub fn mitms(&self, hostname: &str) -> bool {
        let host_part = if let Some(stripped) = hostname.strip_prefix('[') {
            stripped.split(']').next().unwrap_or(hostname)
        } else {
            hostname.split(':').next().unwrap_or(hostname)
        };
        let normalized = host_part.trim().trim_end_matches('.').to_lowercase();
        self.mitm_hosts.contains(&normalized) || self.mitm_hosts.contains(&hostname.to_lowercase())
    }

    pub fn candidates(&self, sticky_key: &str) -> Vec<Arc<UpstreamRuntime>> {
        let n = self.members.len();
        if n == 0 {
            return Vec::new();
        }

        let start_index = match self.strategy {
            PoolStrategy::RoundRobin => {
                (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % n
            }
            PoolStrategy::Sticky => {
                let hash = fnv32a(sticky_key.as_bytes());
                (hash as usize) % n
            }
            PoolStrategy::Failover => 0,
        };

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut healthy = Vec::with_capacity(n);
        let mut cooling = Vec::with_capacity(n);

        for i in 0..n {
            let u = &self.members[(start_index + i) % n];
            if u.is_down(now) {
                cooling.push(Arc::clone(u));
            } else {
                healthy.push(Arc::clone(u));
            }
        }

        healthy.extend(cooling);
        healthy
    }

    pub fn mark_down(&self, upstream: &UpstreamRuntime) {
        upstream.mark_down(self.cooldown_secs);
    }
}

/// 32-bit FNV-1a hash matching Go standard library `hash/fnv` (fnv.New32a())
pub fn fnv32a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in bytes {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
