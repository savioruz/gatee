use chrono::Utc;
use gatee_config::{UpstreamCfg, UpstreamKind};
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Debug)]
pub struct UpstreamRuntime {
    pub cfg: UpstreamCfg,
    pub down_until: AtomicI64, // Unix timestamp in seconds
}

impl UpstreamRuntime {
    pub fn new(cfg: UpstreamCfg) -> Self {
        Self {
            cfg,
            down_until: AtomicI64::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    pub fn kind(&self) -> &UpstreamKind {
        &self.cfg.kind
    }

    pub fn url(&self) -> &str {
        &self.cfg.url
    }

    pub fn config(&self) -> &UpstreamCfg {
        &self.cfg
    }

    pub fn is_down(&self, now_sec: i64) -> bool {
        self.down_until.load(Ordering::Relaxed) > now_sec
    }

    pub fn is_down_now(&self) -> bool {
        self.is_down(Utc::now().timestamp())
    }

    pub fn mark_down(&self, cooldown_secs: u64) {
        let until = Utc::now().timestamp() + cooldown_secs as i64;
        self.down_until.store(until, Ordering::Relaxed);
    }

    pub fn reset_cooldown(&self) {
        self.down_until.store(0, Ordering::Relaxed);
    }

    pub fn remaining_cooldown_secs(&self, now_sec: i64) -> u64 {
        let until = self.down_until.load(Ordering::Relaxed);
        if until > now_sec {
            (until - now_sec) as u64
        } else {
            0
        }
    }
}
