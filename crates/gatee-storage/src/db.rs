use gatee_config::{Config, PoolCfg, PoolStrategy, UpstreamCfg, UpstreamKind};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

use crate::model::{PoolRecord, RequestLogEntry, SettingRecord, UpstreamRecord};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Db(#[from] libsql::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Configuration error: {0}")]
    Config(#[from] gatee_config::ConfigError),
}

#[derive(Clone)]
pub struct Storage {
    conn: libsql::Connection,
}

impl Storage {
    pub async fn new_in_memory() -> Result<Self, StorageError> {
        let db = libsql::Builder::new_local(":memory:").build().await?;
        let conn = db.connect()?;
        let storage = Self { conn };
        storage.migrate().await?;
        storage.ensure_seeded(None).await?;
        Ok(storage)
    }

    pub async fn new_from_path(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let db = libsql::Builder::new_local(p).build().await?;
        let conn = db.connect()?;
        let storage = Self { conn };
        storage.migrate().await?;
        storage.ensure_seeded(None).await?;
        Ok(storage)
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        self.conn.execute("PRAGMA foreign_keys = ON;", ()).await?;
        const MIGRATION_001: &str = include_str!("../../../migrations/001_init_gatee.sql");
        const MIGRATION_002: &str = include_str!("../../../migrations/002_config_tables.sql");
        self.conn.execute_batch(MIGRATION_001).await?;
        self.conn.execute_batch(MIGRATION_002).await?;
        Ok(())
    }

    pub async fn ensure_seeded(&self, initial_password: Option<&str>) -> Result<(), StorageError> {
        let mut rows = self
            .conn
            .query("SELECT COUNT(*) FROM upstreams", ())
            .await?;
        let count: i64 = if let Some(row) = rows.next().await? {
            row.get(0)?
        } else {
            0
        };

        if count == 0 {
            // Seed default direct upstream
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO upstreams (name, kind, url, created_by, modified_by)
                     VALUES ('direct', 'direct', '', 'system', 'system')",
                    (),
                )
                .await?;

            // Seed default failover pool
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO pools (name, strategy, cooldown_secs, mitm_hosts, created_by, modified_by)
                     VALUES ('default', 'failover', 30, '[]', 'system', 'system')",
                    (),
                )
                .await?;

            // Seed pool member
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO pool_members (pool_name, upstream_name, priority_order, created_by, modified_by)
                     VALUES ('default', 'direct', 0, 'system', 'system')",
                    (),
                )
                .await?;
        }

        if let Some(password) = initial_password {
            if !password.is_empty() {
                let existing = self.get_setting("password").await?;
                if existing.is_none() {
                    self.set_setting("password", password, "system").await?;
                }
            }
        }

        Ok(())
    }

    // --- Request Logs ---

    pub async fn insert_log(&self, entry: &RequestLogEntry) -> Result<(), StorageError> {
        let created_by = if entry.created_by.is_empty() {
            "system"
        } else {
            &entry.created_by
        };

        let ts_str = entry
            .timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        self.conn
            .execute(
                "INSERT INTO request_logs (created_at, client_ip, pool, upstream, target_host, is_mitm, status_code, latency_ms, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                libsql::params![
                    ts_str,
                    entry.client_ip.clone(),
                    entry.pool.clone(),
                    entry.upstream.clone(),
                    entry.target_host.clone(),
                    if entry.is_mitm { 1 } else { 0 },
                    entry.status_code,
                    entry.latency_ms,
                    created_by,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn fetch_recent_logs(
        &self,
        limit: usize,
    ) -> Result<Vec<RequestLogEntry>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, created_at, client_ip, pool, upstream, target_host, is_mitm, status_code, latency_ms, created_by
                 FROM request_logs ORDER BY id DESC LIMIT ?1",
                libsql::params![limit as i64],
            )
            .await?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            let ts_str: String = row.get(1)?;
            let ts = time::OffsetDateTime::parse(
                &ts_str,
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc());

            results.push(RequestLogEntry {
                id: Some(row.get(0)?),
                timestamp: ts,
                client_ip: row.get(2)?,
                pool: row.get(3)?,
                upstream: row.get(4)?,
                target_host: row.get(5)?,
                is_mitm: row.get::<i64>(6)? != 0,
                status_code: row.get::<i64>(7)? as i32,
                latency_ms: row.get(8)?,
                created_by: row.get(9)?,
            });
        }
        Ok(results)
    }

    // --- Upstreams CRUD ---

    pub async fn list_upstreams(&self) -> Result<Vec<UpstreamRecord>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, kind, url, created_at, modified_at, created_by, modified_by
                 FROM upstreams ORDER BY name ASC",
                (),
            )
            .await?;

        let mut list = Vec::new();
        while let Some(row) = rows.next().await? {
            list.push(UpstreamRecord {
                name: row.get(0)?,
                kind: row.get(1)?,
                url: row.get(2)?,
                created_at: row.get(3)?,
                modified_at: row.get(4)?,
                created_by: row.get(5)?,
                modified_by: row.get(6)?,
            });
        }
        Ok(list)
    }

    pub async fn get_upstream(&self, name: &str) -> Result<Option<UpstreamRecord>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, kind, url, created_at, modified_at, created_by, modified_by
                 FROM upstreams WHERE name = ?1",
                libsql::params![name],
            )
            .await?;

        if let Some(row) = rows.next().await? {
            Ok(Some(UpstreamRecord {
                name: row.get(0)?,
                kind: row.get(1)?,
                url: row.get(2)?,
                created_at: row.get(3)?,
                modified_at: row.get(4)?,
                created_by: row.get(5)?,
                modified_by: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn upsert_upstream(
        &self,
        name: &str,
        kind: &str,
        url: &str,
        actor: &str,
    ) -> Result<(), StorageError> {
        let kind_enum = UpstreamKind::from_str(kind)?;
        let cfg = UpstreamCfg::new(name, kind_enum, url);
        cfg.validate()?;

        self.conn
            .execute(
                "INSERT INTO upstreams (name, kind, url, created_by, modified_by)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(name) DO UPDATE SET
                     kind = excluded.kind,
                     url = excluded.url,
                     modified_by = excluded.modified_by",
                libsql::params![cfg.name, cfg.kind.as_str(), cfg.url, actor],
            )
            .await?;
        Ok(())
    }

    pub async fn delete_upstream(&self, name: &str) -> Result<(), StorageError> {
        // Enforce FK check: check if any pool references this upstream
        let mut rows = self
            .conn
            .query(
                "SELECT pool_name FROM pool_members WHERE upstream_name = ?1 LIMIT 1",
                libsql::params![name],
            )
            .await?;

        if let Some(row) = rows.next().await? {
            let pool_name: String = row.get(0)?;
            return Err(StorageError::Validation(format!(
                "Cannot delete upstream '{}': referenced by pool '{}'",
                name, pool_name
            )));
        }

        self.conn
            .execute(
                "DELETE FROM upstreams WHERE name = ?1",
                libsql::params![name],
            )
            .await?;
        Ok(())
    }

    // --- Pools CRUD ---

    pub async fn list_pools(&self) -> Result<Vec<PoolRecord>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, strategy, cooldown_secs, mitm_hosts, created_at, modified_at, created_by, modified_by
                 FROM pools ORDER BY name ASC",
                (),
            )
            .await?;

        let mut pools = Vec::new();
        while let Some(row) = rows.next().await? {
            let pool_name: String = row.get(0)?;
            let strategy: String = row.get(1)?;
            let cooldown_secs: i64 = row.get(2)?;
            let mitm_hosts_raw: String = row.get(3)?;
            let mitm_hosts: Vec<String> = serde_json::from_str(&mitm_hosts_raw).unwrap_or_default();
            let created_at: String = row.get(4)?;
            let modified_at: String = row.get(5)?;
            let created_by: String = row.get(6)?;
            let modified_by: String = row.get(7)?;

            let mut member_rows = self
                .conn
                .query(
                    "SELECT upstream_name FROM pool_members WHERE pool_name = ?1 ORDER BY priority_order ASC",
                    libsql::params![pool_name.clone()],
                )
                .await?;

            let mut members = Vec::new();
            while let Some(mrow) = member_rows.next().await? {
                members.push(mrow.get(0)?);
            }

            pools.push(PoolRecord {
                name: pool_name,
                strategy,
                cooldown_secs: cooldown_secs as u64,
                mitm_hosts,
                members,
                created_at,
                modified_at,
                created_by,
                modified_by,
            });
        }
        Ok(pools)
    }

    pub async fn get_pool(&self, name: &str) -> Result<Option<PoolRecord>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, strategy, cooldown_secs, mitm_hosts, created_at, modified_at, created_by, modified_by
                 FROM pools WHERE name = ?1",
                libsql::params![name],
            )
            .await?;

        if let Some(row) = rows.next().await? {
            let pool_name: String = row.get(0)?;
            let strategy: String = row.get(1)?;
            let cooldown_secs: i64 = row.get(2)?;
            let mitm_hosts_raw: String = row.get(3)?;
            let mitm_hosts: Vec<String> = serde_json::from_str(&mitm_hosts_raw).unwrap_or_default();
            let created_at: String = row.get(4)?;
            let modified_at: String = row.get(5)?;
            let created_by: String = row.get(6)?;
            let modified_by: String = row.get(7)?;

            let mut member_rows = self
                .conn
                .query(
                    "SELECT upstream_name FROM pool_members WHERE pool_name = ?1 ORDER BY priority_order ASC",
                    libsql::params![pool_name.clone()],
                )
                .await?;

            let mut members = Vec::new();
            while let Some(mrow) = member_rows.next().await? {
                members.push(mrow.get(0)?);
            }

            Ok(Some(PoolRecord {
                name: pool_name,
                strategy,
                cooldown_secs: cooldown_secs as u64,
                mitm_hosts,
                members,
                created_at,
                modified_at,
                created_by,
                modified_by,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn upsert_pool(&self, pool: &PoolRecord, actor: &str) -> Result<(), StorageError> {
        let strat_enum = PoolStrategy::from_str(&pool.strategy)?;
        let pool_cfg = PoolCfg::new(
            pool.members.clone(),
            strat_enum,
            pool.mitm_hosts.clone(),
            pool.cooldown_secs,
        );

        // Validate all members exist in upstreams
        let upstreams = self.list_upstreams().await?;
        let valid_set: std::collections::HashSet<String> =
            upstreams.into_iter().map(|u| u.name).collect();

        pool_cfg.validate(&pool.name, |m| valid_set.contains(m))?;

        let mitm_hosts_json = serde_json::to_string(&pool.mitm_hosts)?;

        // Execute pool insert/update
        self.conn
            .execute(
                "INSERT INTO pools (name, strategy, cooldown_secs, mitm_hosts, created_by, modified_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(name) DO UPDATE SET
                     strategy = excluded.strategy,
                     cooldown_secs = excluded.cooldown_secs,
                     mitm_hosts = excluded.mitm_hosts,
                     modified_by = excluded.modified_by",
                libsql::params![
                    pool.name.clone(),
                    pool_cfg.strategy.as_str(),
                    pool.cooldown_secs as i64,
                    mitm_hosts_json,
                    actor,
                ],
            )
            .await?;

        // Replace members
        self.conn
            .execute(
                "DELETE FROM pool_members WHERE pool_name = ?1",
                libsql::params![pool.name.clone()],
            )
            .await?;

        for (idx, member) in pool.members.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT INTO pool_members (pool_name, upstream_name, priority_order, created_by, modified_by)
                     VALUES (?1, ?2, ?3, ?4, ?4)",
                    libsql::params![pool.name.clone(), member.clone(), idx as i64, actor],
                )
                .await?;
        }

        Ok(())
    }

    pub async fn delete_pool(&self, name: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM pools WHERE name = ?1", libsql::params![name])
            .await?;
        Ok(())
    }

    // --- Settings KV ---

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT value FROM settings WHERE key = ?1",
                libsql::params![key],
            )
            .await?;

        if let Some(row) = rows.next().await? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub async fn set_setting(
        &self,
        key: &str,
        value: &str,
        actor: &str,
    ) -> Result<(), StorageError> {
        self.conn
            .execute(
                "INSERT INTO settings (key, value, created_by, modified_by)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     modified_by = excluded.modified_by",
                libsql::params![key, value, actor],
            )
            .await?;
        Ok(())
    }

    pub async fn list_settings(&self) -> Result<Vec<SettingRecord>, StorageError> {
        let mut rows = self
            .conn
            .query(
                "SELECT key, value, created_at, modified_at, created_by, modified_by FROM settings ORDER BY key ASC",
                (),
            )
            .await?;

        let mut list = Vec::new();
        while let Some(row) = rows.next().await? {
            list.push(SettingRecord {
                key: row.get(0)?,
                value: row.get(1)?,
                created_at: row.get(2)?,
                modified_at: row.get(3)?,
                created_by: row.get(4)?,
                modified_by: row.get(5)?,
            });
        }
        Ok(list)
    }

    // --- Load Full Config ---

    pub async fn load_full_config(&self) -> Result<Config, StorageError> {
        let upstream_records = self.list_upstreams().await?;
        let pool_records = self.list_pools().await?;
        let password = self.get_setting("password").await?.unwrap_or_default();

        let mut upstreams = Vec::new();
        for ur in upstream_records {
            let kind = UpstreamKind::from_str(&ur.kind)?;
            upstreams.push(UpstreamCfg::new(ur.name, kind, ur.url));
        }

        let mut pools = HashMap::new();
        for pr in pool_records {
            let strategy = PoolStrategy::from_str(&pr.strategy)?;
            pools.insert(
                pr.name,
                PoolCfg::new(pr.members, strategy, pr.mitm_hosts, pr.cooldown_secs),
            );
        }

        let mut cfg = Config::new();
        cfg.password = password;
        cfg.upstreams = upstreams;
        cfg.pools = pools;
        cfg.validate()?;

        Ok(cfg)
    }
}
