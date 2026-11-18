use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Db(#[from] libsql::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub pool: String,
    pub upstream: String,
    pub target_host: String,
    pub is_mitm: bool,
    pub status_code: i32,
    pub latency_ms: i64,
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
        Ok(storage)
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        const MIGRATION_001: &str = include_str!("../../../migrations/001_init_gatee.sql");
        for stmt in MIGRATION_001.split(';') {
            let trimmed = stmt.trim();
            if !trimmed.is_empty() {
                self.conn.execute(trimmed, ()).await?;
            }
        }
        Ok(())
    }

    pub async fn insert_log(&self, entry: &RequestLogEntry) -> Result<(), StorageError> {
        self.conn
            .execute(
                "INSERT INTO request_logs (timestamp, client_ip, pool, upstream, target_host, is_mitm, status_code, latency_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                libsql::params![
                    entry.timestamp.to_rfc3339(),
                    entry.client_ip.clone(),
                    entry.pool.clone(),
                    entry.upstream.clone(),
                    entry.target_host.clone(),
                    if entry.is_mitm { 1 } else { 0 },
                    entry.status_code,
                    entry.latency_ms,
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
                "SELECT id, timestamp, client_ip, pool, upstream, target_host, is_mitm, status_code, latency_ms
                 FROM request_logs ORDER BY id DESC LIMIT ?1",
                libsql::params![limit as i64],
            )
            .await?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            let ts_str: String = row.get(1)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

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
            });
        }
        Ok(results)
    }
}
