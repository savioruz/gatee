use crate::db::{RequestLogEntry, Storage};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::error;

#[derive(Clone)]
pub struct LogEmitter {
    sender: mpsc::Sender<RequestLogEntry>,
}

impl LogEmitter {
    pub fn new(storage: Storage, buffer: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<RequestLogEntry>(buffer);
        let storage = Arc::new(storage);

        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if let Err(e) = storage.insert_log(&entry).await {
                    error!("Failed to write request log to database: {}", e);
                }
            }
        });

        Self { sender: tx }
    }

    pub fn record(&self, entry: RequestLogEntry) {
        if let Err(e) = self.sender.try_send(entry) {
            tracing::warn!("Request log dropped: {}", e);
        }
    }
}
