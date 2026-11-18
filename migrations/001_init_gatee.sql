CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_ip TEXT NOT NULL,
    pool TEXT NOT NULL,
    upstream TEXT NOT NULL,
    target_host TEXT NOT NULL,
    is_mitm INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_pool ON request_logs(pool);

CREATE TABLE IF NOT EXISTS upstream_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    upstream_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_upstream_events_upstream ON upstream_events(upstream_name);
