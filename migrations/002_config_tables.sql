CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT 'system',
    modified_by TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS upstreams (
    name TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT 'system',
    modified_by TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS pools (
    name TEXT PRIMARY KEY,
    strategy TEXT NOT NULL DEFAULT 'failover',
    cooldown_secs INTEGER NOT NULL DEFAULT 30,
    mitm_hosts TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT 'system',
    modified_by TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS pool_members (
    pool_name TEXT NOT NULL,
    upstream_name TEXT NOT NULL,
    priority_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT 'system',
    modified_by TEXT NOT NULL DEFAULT 'system',
    PRIMARY KEY (pool_name, upstream_name),
    FOREIGN KEY (pool_name) REFERENCES pools(name) ON DELETE CASCADE,
    FOREIGN KEY (upstream_name) REFERENCES upstreams(name) ON DELETE RESTRICT
);

CREATE TRIGGER IF NOT EXISTS trg_settings_modified_at
AFTER UPDATE ON settings
FOR EACH ROW
WHEN OLD.modified_at = NEW.modified_at
BEGIN
    UPDATE settings SET modified_at = CURRENT_TIMESTAMP WHERE key = OLD.key;
END;

CREATE TRIGGER IF NOT EXISTS trg_upstreams_modified_at
AFTER UPDATE ON upstreams
FOR EACH ROW
WHEN OLD.modified_at = NEW.modified_at
BEGIN
    UPDATE upstreams SET modified_at = CURRENT_TIMESTAMP WHERE name = OLD.name;
END;

CREATE TRIGGER IF NOT EXISTS trg_pools_modified_at
AFTER UPDATE ON pools
FOR EACH ROW
WHEN OLD.modified_at = NEW.modified_at
BEGIN
    UPDATE pools SET modified_at = CURRENT_TIMESTAMP WHERE name = OLD.name;
END;

CREATE TRIGGER IF NOT EXISTS trg_pool_members_modified_at
AFTER UPDATE ON pool_members
FOR EACH ROW
WHEN OLD.modified_at = NEW.modified_at
BEGIN
    UPDATE pool_members SET modified_at = CURRENT_TIMESTAMP 
    WHERE pool_name = OLD.pool_name AND upstream_name = OLD.upstream_name;
END;
