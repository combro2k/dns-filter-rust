-- Initial schema: operational config tables for dns-filter
-- Backend: SQLite

CREATE TABLE IF NOT EXISTS filter_lists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('block', 'allow')),
    url TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 43200,
    enabled INTEGER NOT NULL DEFAULT 1,
    list_type TEXT NOT NULL DEFAULT 'adguard'
);

CREATE TABLE IF NOT EXISTS filter_cache_documents (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filtering_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    sinkhole_ipv4 TEXT NOT NULL DEFAULT '0.0.0.0',
    sinkhole_ipv6 TEXT NOT NULL DEFAULT '::',
    any_query_policy TEXT NOT NULL DEFAULT 'notimp'
);

CREATE TABLE IF NOT EXISTS resolver_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    strategy TEXT NOT NULL DEFAULT 'round_robin',
    bootstrap_resolvers TEXT NOT NULL DEFAULT '["1.1.1.1"]'
);

CREATE TABLE IF NOT EXISTS upstream_servers (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    protocol TEXT NOT NULL,
    address TEXT NOT NULL,
    auth_token TEXT,
    auth_username TEXT,
    auth_password TEXT,
    max_hops INTEGER,
    nameserver_ip_family TEXT,
    root_hints_path TEXT,
    root_key_path TEXT,
    dnssec INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
    id TEXT PRIMARY KEY,
    zone TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    bypass_filter INTEGER NOT NULL DEFAULT 0,
    fallback_to_default_resolvers INTEGER NOT NULL DEFAULT 0,
    strategy TEXT
);

CREATE TABLE IF NOT EXISTS zone_servers (
    id TEXT PRIMARY KEY,
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    protocol TEXT NOT NULL,
    address TEXT NOT NULL,
    auth_token TEXT,
    auth_username TEXT,
    auth_password TEXT,
    check_interval TEXT,
    max_hops INTEGER,
    nameserver_ip_family TEXT,
    root_hints_path TEXT,
    root_key_path TEXT,
    dnssec INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zone_discovery (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    address TEXT NOT NULL,
    check_interval TEXT,
    allowed_types TEXT NOT NULL DEFAULT '[]',
    bypass_filter INTEGER NOT NULL DEFAULT 0,
    fallback_to_default_resolvers INTEGER NOT NULL DEFAULT 0,
    auth_token TEXT,
    auth_username TEXT,
    auth_password TEXT
);

-- Seed singleton rows so they always exist for UPDATE queries
INSERT OR IGNORE INTO filtering_config (id) VALUES (1);
INSERT OR IGNORE INTO resolver_config (id) VALUES (1);
