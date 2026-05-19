-- Initial schema: operational config tables for dns-filter
-- Backend: PostgreSQL

CREATE TABLE IF NOT EXISTS filter_lists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('block', 'allow')),
    url TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 43200,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
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
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    protocol TEXT NOT NULL,
    address TEXT NOT NULL,
    auth_token TEXT,
    auth_username TEXT,
    auth_password TEXT,
    max_hops INTEGER,
    nameserver_ip_family TEXT,
    root_hints_path TEXT,
    root_key_path TEXT,
    dnssec BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
    id TEXT PRIMARY KEY,
    zone TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    bypass_filter BOOLEAN NOT NULL DEFAULT FALSE,
    fallback_to_default_resolvers BOOLEAN NOT NULL DEFAULT FALSE,
    strategy TEXT
);

CREATE TABLE IF NOT EXISTS zone_servers (
    id TEXT PRIMARY KEY,
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
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
    dnssec BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zone_discovery (
    id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    address TEXT NOT NULL,
    check_interval TEXT,
    allowed_types TEXT NOT NULL DEFAULT '[]',
    bypass_filter BOOLEAN NOT NULL DEFAULT FALSE,
    fallback_to_default_resolvers BOOLEAN NOT NULL DEFAULT FALSE,
    auth_token TEXT,
    auth_username TEXT,
    auth_password TEXT
);

-- Seed singleton rows
INSERT INTO filtering_config (id) VALUES (1) ON CONFLICT DO NOTHING;
INSERT INTO resolver_config (id) VALUES (1) ON CONFLICT DO NOTHING;
