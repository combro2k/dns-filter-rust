-- Initial schema: operational config tables for dns-filter
-- Backend: MySQL

CREATE TABLE IF NOT EXISTS filter_lists (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    kind VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    interval_seconds INT NOT NULL DEFAULT 43200,
    enabled TINYINT NOT NULL DEFAULT 1,
    list_type VARCHAR(50) NOT NULL DEFAULT 'adguard'
);

CREATE TABLE IF NOT EXISTS filter_cache_documents (
    `key` VARCHAR(255) PRIMARY KEY,
    value LONGTEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filtering_config (
    id INT PRIMARY KEY,
    sinkhole_ipv4 VARCHAR(45) NOT NULL DEFAULT '0.0.0.0',
    sinkhole_ipv6 VARCHAR(45) NOT NULL DEFAULT '::',
    any_query_policy VARCHAR(50) NOT NULL DEFAULT 'notimp'
);

CREATE TABLE IF NOT EXISTS resolver_config (
    id INT PRIMARY KEY,
    strategy VARCHAR(50) NOT NULL DEFAULT 'round_robin',
    bootstrap_resolvers TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upstream_servers (
    id VARCHAR(36) PRIMARY KEY,
    enabled TINYINT NOT NULL DEFAULT 1,
    protocol VARCHAR(50) NOT NULL,
    address TEXT NOT NULL,
    auth_token TEXT,
    auth_username VARCHAR(255),
    auth_password VARCHAR(255),
    max_hops INT,
    nameserver_ip_family VARCHAR(10),
    root_hints_path TEXT,
    root_key_path TEXT,
    dnssec TINYINT NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
    id VARCHAR(36) PRIMARY KEY,
    zone VARCHAR(255) NOT NULL UNIQUE,
    enabled TINYINT NOT NULL DEFAULT 1,
    bypass_filter TINYINT NOT NULL DEFAULT 0,
    fallback_to_default_resolvers TINYINT NOT NULL DEFAULT 0,
    strategy VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS zone_servers (
    id VARCHAR(36) PRIMARY KEY,
    zone_id VARCHAR(36) NOT NULL,
    enabled TINYINT NOT NULL DEFAULT 1,
    protocol VARCHAR(50) NOT NULL,
    address TEXT NOT NULL,
    auth_token TEXT,
    auth_username VARCHAR(255),
    auth_password VARCHAR(255),
    check_interval VARCHAR(50),
    max_hops INT,
    nameserver_ip_family VARCHAR(10),
    root_hints_path TEXT,
    root_key_path TEXT,
    dnssec TINYINT NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0,
    FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS zone_discovery (
    id VARCHAR(36) PRIMARY KEY,
    enabled TINYINT NOT NULL DEFAULT 1,
    address TEXT NOT NULL,
    check_interval VARCHAR(50),
    allowed_types TEXT NOT NULL,
    bypass_filter TINYINT NOT NULL DEFAULT 0,
    fallback_to_default_resolvers TINYINT NOT NULL DEFAULT 0,
    auth_token TEXT,
    auth_username VARCHAR(255),
    auth_password VARCHAR(255)
);

-- Seed singleton rows
INSERT IGNORE INTO filtering_config (id, sinkhole_ipv4, sinkhole_ipv6, any_query_policy) VALUES (1, '0.0.0.0', '::', 'notimp');
INSERT IGNORE INTO resolver_config (id, strategy, bootstrap_resolvers) VALUES (1, 'round_robin', '["1.1.1.1"]');
