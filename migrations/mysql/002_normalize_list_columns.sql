-- Normalize JSON array columns to proper relational tables.
-- Backend: MySQL

-- 1. Create bootstrap_resolvers table
CREATE TABLE IF NOT EXISTS bootstrap_resolvers (
    id VARCHAR(36) PRIMARY KEY,
    address VARCHAR(255) NOT NULL UNIQUE,
    sort_order INT NOT NULL DEFAULT 0
);

-- Migrate existing JSON data from resolver_config.bootstrap_resolvers
INSERT INTO bootstrap_resolvers (id, address, sort_order)
SELECT
    UUID() AS id,
    j.addr AS address,
    j.idx AS sort_order
FROM resolver_config,
     JSON_TABLE(resolver_config.bootstrap_resolvers, '$[*]'
         COLUMNS (
             idx FOR ORDINALITY,
             addr VARCHAR(255) PATH '$'
         )
     ) AS j
WHERE resolver_config.id = 1;

-- 2. Create zone_discovery_allowed_types table
CREATE TABLE IF NOT EXISTS zone_discovery_allowed_types (
    id VARCHAR(36) PRIMARY KEY,
    zone_discovery_id VARCHAR(36) NOT NULL,
    allowed_type VARCHAR(50) NOT NULL,
    UNIQUE(zone_discovery_id, allowed_type),
    FOREIGN KEY (zone_discovery_id) REFERENCES zone_discovery(id) ON DELETE CASCADE
);

-- Migrate existing JSON data from zone_discovery.allowed_types
INSERT INTO zone_discovery_allowed_types (id, zone_discovery_id, allowed_type)
SELECT
    UUID() AS id,
    zd.id AS zone_discovery_id,
    j.atype AS allowed_type
FROM zone_discovery AS zd,
     JSON_TABLE(zd.allowed_types, '$[*]'
         COLUMNS (
             atype VARCHAR(50) PATH '$'
         )
     ) AS j;

-- 3. Drop old columns
ALTER TABLE resolver_config DROP COLUMN bootstrap_resolvers;
ALTER TABLE zone_discovery DROP COLUMN allowed_types;
