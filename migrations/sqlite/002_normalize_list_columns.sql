-- Normalize JSON array columns to proper relational tables.
-- Backend: SQLite

-- 1. Create bootstrap_resolvers table
CREATE TABLE IF NOT EXISTS bootstrap_resolvers (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    sort_order INTEGER NOT NULL DEFAULT 0
);

-- Migrate existing JSON data from resolver_config.bootstrap_resolvers
INSERT INTO bootstrap_resolvers (id, address, sort_order)
SELECT
    lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' ||
          substr(hex(randomblob(2)),2) || '-' ||
          substr('89ab', abs(random()) % 4 + 1, 1) ||
          substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))) AS id,
    j.value AS address,
    j.key AS sort_order
FROM resolver_config, json_each(resolver_config.bootstrap_resolvers) AS j
WHERE resolver_config.id = 1;

-- 2. Create zone_discovery_allowed_types table
CREATE TABLE IF NOT EXISTS zone_discovery_allowed_types (
    id TEXT PRIMARY KEY,
    zone_discovery_id TEXT NOT NULL REFERENCES zone_discovery(id) ON DELETE CASCADE,
    allowed_type TEXT NOT NULL,
    UNIQUE(zone_discovery_id, allowed_type)
);

-- Migrate existing JSON data from zone_discovery.allowed_types
INSERT INTO zone_discovery_allowed_types (id, zone_discovery_id, allowed_type)
SELECT
    lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' ||
          substr(hex(randomblob(2)),2) || '-' ||
          substr('89ab', abs(random()) % 4 + 1, 1) ||
          substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))) AS id,
    zd.id AS zone_discovery_id,
    j.value AS allowed_type
FROM zone_discovery AS zd, json_each(zd.allowed_types) AS j;

-- 3. Drop old columns
ALTER TABLE resolver_config DROP COLUMN bootstrap_resolvers;
ALTER TABLE zone_discovery DROP COLUMN allowed_types;
