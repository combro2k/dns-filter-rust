-- Normalize JSON array columns to proper relational tables.
-- Backend: PostgreSQL

-- 1. Create bootstrap_resolvers table
CREATE TABLE IF NOT EXISTS bootstrap_resolvers (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    sort_order INTEGER NOT NULL DEFAULT 0
);

-- Migrate existing JSON data from resolver_config.bootstrap_resolvers
INSERT INTO bootstrap_resolvers (id, address, sort_order)
SELECT
    gen_random_uuid()::text AS id,
    elem.value AS address,
    elem.ordinality - 1 AS sort_order
FROM resolver_config,
     jsonb_array_elements_text(resolver_config.bootstrap_resolvers::jsonb)
     WITH ORDINALITY AS elem(value, ordinality)
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
    gen_random_uuid()::text AS id,
    zd.id AS zone_discovery_id,
    elem.value AS allowed_type
FROM zone_discovery AS zd,
     jsonb_array_elements_text(zd.allowed_types::jsonb) AS elem(value);

-- 3. Drop old columns
ALTER TABLE resolver_config DROP COLUMN bootstrap_resolvers;
ALTER TABLE zone_discovery DROP COLUMN allowed_types;
