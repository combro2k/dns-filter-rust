-- Add DNS response cache settings to resolver_config
ALTER TABLE resolver_config ADD COLUMN dns_cache_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE resolver_config ADD COLUMN dns_cache_min_ttl_seconds INTEGER DEFAULT NULL;
ALTER TABLE resolver_config ADD COLUMN dns_cache_max_ttl_seconds INTEGER DEFAULT NULL;