-- Add DNS response cache settings to resolver_config
ALTER TABLE resolver_config ADD COLUMN dns_cache_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE resolver_config ADD COLUMN dns_cache_min_ttl_seconds INTEGER;
ALTER TABLE resolver_config ADD COLUMN dns_cache_max_ttl_seconds INTEGER;