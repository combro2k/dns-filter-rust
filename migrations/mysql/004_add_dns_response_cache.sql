-- Add DNS response cache settings to resolver_config
ALTER TABLE resolver_config
    ADD COLUMN dns_cache_enabled TINYINT NOT NULL DEFAULT 1,
    ADD COLUMN dns_cache_min_ttl_seconds INT NULL,
    ADD COLUMN dns_cache_max_ttl_seconds INT NULL;