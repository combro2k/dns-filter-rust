-- Add outbound routing columns to upstream_servers
ALTER TABLE upstream_servers ADD COLUMN bind_address TEXT DEFAULT NULL;
ALTER TABLE upstream_servers ADD COLUMN fwmark INTEGER DEFAULT NULL;
