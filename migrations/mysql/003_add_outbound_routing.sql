-- Add outbound routing columns to upstream_servers
ALTER TABLE upstream_servers ADD COLUMN bind_address VARCHAR(45) DEFAULT NULL;
ALTER TABLE upstream_servers ADD COLUMN fwmark INT DEFAULT NULL;
