DROP INDEX IF EXISTS permissions_tenant_name_uq;
DROP INDEX IF EXISTS idx_permissions_tenant;
ALTER TABLE permissions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE permissions ADD CONSTRAINT permissions_name_key UNIQUE (name);
DROP TABLE IF EXISTS tenant_policies;
