-- v0.9.0 — per-tenant policies.
-- Single denormalized table keyed by tenant_id (1:1 with tenants). NULL row
-- means "no overrides; system defaults apply".

CREATE TABLE tenant_policies (
    tenant_id            UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- Password policy
    password_min_length  INT NOT NULL DEFAULT 8,
    password_require_upper BOOLEAN NOT NULL DEFAULT false,
    password_require_digit BOOLEAN NOT NULL DEFAULT false,
    password_require_symbol BOOLEAN NOT NULL DEFAULT false,
    -- Email domain allowlist; empty array = any domain allowed
    allowed_email_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- MFA enforcement
    require_mfa          BOOLEAN NOT NULL DEFAULT false,
    -- Session policy
    max_active_sessions  INT NOT NULL DEFAULT 0, -- 0 = unlimited
    -- Bookkeeping
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Permissions become tenant-scoped (NULL = system / global)
ALTER TABLE permissions ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
CREATE INDEX idx_permissions_tenant ON permissions (tenant_id);

-- Drop the old unique constraint on (name) and add a tenant-aware one
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_name_key;
CREATE UNIQUE INDEX permissions_tenant_name_uq ON permissions (COALESCE(tenant_id::text, ''), name);
