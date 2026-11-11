CREATE INDEX IF NOT EXISTS idx_policies_version_lookup
    ON security_policies (tenant_id, name, version);

CREATE INDEX IF NOT EXISTS idx_policies_name_created_at
    ON security_policies (tenant_id, name, created_at DESC);
