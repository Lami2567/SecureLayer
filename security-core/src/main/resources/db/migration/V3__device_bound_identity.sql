ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS certificate_subject TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS public_key_sha256 TEXT NOT NULL DEFAULT '';

ALTER TABLE devices
    ALTER COLUMN credential_hash DROP NOT NULL;

ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS fingerprint_sha256 TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_tenant_fingerprint
    ON certificates (tenant_id, fingerprint_sha256)
    WHERE fingerprint_sha256 <> '';

CREATE INDEX IF NOT EXISTS idx_certificates_device_revoked
    ON certificates (device_id, revoked, not_after DESC);

CREATE INDEX IF NOT EXISTS idx_devices_tenant_state
    ON devices (tenant_id, state);
