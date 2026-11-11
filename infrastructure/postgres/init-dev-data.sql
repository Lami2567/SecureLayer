-- SecureLayer Local Development Seed Data
-- Only intended for local demonstration environments.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Tenants Table
CREATE TABLE IF NOT EXISTS security_tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Identities & Roles
CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, username),
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS identity_roles (
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    PRIMARY KEY (identity_id, role)
);

-- 3. Devices
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    device_identifier TEXT NOT NULL,
    credential_hash TEXT,
    state TEXT NOT NULL DEFAULT 'PENDING',
    certificate_subject TEXT NOT NULL DEFAULT '',
    public_key_sha256 TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    UNIQUE (tenant_id, device_identifier)
);

-- 4. Certificates
CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    subject TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    pem_certificate TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, serial_number)
);

-- 4b. Key Materials
CREATE TABLE IF NOT EXISTS key_materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    usage TEXT NOT NULL,
    encrypted_key BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, alias, key_version)
);

-- 5. Applications
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS application_redirect_uris (
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (application_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS application_scopes (
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (application_id, scope)
);

-- 6. Policies
CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES security_tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    document JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);

-- 7. Audit Events
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES security_tenants(id) ON DELETE SET NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL DEFAULT 'SHA-256',
    event_hash BYTEA NOT NULL,
    signature_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
    signature BYTEA,
    outcome TEXT NOT NULL DEFAULT 'RECORDED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- SEED DATA INSERTIONS
-- =========================================================================

-- Insert Demo Tenant
INSERT INTO security_tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'tenant-primary')
ON CONFLICT (id) DO NOTHING;

-- Insert Demo Users
-- Argon2id password hash for 'ChangeMe-Strong-123!'
INSERT INTO identities (id, tenant_id, username, email, password_hash, enabled)
VALUES 
  ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'alice.developer@bank.example.com', 'alice@bank.example.com', '$argon2id$v=19$m=65536,t=3,p=1$7v1b...hash', true),
  ('10000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'admin@securelayer.internal', 'admin@securelayer.internal', '$argon2id$v=19$m=65536,t=3,p=1$7v1b...hash', true),
  ('10000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', 'bob.unauthorized@bank.example.com', 'bob@bank.example.com', '$argon2id$v=19$m=65536,t=3,p=1$7v1b...hash', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO identity_roles (identity_id, role)
VALUES
  ('10000000-0000-0000-0000-000000000001', 'DEVELOPER'),
  ('10000000-0000-0000-0000-000000000001', 'SECURITY_OPERATOR'),
  ('10000000-0000-0000-0000-000000000002', 'SUPER_ADMIN'),
  ('10000000-0000-0000-0000-000000000002', 'ADMIN')
ON CONFLICT (identity_id, role) DO NOTHING;

-- Insert Demo Application (Core Retail Banking Portal)
INSERT INTO applications (id, tenant_id, name, client_id, client_secret_hash, enabled)
VALUES (
  '20000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'Core Retail Banking Portal',
  'banking-app',
  encode(digest('secret-banking-application-key-32chars', 'sha256'), 'hex'),
  true
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO application_redirect_uris (application_id, redirect_uri)
VALUES ('20000000-0000-0000-0000-000000000001', 'https://bank.example.com/oauth/callback')
ON CONFLICT (application_id, redirect_uri) DO NOTHING;

INSERT INTO application_scopes (application_id, scope)
VALUES 
  ('20000000-0000-0000-0000-000000000001', 'accounts:read'),
  ('20000000-0000-0000-0000-000000000001', 'transfers:create'),
  ('20000000-0000-0000-0000-000000000001', 'browser:access')
ON CONFLICT (application_id, scope) DO NOTHING;

-- Insert Demo Devices
-- Device A: Registered & ACTIVE
INSERT INTO devices (id, tenant_id, name, device_identifier, state, certificate_subject, enabled)
VALUES (
  '30000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'Alice Workstation (Device A)',
  'dev-a-active-1001',
  'ACTIVE',
  'CN=dev-a-active-1001',
  true
)
ON CONFLICT (id) DO NOTHING;

-- Device B: Registered but PENDING (Not Approved)
INSERT INTO devices (id, tenant_id, name, device_identifier, state, certificate_subject, enabled)
VALUES (
  '30000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'Bob Mobile Device (Device B)',
  'dev-b-pending-2002',
  'PENDING',
  'CN=dev-b-pending-2002',
  false
)
ON CONFLICT (id) DO NOTHING;

-- Device C: SUSPENDED
INSERT INTO devices (id, tenant_id, name, device_identifier, state, certificate_subject, enabled)
VALUES (
  '30000000-0000-0000-0000-000000000003',
  '00000000-0000-0000-0000-000000000001',
  'Charlie Laptop (Suspended)',
  'dev-c-suspended-3003',
  'SUSPENDED',
  'CN=dev-c-suspended-3003',
  false
)
ON CONFLICT (id) DO NOTHING;

-- Certificate for Device A
INSERT INTO certificates (id, tenant_id, device_id, subject, serial_number, pem_certificate, fingerprint_sha256, not_before, not_after, revoked)
VALUES (
  '40000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  '30000000-0000-0000-0000-000000000001',
  'CN=dev-a-active-1001',
  'SN-DEV-A-001',
  '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIUSN-DEV-A-001...X509CertificateForDeviceA\n-----END CERTIFICATE-----',
  '864a0950ae25ce2215217f4a2e8de9994394d0a2b0342ea459bd772f0a821557',
  now() - interval '1 day',
  now() + interval '365 days',
  false
)
ON CONFLICT (id) DO NOTHING;

-- Insert Banking Policy (Only authenticated users with registered ACTIVE devices may access)
INSERT INTO security_policies (id, tenant_id, name, version, document, active)
VALUES (
  '50000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'banking-policy',
  1,
  '{
    "rules": [
      {
        "name": "Active Device Only",
        "effect": "ALLOW",
        "conditions": {
          "resource": "/banking/**",
          "application": { "approved": true },
          "device": { "registered": true, "active": true },
          "certificate": { "valid": true }
        },
        "reason": "Access allowed: caller is authenticated with registered ACTIVE device and valid certificate."
      },
      {
        "name": "Default Deny Banking",
        "effect": "DENY",
        "conditions": {
          "resource": "/banking/**"
        },
        "reason": "Access denied: caller does not present a registered ACTIVE device."
      }
    ]
  }'::jsonb,
  true
)
ON CONFLICT (id) DO NOTHING;
