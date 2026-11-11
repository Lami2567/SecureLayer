# SecureLayer Architecture

SecureLayer separates central policy and identity decisions from application-local enforcement.

## Control Plane

The control plane owns:

- Tenant and policy metadata.
- OAuth 2.1 / OpenID Connect resource server configuration.
- Public key and certificate metadata.
- Audit event intake and verification.
- SDK and data-plane bootstrap APIs.

The initial implementation is the `gateway` Spring Boot service.

## Data Plane

The data plane is embedded into applications through language SDKs, browser extension code, and future sidecar or gateway integrations.

Data-plane enforcement should:

- Fetch signed policy material from the control plane.
- Validate policy integrity before use.
- Use AEAD encryption for confidential payloads.
- Sign security-relevant actions where non-repudiation is required.
- Submit audit records with hashes and signatures.

## Cryptography

Approved primitives for the current platform baseline:

- AES-256-GCM for authenticated encryption.
- SHA-256 for digest generation.
- Ed25519 for detached digital signatures.
- TLS 1.3 for transport security.
- X.509 certificates for service identity and trust distribution.

Cryptographic operations must use established libraries and platform cryptographic APIs. Application code must not implement custom ciphers, signature algorithms, padding, random number generators, or certificate parsers.

## Persistence

PostgreSQL stores tenant, policy, and audit metadata. Redis is reserved for short-lived control-plane state such as policy cache entries, nonce tracking, and rate-limit counters.

## Operational Model

All service configuration is environment-driven. Secrets must come from a secret manager, Docker secret, Kubernetes secret, or equivalent production mechanism.

Logs are emitted as structured JSON and include a correlation ID when requests enter the gateway.

