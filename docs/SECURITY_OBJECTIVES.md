# SecureLayer Security Objectives & Cryptographic Architecture

## 1. Executive Overview

SecureLayer is a zero-trust enterprise security platform designed to enforce fine-grained access control, end-to-end payload confidentiality, cryptographic integrity, device-bound identity, and strict non-repudiation across distributed applications and microservices.

Rather than relying on perimeter defenses, unverified bearer tokens, or implicit network trust, SecureLayer treats every access request as untrusted until cryptographically verified across identity, device state, message authenticity, and policy compliance.

---

## 2. Core Security Taxonomy: Clear Distinctions

A fundamental failure mode in enterprise security architectures is conflating distinct security primitives. SecureLayer strictly delineates between the following five core security domains:

| Objective | Fundamental Question | SecureLayer Mechanism | Failure Mode Prevented |
| :--- | :--- | :--- | :--- |
| **Authentication** | *"Who are you?"* | OAuth 2.1 JWT (Argon2id password hashing) & Device X.509 Certificates (mTLS / Proof-of-Possession) | Credential stuffing, spoofed device identity, session theft |
| **Authorization** | *"What are you allowed to do?"* | Centralized Policy Engine evaluating RBAC, ABAC, device state (`ACTIVE`), and contextual attributes (Default: **DENY**) | Privilege escalation, unauthorized resource access, insider abuse |
| **Confidentiality** | *"Who can read this payload?"* | AES-256-GCM Authenticated Encryption (128-bit random IV, unique per message) | Eavesdropping, network sniffing, storage disclosure |
| **Integrity** | *"Has this message been altered in transit?"* | SHA-256 cryptographic digests & HMAC-SHA256 headers (`X-Message-Sha256`) | Man-in-the-middle tampering, parameter manipulation, byte corruption |
| **Non-Repudiation** | *"Can the sender deny having executed this action?"* | Ed25519 asymmetric digital signatures on business payloads + tamper-evident audit ledger | Repudiation of financial transfers, fraudulent transactions, denied administrative actions |

---

## 3. Deep Dive: Implementation of the Four Security Objectives

### 3.1. Confidentiality (AES-256-GCM)

**Objective:** Ensure that data in transit and sensitive records at rest are inaccessible to unauthorized entities, intermediate proxies, or eavesdroppers.

* **Cipher:** Advanced Encryption Standard in Galois/Counter Mode (`AES-256-GCM`).
* **Key Size:** 256 bits (32 bytes), providing defense against brute-force and classical quantum attacks (Grover's algorithm leaves 128-bit security margin).
* **Initialization Vector (Nonce):**
  * Cryptographically secure 96-bit (12-byte) random nonce generated using platform CSPRNGs (`crypto.randomBytes`, `os.urandom`, or `SecureRandom`).
  * **Strict Nonce Reuse Protection:** Each encryption operation generates a fresh nonce. Reusing an IV with the same AES-GCM key catastrophically leaks the authentication subkey $H$, destroying integrity protection. Nonces are prepended or packaged alongside ciphertext payloads.
* **Authenticated Data (AEAD):**
  * Produces a 128-bit (16-byte) authentication tag.
  * Ensures ciphertext and associated authenticated data (AAD) cannot be altered without failing decryption.
* **Cross-Language Interoperability:**
  * Byte-level compatibility verified across Node.js (`crypto.createCipheriv`), Python (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`), and Java 25 (`javax.crypto.Cipher` with `GCMParameterSpec(128, iv)`).

---

### 3.2. Integrity (SHA-256 & HMAC-SHA256)

**Objective:** Guarantee that messages, configuration policies, and security events cannot be modified unnoticed by any intermediary.

* **Digest Algorithm:** `SHA-256` (FIPS PUB 180-4), yielding a 256-bit hash.
* **Message Integrity Header:** Every protected request carries `X-Message-Sha256`, encoding the Base64 representation of the SHA-256 digest of the request body.
* **Gateway & Service Enforcement:**
  * The SecureLayer Gateway and Upstream Banking API compute the cryptographic hash of the received raw bytes independently:
    $$\text{Computed Digest} = \text{Base64}(\text{SHA-256}(\text{Raw Payload Body}))$$
  * If `Header Digest` $\neq$ `Computed Digest`, the request is immediately aborted with `HTTP 400 Bad Request` (`REQUEST_INTEGRITY_FAILED`).
  * No upstream business logic or database queries execute on corrupted or tampered payloads.
* **Tamper-Evident Audit Logging:**
  * Each audit event calculates its deterministic record hash:
    $$\text{EventHash} = \text{SHA-256}(\text{TenantId} \parallel \text{Subject} \parallel \text{Action} \parallel \text{Resource} \parallel \text{Timestamp})$$
  * Event hashes form an append-only verification trail stored in PostgreSQL and cached in Redis.

---

### 3.3. Authentication (User & Device-Bound Identity)

**Objective:** Cryptographically establish and verify the claimed identity of both the human actor and the physical/virtual device executing the transaction.

#### A. User Identity
* Passwords stored with **Argon2id** (memory-hard, resistant to GPU/ASIC cracking).
* Authenticated sessions issue short-lived OAuth 2.1 JWTs bearing standard claims (`sub`, `iss`, `aud`, `exp`, `roles`, `scope`).

#### B. Device-Bound Identity
* **Asymmetric Key Pairs:** Client devices generate asymmetric key pairs locally on secure hardware (Secure Enclave / TPM / Web Crypto isolated storage).
* **Proof of Possession (PoP):** Private keys **never** leave the client device or travel over the network. The server verifies a digital signature over a server-issued challenge nonce to prove possession of the private key during registration.
* **X.509 Device Certificates:**
  * Security Core acts as an internal Certificate Authority (CA) issuing X.509 v3 device certificates.
  * Certificate fields include Subject (`CN=<device-id>`), Validity Period, Serial Number, and SHA-256 Public Key Thumbprint.
* **Device Lifecycle States:**
  * `PENDING`: Device registered but awaiting security administrator approval. Requests are blocked.
  * `ACTIVE`: Fully approved, valid certificate, allowed to submit policy requests.
  * `SUSPENDED`: Temporarily deactivated by administrator. All requests are denied immediately.
  * `REVOKED`: Permanently decommissioned or compromised. Certificate placed on CRL.

---

### 3.4. Non-Repudiation (Ed25519 Digital Signatures)

**Objective:** Ensure that an authorized entity cannot deny the authenticity, origination, or commitment of a performed operation or financial transaction.

* **Signature Scheme:** **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519 using SHA-512).
* **Why Ed25519?**
  * Immune to side-channel timing attacks (constant-time execution).
  * High-performance verification and compact 64-byte signatures.
  * Deterministic signing eliminates vulnerability to poor RNG state during signature generation (unlike ECDSA nonce reuse which leaked Sony PS3 private keys).
* **Transaction Signing Workflow:**
  1. Client creates transaction: `{"transferId": "TX-100", "amount": 50000, "to": "ACC-BOB"}`.
  2. Device signs canonical JSON payload using its private Ed25519 key:
     $$\sigma = \text{Sign}_{K_{\text{device}}}(\text{CanonicalPayload})$$
  3. Signature transmitted in `X-Transaction-Signature` header.
  4. Upstream Banking API verifies signature against registered device public key.
  5. If valid, transaction commits and an immutable audit event records:
     $$\{\text{TransactionId}, \sigma, \text{DeviceId}, \text{Timestamp}\}$$
  6. Any post-signing tampering of either the payload or the signature triggers immediate rejection (`SIGNATURE_VERIFICATION_FAILED`).

---

## 4. Policy Enforcement: Default DENY Architecture

SecureLayer follows the Principle of Least Privilege. By default, access is **DENY**.

### Policy Decision Matrix

```
                          ┌───────────────────────────┐
                          │    Incoming API Request   │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │   Valid Message Digest?   │─── NO ──► HTTP 400 (INTEGRITY FAILED)
                          └─────────────┬─────────────┘
                                        │ YES
                                        ▼
                          ┌───────────────────────────┐
                          │ Authenticated User Token? │─── NO ──► HTTP 401 (UNAUTHORIZED)
                          └─────────────┬─────────────┘
                                        │ YES
                                        ▼
                          ┌───────────────────────────┐
                          │ Valid Device Certificate? │─── NO ──► HTTP 403 (CERTIFICATE DENIED)
                          └─────────────┬─────────────┘
                                        │ YES
                                        ▼
                          ┌───────────────────────────┐
                          │   Device State == ACTIVE? │─── NO ──► HTTP 403 (POLICY DENIED)
                          └─────────────┬─────────────┘
                                        │ YES
                                        ▼
                          ┌───────────────────────────┐
                          │ Application Approved &    │─── NO ──► HTTP 403 (POLICY DENIED)
                          │   Resource Allowed?       │
                          └─────────────┬─────────────┘
                                        │ YES
                                        ▼
                          ┌───────────────────────────┐
                          │  Forward to Banking Core  │──► HTTP 200 (ALLOWED)
                          └───────────────────────────┘
```

---

## 5. Local Docker Demonstration Environment

The demonstration environment simulates a complete enterprise retail banking infrastructure running across 7 orchestrated containers.

### Container Service Topology

| Service | Container Name | Port | Description |
| :--- | :--- | :--- | :--- |
| `postgres` | `securelayer-postgres` | `5432` | Relational store for tenants, devices, certificates, policies, and audit logs. Initialized with dev seed data. |
| `redis` | `securelayer-redis` | `6379` | In-memory cache for fast session lookup and audit event caching. |
| `security-core` | `securelayer-security-core` | `8090`, `9090` | Java 25 / Spring Boot control plane and gRPC server. Manages identities, CAs, policy evaluation. |
| `gateway` | `securelayer-gateway` | `8080` | Stateless reverse proxy enforcing message integrity, device validation, and policy checks before routing. |
| `dashboard` | `securelayer-dashboard` | `3000` | Next.js cybersecurity developer console displaying real-time audit logs, devices, and policies. |
| `demo-node-app` | `securelayer-demo-node-app` | `3001` | Protected Banking API verifying SHA-256 integrity, Ed25519 signatures, and AES-256-GCM confidential records. |
| `demo-python-app`| `securelayer-demo-python-app`| `3002` | Python 3.12 verification client demonstrating cross-SDK cryptographic interoperability. |

### Single-Command Startup

```bash
docker compose up --build
```

### Automated Scenario Verification

To run the full end-to-end integration scenario (matching the Docker services):

```bash
npm run test:e2e
```
Or execute the automated scenario on the running banking node service:
```bash
curl -X POST http://localhost:3001/demo/scenario
```
Or run the Python verification suite:
```bash
curl -X POST http://localhost:3002/demo/run
```
