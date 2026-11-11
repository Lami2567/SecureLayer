# SecureLayer Cryptographic Architecture & Security Goals

SecureLayer implements a defense-in-depth cryptographic foundation using established algorithms and platform security providers. Custom cryptographic algorithm implementations are strictly prohibited.

---

## 1. Security Goals to Cryptographic Mechanisms Mapping

| Security Goal | Cryptographic Mechanism | Implementation Location | Description |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | **AES-256-GCM** | `BouncyCastleCryptoEngine.encryptAes256Gcm` / Polyglot SDKs | Symmetric authenticated encryption with 256-bit keys, random 96-bit nonces, and 128-bit authentication tags. Encrypts payload content so unauthorized parties cannot read it. |
| **Integrity** | **SHA-256** & **HMAC-SHA256** | `BouncyCastleCryptoEngine.sha256`, `hmacSha256`, `verifyHmacSha256` | SHA-256 generates deterministic cryptographic digests for request bodies (`X-Message-Sha256`), preventing payload tampering. HMAC-SHA256 verifies message authenticity and integrity using shared symmetric keys. |
| **Authentication** | **OAuth 2.1 / OIDC** & **X.509 Certificates** | `SecurityConfig`, `CertificateAuthorityService`, `DeviceAuthenticationService` | OAuth 2.1 / OpenID Connect validates caller identities and role grants (`SUPER_ADMIN`, `ADMIN`, `DEVELOPER`, `SECURITY_OPERATOR`, `DEVICE`). X.509 certificates validate and authenticate physical/browser devices before allowing access. |
| **Non-Repudiation** | **Ed25519 Signatures** & **Signed Audit Logs** | `BouncyCastleCryptoEngine.signEd25519`, `verifyEd25519`, `AuditGrpcService` | Detached Edwards-curve digital signatures (Ed25519) cryptographically bind actions to specific private keys. Callers cannot deny authoring transactions once signed. Audit trails persist event hashes and Ed25519 signatures. |

---

## 2. Protection Against Cryptographic Attacks

### A. Nonce Reuse Protection (`NONCE_REUSE_DETECTED`)
- **Mechanism**: [`NonceRegistry`](../security-core/src/main/java/com/securelayer/core/crypto/NonceRegistry.java) tracks used nonces for each `(keyId, keyVersion)` combination with a configurable TTL.
- **Enforcement**: If a generated 96-bit nonce has already been observed or reserved, encryption is halted or regenerated up to 4 attempts. If unresolvable, returns `CryptoResult.failure(NONCE_REUSE_DETECTED, "Unable to reserve a unique AES-GCM nonce")`.

### B. Tampered Ciphertext Protection (`TAMPERED_CIPHERTEXT`)
- **Mechanism**: AES-GCM provides Authenticated Encryption with Associated Data (AEAD). The 16-byte GCM authentication tag authenticates the ciphertext, nonce, and any associated data (AAD).
- **Enforcement**: Any bit modification to the ciphertext, tag, or AAD causes GCM verification to fail immediately, returning `CryptoResult.failure(TAMPERED_CIPHERTEXT, "Ciphertext, nonce, key, or associated data failed authentication")`.

### C. Invalid Signatures (`INVALID_SIGNATURE`)
- **Mechanism**: Constant-time Ed25519 verification (`crypto.verifyEd25519`).
- **Enforcement**: Any alteration of the message or signature bytes returns `CryptoResult.failure(INVALID_SIGNATURE, "Ed25519 signature verification failed")`.

### D. Invalid Keys (`INVALID_KEY`)
- **Mechanism**: Key validation verifies exact key size (32 bytes / 256 bits for AES-256, minimum 32 bytes for HMAC-SHA256) and key identifier / version matching.
- **Enforcement**: Returns `CryptoResult.failure(INVALID_KEY, "...")` before any cryptographic transform is attempted.

### E. Expired Credentials (`EXPIRED_CREDENTIAL`)
- **Mechanism**: Keys and certificates carry `expiresAt` (`notAfter`) timestamps compared against a high-resolution UTC clock.
- **Enforcement**: Returns `CryptoResult.failure(EXPIRED_CREDENTIAL, "Credential has expired")`.

### F. Replayed Requests (`REPLAYED_REQUEST`)
- **Mechanism**: [`ReplayProtector`](../security-core/src/main/java/com/securelayer/core/crypto/ReplayProtector.java) maintains request identifiers with issuance timestamps, validating against maximum clock skew (5 minutes) and replay cache TTL (10 minutes).
- **Enforcement**: Repeated request IDs return `CryptoResult.failure(REPLAYED_REQUEST, "Request identifier has already been processed")`.

---

## 3. Key Lifecycle & Key Rotation

- **Key Generation**: 
  - AES-256 keys generated via `SecureRandom` through Bouncy Castle providers (`CryptoEngine.generateAes256Key`).
  - Ed25519 key pairs generated via standard RFC 8032 curves (`CryptoEngine.generateEd25519KeyPair`).
- **Key Rotation**:
  - `CryptoEngine.rotateAes256Key(currentKey, newExpiry)` advances key version (`version + 1`) and issues fresh 256-bit entropy without discarding the previous key descriptor until migration completes.
- **Encrypted Key Storage**:
  - Master Key Encryption Service (`KeyEncryptionService`) encrypts private key material at rest using AES-256-GCM before database persistence. No plaintext private keys are ever stored.

---

## 4. Structured Error Handling: `CryptoResult<T>`

Every operation across the cryptographic engine returns a typed `CryptoResult<T>`:
```java
public record CryptoResult<T>(boolean success, T value, CryptoError error)
```

With defined error codes in `CryptoErrorCode`:
- `INVALID_KEY`
- `INVALID_NONCE`
- `NONCE_REUSE_DETECTED`
- `TAMPERED_CIPHERTEXT`
- `INVALID_SIGNATURE`
- `INTEGRITY_CHECK_FAILED`
- `EXPIRED_CREDENTIAL`
- `REPLAYED_REQUEST`
- `INVALID_REQUEST`
- `PROVIDER_FAILURE`
