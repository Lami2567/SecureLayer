# SecureLayer Security & Cryptographic Specification

## 1. Cryptographic Principles & Primitives

SecureLayer strictly adheres to standard cryptographic engineering principles:
1. **Never Implement Cryptographic Math Manually:** All cryptographic transformations are delegated to vetted, standardized platform engines: OpenSSL (via Node.js and Python) and Bouncy Castle / SunJCE (Java 25).
2. **Authenticated Encryption Only:** Unauthenticated symmetric modes (e.g. CBC without HMAC, ECB, raw CTR) are banned.
3. **Provable Nonce Uniqueness:** Nonces for symmetric encryption must never be repeated under the same key.
4. **Deterministic Digital Signatures:** Asymmetric signing algorithms must eliminate poor RNG vulnerabilities.

### Algorithm Selection Matrix

| Purpose | Algorithm | Standard / RFC | Key / Digest Size | Security Margin | Rationale & Tradeoffs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Symmetric Encryption (AEAD)** | AES-256-GCM | NIST SP 800-38D | 256 bits (Key)<br>96 bits (IV)<br>128 bits (Tag) | 128-bit quantum security | High performance with hardware acceleration (AES-NI). AEAD guarantees confidentiality and integrity in a single pass. |
| **Cryptographic Hashing** | SHA-256 | FIPS PUB 180-4 | 256 bits | 128-bit collision resistance | Universal hardware and language compatibility, collision resistant, well-understood security margins. |
| **Message Authentication** | HMAC-SHA256 | RFC 2104 | 256 bits | 256-bit PRF security | Proven PRF security against extension attacks. |
| **Asymmetric Signatures** | Ed25519 | RFC 8032 | 256 bits (Key)<br>512 bits (Sig) | ~128-bit curve security | Immune to timing attacks; deterministic signature generation (SHA-512) prevents nonce-leak attacks common to ECDSA. |
| **Password Hashing** | Argon2id | RFC 9106 | Variable | Tunable memory & time cost | Winner of Password Hashing Competition. Hybrid memory-hard design resists both GPU and side-channel attacks. |
| **Random Number Generation** | CSPRNG | Platform native | N/A | Full entropy | Platform sources (`/dev/urandom`, Windows `BCryptGenRandom`, `SecureRandom`). |

---

## 2. In-Depth Cryptographic Mechanisms

### 2.1. Confidentiality: AES-256-GCM Authenticated Encryption

AES in Galois/Counter Mode operates over 128-bit blocks using a counter to generate a keystream. The GHASH universal hash function evaluates an authentication tag over both the ciphertext and any Additional Authenticated Data (AAD).

$$\text{Ciphertext} = \text{AES-CTR}_K(\text{IV}, \text{Plaintext})$$
$$\text{AuthTag} = \text{GHASH}_H(\text{AAD} \parallel \text{Ciphertext} \parallel \text{Lengths}) \oplus \text{AES}_K(\text{IV}_0)$$

#### Nonce Reuse Hazard & Prevention
Reusing an IV under the same AES-GCM key allows an adversary to XOR the two ciphertexts, recovering the XOR of the plaintexts:
$$C_1 \oplus C_2 = P_1 \oplus P_2$$
Furthermore, two ciphertexts with identical IVs allow the attacker to solve for the GHASH authentication key $H$, enabling arbitrary forgery of authentication tags for any subsequent message.

**Mitigation in SecureLayer:**
- Every encryption call invokes the platform CSPRNG to produce a freshly generated, cryptographically random 96-bit (12-byte) initialization vector.
- The probability of a collision in 96 bits of random IV under the same key reaches $2^{-32}$ only after approximately $2^{48}$ messages, well beyond the key rotation threshold.
- Keys are rotated before $2^{32}$ invocations.

---

### 2.2. Integrity: SHA-256 Digest Verification

To guarantee that request bodies are not tampered with en route between client and gateway:
1. The client SDK serializes the HTTP body.
2. The client calculates the binary SHA-256 digest and encodes it in Base64:
   $$\text{Digest} = \text{Base64}(\text{SHA-256}(\text{RawBodyBytes}))$$
3. The client attaches this value to the `X-Message-Sha256` HTTP header.
4. The SecureLayer Gateway reads the raw bytes from the socket before deserialization, calculates the SHA-256 digest, and performs a constant-time string comparison against the header.
5. If the comparison fails, the connection is terminated with `HTTP 400 Bad Request` (`REQUEST_INTEGRITY_FAILED`).

---

### 2.3. Non-Repudiation: Ed25519 Digital Signatures

Non-repudiation prevents an actor from claiming that a transaction was forged or modified after submission. SecureLayer achieves this using **Ed25519**:

1. **Key Generation:** Devices generate a private scalar $k \in \mathbb{F}_q$ and public curve point $A = kB$.
2. **Signature Creation:** Senders hash their private key scalar and the canonical message $M$:
   $$r = \text{SHA-512}(h_b, \dots, h_{2b-1}, M)$$
   $$R = rB$$
   $$S = (r + \text{SHA-512}(R, A, M) \cdot s) \pmod \ell$$
   $$\text{Signature} = (R, S)$$
3. **Signature Verification:** The recipient validates the equation:
   $$8SB = 8R + 8 \cdot \text{SHA-512}(R, A, M)A$$
4. **Deterministic Advantage:** Because $r$ is derived deterministically from the private seed and message (rather than an ephemeral random number generator), Ed25519 is completely immune to broken RNG failures that historically compromised Sony PlayStation 3 and Bitcoin ECDSA implementations.

---

## 3. Key & Certificate Management

### 3.1. Key Lifecycle & Envelope Encryption
In SecureLayer, stored secrets (e.g. client secrets, database credentials) are encrypted using **Envelope Encryption**:
- **Data Encryption Keys (DEKs):** Ephemeral 256-bit symmetric keys generated per secret to perform AES-256-GCM encryption.
- **Key Encryption Key (KEK / Master Key):** A high-entropy master key stored in an isolated environment (or KMS) that encrypts the DEKs.

```
                    ┌───────────────────────────┐
                    │  Master Banking Key (KEK) │
                    └─────────────┬─────────────┘
                                  │ Encrypts
                                  ▼
                    ┌───────────────────────────┐
                    │ Encrypted Data Key (eDEK) │
                    └─────────────┬─────────────┘
                                  │ Decrypts in memory
                                  ▼
┌───────────────────────────┐  AES-256-GCM  ┌───────────────────────────┐
│     Sensitive Secret      │◄─────────────►│ Plaintext Data Key (DEK)  │
└───────────────────────────┘               └───────────────────────────┘
```

### 3.2. Device Identity & X.509 Certificate Hierarchy

1. **Proof of Possession (PoP):**
   - When a device registers, it sends its Public Key and Device Identifier.
   - The server issues a cryptographically random challenge string (nonce) with a 60-second expiration.
   - The device signs the challenge with its private key and returns the signature.
   - The server verifies the signature using the supplied public key.
   - **Private keys are never transmitted to the server.**
2. **Certificate Issuance:**
   - Once PoP is verified, the internal CA issues an X.509 v3 certificate with:
     - `Subject: CN=<device-identifier>`
     - `Validity: 90 to 365 days`
     - `KeyUsage: Digital Signature, Key Encipherment`
     - `ExtendedKeyUsage: Client Authentication (1.3.6.1.5.5.7.3.2)`
3. **Revocation & Certificate Rotation:**
   - Administrators can transition a device to `SUSPENDED` or `REVOKED` via the Dashboard or REST API.
   - Revoked certificate serial numbers are added to the Certificate Revocation List (CRL) in PostgreSQL and cached in Redis.
   - Edge gateways check the CRL cache on every authenticated request.

---

## 4. Production Hardening: KMS & HSM Transition

In this prototype and academic reference platform, master encryption keys and the internal CA private key are loaded from secure configuration variables. For enterprise-grade production environments, the following upgrades are recommended:

1. **FIPS 140-2/3 Level 3 Hardware Security Modules (HSMs):**
   - The Root CA private key should reside inside a hardware module (e.g. Thales Luna, AWS CloudHSM, Google Cloud HSM).
   - Certificate signing operations occur inside the HSM boundary; the private key bytes can never be extracted into host RAM.
2. **Cloud KMS Integration:**
   - Replace the static master key with envelope encryption managed by **AWS KMS**, **Google Cloud KMS**, or **Azure Key Vault**.
   - KMS policies enforce IAM constraints, audit logging via CloudTrail, and automated key rotation schedules.
3. **Mutual TLS (mTLS) Termination at Gateway:**
   - Configure edge gateways with client certificate verification directly at the TLS handshake level (RFC 8446), verifying hardware-bound client certificates before HTTP stream processing begins.
