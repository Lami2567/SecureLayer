# SecureLayer Cryptographic Engine

The cryptographic engine lives in `security-core` under `com.securelayer.core.crypto`.
It uses Java Cryptography Architecture providers and Bouncy Castle where appropriate.
SecureLayer does not implement cryptographic algorithms manually.

## SDK Protocol Surface

SDKs should model engine calls around the same structured result contract:

- `CryptoResult<T>` returns either a value or a `CryptoError`.
- `CryptoErrorCode` identifies security-relevant failures such as `INVALID_KEY`, `TAMPERED_CIPHERTEXT`, `INVALID_SIGNATURE`, `EXPIRED_CREDENTIAL`, and `REPLAYED_REQUEST`.
- `AesGcmEncryptedMessage` carries `keyId`, `keyVersion`, `nonce`, `ciphertext`, and `associatedData`.
- `KeyMaterialRef` carries key identity, version, encoded key material, and optional expiry.

## Mechanisms And Security Properties

| Security property | Mechanism | Notes |
| --- | --- | --- |
| Confidentiality | AES-256-GCM | Encrypts payloads with 256-bit AES keys and a 96-bit nonce. |
| Integrity | AES-256-GCM authentication tag and HMAC-SHA-256 | GCM detects ciphertext/AAD tampering. HMAC protects non-encrypted messages or metadata. |
| Authentication | HMAC-SHA-256 and freshness checks | Shared-key authentication proves possession of a secret. Replay checks require unique request IDs and bounded timestamps. |
| Non-repudiation | Ed25519 detached signatures | Public-key signatures verify the signer without sharing the private key. |

## Protections

- Nonce reuse: `NonceRegistry` reserves AES-GCM nonces per key id and version. The default implementation is in-memory for local execution; production deployments should back this with shared storage.
- Tampered ciphertext: AES-GCM decrypt failures return `TAMPERED_CIPHERTEXT`.
- Invalid signatures: Ed25519 verification failures return `INVALID_SIGNATURE`.
- Invalid keys: key length, key identity, and key version checks return `INVALID_KEY`.
- Expired credentials: `KeyMaterialRef.notAfter` is checked before key use and returns `EXPIRED_CREDENTIAL`.
- Replayed requests: `ReplayProtector` records request IDs inside an accepted timestamp window and returns `REPLAYED_REQUEST` on duplicates or stale timestamps.
- Key rotation: `rotateAes256Key` creates a new key version for the same key id and returns both previous and active key references.

## Operational Notes

AES-GCM nonce uniqueness must hold for every key version. If SecureLayer runs more than one node, replace the in-memory nonce and replay protectors with Redis or database-backed implementations so reservations are shared across nodes.

Private keys and symmetric keys should never be stored as plaintext. When key persistence is required, use the key management service to wrap key material before storage.
