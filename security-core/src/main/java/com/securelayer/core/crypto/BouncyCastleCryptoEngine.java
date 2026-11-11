package com.securelayer.core.crypto;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class BouncyCastleCryptoEngine implements CryptoEngine {
    private static final int AES_256_KEY_BYTES = 32;
    private static final int HMAC_SHA256_MIN_KEY_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final Duration NONCE_RESERVATION_TTL = Duration.ofDays(7);
    private static final Duration REPLAY_TTL = Duration.ofMinutes(10);
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);

    private final SecureLayerCrypto crypto;
    private final NonceRegistry nonceRegistry;
    private final ReplayProtector replayProtector;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public BouncyCastleCryptoEngine(SecureLayerCrypto crypto, NonceRegistry nonceRegistry, ReplayProtector replayProtector) {
        this(crypto, nonceRegistry, replayProtector, Clock.systemUTC());
    }

    BouncyCastleCryptoEngine(SecureLayerCrypto crypto, NonceRegistry nonceRegistry, ReplayProtector replayProtector, Clock clock) {
        this.crypto = crypto;
        this.nonceRegistry = nonceRegistry;
        this.replayProtector = replayProtector;
        this.clock = clock;
    }

    @Override
    public CryptoResult<KeyMaterialRef> generateAes256Key(String keyId, int version, Instant expiresAt) {
        if (keyId == null || keyId.isBlank() || version < 1) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Key id and positive key version are required");
        }
        SecretKey key = crypto.generateAes256Key();
        return CryptoResult.success(new KeyMaterialRef(keyId, version, key.getEncoded(), expiresAt));
    }

    @Override
    public CryptoResult<KeyMaterialRef> generateHmacSha256Key(String keyId, int version, Instant expiresAt) {
        if (keyId == null || keyId.isBlank() || version < 1) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Key id and positive key version are required");
        }
        return CryptoResult.success(new KeyMaterialRef(keyId, version, crypto.secureRandomBytes(HMAC_SHA256_MIN_KEY_BYTES), expiresAt));
    }

    @Override
    public CryptoResult<KeyPair> generateEd25519KeyPair() {
        try {
            return CryptoResult.success(crypto.generateEd25519KeyPair());
        } catch (CryptoException ex) {
            return providerFailure(ex);
        }
    }

    @Override
    public CryptoResult<byte[]> secureRandomBytes(int length) {
        try {
            return CryptoResult.success(crypto.secureRandomBytes(length));
        } catch (CryptoException ex) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, ex.getMessage());
        }
    }

    @Override
    public CryptoResult<AesGcmEncryptedMessage> encryptAes256Gcm(KeyMaterialRef key, byte[] plaintext, byte[] associatedData) {
        CryptoResult<Void> keyCheck = validateAesKey(key);
        if (!keyCheck.success()) {
            return CryptoResult.failure(keyCheck.error().code(), keyCheck.error().message());
        }
        if (plaintext == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Plaintext is required");
        }
        try {
            AeadCiphertext encrypted;
            int attempts = 0;
            boolean reserved;
            do {
                encrypted = crypto.encryptAes256Gcm(aesKey(key), plaintext, associatedData);
                attempts++;
                reserved = nonceRegistry.reserve(key.keyId(), key.version(), encrypted.nonce(), NONCE_RESERVATION_TTL);
            } while (!reserved && attempts < 4);
            if (!reserved) {
                return CryptoResult.failure(CryptoErrorCode.NONCE_REUSE_DETECTED, "Unable to reserve a unique AES-GCM nonce");
            }
            return CryptoResult.success(new AesGcmEncryptedMessage(key.keyId(), key.version(), encrypted.nonce(),
                    encrypted.ciphertext(), encrypted.associatedData()));
        } catch (CryptoException ex) {
            return providerFailure(ex);
        }
    }

    @Override
    public CryptoResult<byte[]> decryptAes256Gcm(KeyMaterialRef key, AesGcmEncryptedMessage message) {
        CryptoResult<Void> keyCheck = validateAesKey(key);
        if (!keyCheck.success()) {
            return CryptoResult.failure(keyCheck.error().code(), keyCheck.error().message());
        }
        if (message == null || message.nonce().length != GCM_NONCE_BYTES || message.ciphertext().length == 0) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "AES-GCM message is incomplete");
        }
        if (!key.keyId().equals(message.keyId()) || key.version() != message.keyVersion()) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "Ciphertext key reference does not match the supplied key");
        }
        try {
            return CryptoResult.success(crypto.decryptAes256Gcm(aesKey(key),
                    new AeadCiphertext(message.nonce(), message.ciphertext(), message.associatedData())));
        } catch (CryptoException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("authentication failed")) {
                return CryptoResult.failure(CryptoErrorCode.TAMPERED_CIPHERTEXT, "Ciphertext, nonce, key, or associated data failed authentication");
            }
            return providerFailure(ex);
        }
    }

    @Override
    public CryptoResult<byte[]> sha256(byte[] message) {
        if (message == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Message is required");
        }
        return CryptoResult.success(crypto.sha256(message));
    }

    @Override
    public CryptoResult<byte[]> hmacSha256(KeyMaterialRef key, byte[] message) {
        CryptoResult<Void> keyCheck = validateHmacKey(key);
        if (!keyCheck.success()) {
            return CryptoResult.failure(keyCheck.error().code(), keyCheck.error().message());
        }
        if (message == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Message is required");
        }
        try {
            return CryptoResult.success(crypto.hmacSha256(hmacKey(key), message));
        } catch (CryptoException ex) {
            return providerFailure(ex);
        }
    }

    @Override
    public CryptoResult<Void> verifyHmacSha256(KeyMaterialRef key, byte[] message, byte[] expectedMac) {
        if (expectedMac == null || expectedMac.length == 0) {
            return CryptoResult.failure(CryptoErrorCode.INTEGRITY_CHECK_FAILED, "Expected HMAC is required");
        }
        CryptoResult<byte[]> actual = hmacSha256(key, message);
        if (!actual.success()) {
            return CryptoResult.failure(actual.error().code(), actual.error().message());
        }
        if (!java.security.MessageDigest.isEqual(actual.value(), expectedMac)) {
            return CryptoResult.failure(CryptoErrorCode.INTEGRITY_CHECK_FAILED, "HMAC verification failed");
        }
        return CryptoResult.success(null);
    }

    @Override
    public CryptoResult<byte[]> signEd25519(KeyPair keyPair, byte[] message) {
        if (keyPair == null || keyPair.getPrivate() == null || message == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Private key and message are required");
        }
        try {
            return CryptoResult.success(crypto.signEd25519(keyPair, message));
        } catch (CryptoException ex) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "Unable to sign with supplied Ed25519 key");
        }
    }

    @Override
    public CryptoResult<Void> verifyEd25519(PublicKey publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || message == null || signature == null || signature.length == 0) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Public key, message, and signature are required");
        }
        try {
            if (!crypto.verifyEd25519(publicKey, message, signature)) {
                return CryptoResult.failure(CryptoErrorCode.INVALID_SIGNATURE, "Ed25519 signature verification failed");
            }
            return CryptoResult.success(null);
        } catch (CryptoException ex) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "Unable to verify with supplied Ed25519 key");
        }
    }

    @Override
    public CryptoResult<KeyRotationResult> rotateAes256Key(KeyMaterialRef currentKey, Instant newExpiry) {
        CryptoResult<Void> keyCheck = validateAesKey(currentKey);
        if (!keyCheck.success()) {
            return CryptoResult.failure(keyCheck.error().code(), keyCheck.error().message());
        }
        CryptoResult<KeyMaterialRef> replacement = generateAes256Key(currentKey.keyId(), currentKey.version() + 1, newExpiry);
        if (!replacement.success()) {
            return CryptoResult.failure(replacement.error().code(), replacement.error().message());
        }
        return CryptoResult.success(new KeyRotationResult(currentKey, replacement.value()));
    }

    @Override
    public CryptoResult<Void> verifyFreshRequest(ReplayCheck replayCheck) {
        if (replayCheck == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Replay check is required");
        }
        return replayProtector.verifyFresh(replayCheck.requestId(), replayCheck.issuedAt(), MAX_CLOCK_SKEW, REPLAY_TTL);
    }

    @Override
    public CryptoResult<Void> verifyCredentialNotExpired(Instant expiresAt) {
        if (expiresAt == null) {
            return CryptoResult.success(null);
        }
        if (!clock.instant().isBefore(expiresAt)) {
            return CryptoResult.failure(CryptoErrorCode.EXPIRED_CREDENTIAL, "Credential has expired");
        }
        return CryptoResult.success(null);
    }

    private CryptoResult<Void> validateAesKey(KeyMaterialRef key) {
        CryptoResult<Void> credentialCheck = validateKeyRef(key, AES_256_KEY_BYTES);
        if (!credentialCheck.success()) {
            return credentialCheck;
        }
        return verifyCredentialNotExpired(key.notAfter());
    }

    private CryptoResult<Void> validateHmacKey(KeyMaterialRef key) {
        CryptoResult<Void> credentialCheck = validateKeyRef(key, HMAC_SHA256_MIN_KEY_BYTES);
        if (!credentialCheck.success()) {
            return credentialCheck;
        }
        return verifyCredentialNotExpired(key.notAfter());
    }

    private CryptoResult<Void> validateKeyRef(KeyMaterialRef key, int minimumBytes) {
        if (key == null || key.keyId() == null || key.keyId().isBlank() || key.version() < 1) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "Key id and key version are required");
        }
        if (minimumBytes == AES_256_KEY_BYTES && key.encodedKey().length != AES_256_KEY_BYTES) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "AES-256 requires exactly 256 bits of key material");
        }
        if (key.encodedKey().length < minimumBytes) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_KEY, "Key material is invalid for the requested operation");
        }
        return CryptoResult.success(null);
    }

    private SecretKey aesKey(KeyMaterialRef key) {
        return new SecretKeySpec(key.encodedKey(), "AES");
    }

    private SecretKey hmacKey(KeyMaterialRef key) {
        return crypto.hmacSha256Key(key.encodedKey());
    }

    private <T> CryptoResult<T> providerFailure(CryptoException ex) {
        return CryptoResult.failure(CryptoErrorCode.PROVIDER_FAILURE, ex.getMessage());
    }
}
