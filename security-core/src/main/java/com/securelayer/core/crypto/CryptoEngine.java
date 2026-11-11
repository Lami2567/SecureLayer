package com.securelayer.core.crypto;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;

public interface CryptoEngine {
    CryptoResult<KeyMaterialRef> generateAes256Key(String keyId, int version, Instant expiresAt);

    CryptoResult<KeyMaterialRef> generateHmacSha256Key(String keyId, int version, Instant expiresAt);

    CryptoResult<KeyPair> generateEd25519KeyPair();

    CryptoResult<byte[]> secureRandomBytes(int length);

    CryptoResult<AesGcmEncryptedMessage> encryptAes256Gcm(KeyMaterialRef key, byte[] plaintext, byte[] associatedData);

    CryptoResult<byte[]> decryptAes256Gcm(KeyMaterialRef key, AesGcmEncryptedMessage message);

    CryptoResult<byte[]> sha256(byte[] message);

    CryptoResult<byte[]> hmacSha256(KeyMaterialRef key, byte[] message);

    CryptoResult<Void> verifyHmacSha256(KeyMaterialRef key, byte[] message, byte[] expectedMac);

    CryptoResult<byte[]> signEd25519(KeyPair keyPair, byte[] message);

    CryptoResult<Void> verifyEd25519(PublicKey publicKey, byte[] message, byte[] signature);

    CryptoResult<KeyRotationResult> rotateAes256Key(KeyMaterialRef currentKey, Instant newExpiry);

    CryptoResult<Void> verifyFreshRequest(ReplayCheck replayCheck);

    CryptoResult<Void> verifyCredentialNotExpired(Instant expiresAt);
}
