package com.securelayer.core.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class BouncyCastleCryptoEngineTest {
    private final BouncyCastleCryptoEngine engine = new BouncyCastleCryptoEngine(
            new SecureLayerCrypto(),
            new InMemoryNonceRegistry(),
            new InMemoryReplayProtector());

    @Test
    void encryptsAndDecryptsAes256Gcm() {
        KeyMaterialRef key = engine.generateAes256Key("payload", 1, Instant.now().plusSeconds(3600)).value();

        CryptoResult<AesGcmEncryptedMessage> encrypted = engine.encryptAes256Gcm(key, bytes("hello"), bytes("tenant:1"));
        CryptoResult<byte[]> decrypted = engine.decryptAes256Gcm(key, encrypted.value());

        assertThat(encrypted.success()).isTrue();
        assertThat(encrypted.value().nonce()).hasSize(12);
        assertThat(decrypted.success()).isTrue();
        assertThat(decrypted.value()).isEqualTo(bytes("hello"));
    }

    @Test
    void rejectsTamperedCiphertext() {
        KeyMaterialRef key = engine.generateAes256Key("payload", 1, Instant.now().plusSeconds(3600)).value();
        AesGcmEncryptedMessage encrypted = engine.encryptAes256Gcm(key, bytes("hello"), bytes("tenant:1")).value();
        byte[] tampered = encrypted.ciphertext();
        tampered[0] = (byte) (tampered[0] ^ 0x01);

        CryptoResult<byte[]> result = engine.decryptAes256Gcm(key,
                new AesGcmEncryptedMessage(encrypted.keyId(), encrypted.keyVersion(), encrypted.nonce(), tampered, encrypted.associatedData()));

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.TAMPERED_CIPHERTEXT);
    }

    @Test
    void rejectsInvalidAesKeyLength() {
        KeyMaterialRef invalid = new KeyMaterialRef("payload", 1, bytes("short"), Instant.now().plusSeconds(3600));

        CryptoResult<AesGcmEncryptedMessage> result = engine.encryptAes256Gcm(invalid, bytes("hello"), new byte[0]);

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.INVALID_KEY);
    }

    @Test
    void reportsNonceReservationFailure() {
        BouncyCastleCryptoEngine nonceFailingEngine = new BouncyCastleCryptoEngine(
                new SecureLayerCrypto(),
                (keyId, keyVersion, nonce, ttl) -> false,
                new InMemoryReplayProtector());
        KeyMaterialRef key = nonceFailingEngine.generateAes256Key("payload", 1, Instant.now().plusSeconds(3600)).value();

        CryptoResult<AesGcmEncryptedMessage> result = nonceFailingEngine.encryptAes256Gcm(key, bytes("hello"), new byte[0]);

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.NONCE_REUSE_DETECTED);
    }

    @Test
    void hashesWithSha256() {
        CryptoResult<byte[]> digest = engine.sha256(bytes("hello"));

        assertThat(digest.success()).isTrue();
        assertThat(digest.value()).hasSize(32);
    }

    @Test
    void computesAndVerifiesHmacSha256() {
        KeyMaterialRef key = engine.generateHmacSha256Key("mac", 1, Instant.now().plusSeconds(3600)).value();
        CryptoResult<byte[]> mac = engine.hmacSha256(key, bytes("message"));

        assertThat(mac.success()).isTrue();
        assertThat(engine.verifyHmacSha256(key, bytes("message"), mac.value()).success()).isTrue();
    }

    @Test
    void rejectsInvalidHmac() {
        KeyMaterialRef key = engine.generateHmacSha256Key("mac", 1, Instant.now().plusSeconds(3600)).value();
        byte[] wrongMac = engine.hmacSha256(key, bytes("message")).value();
        wrongMac[0] = (byte) (wrongMac[0] ^ 0x01);

        CryptoResult<Void> result = engine.verifyHmacSha256(key, bytes("message"), wrongMac);

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.INTEGRITY_CHECK_FAILED);
    }

    @Test
    void signsAndVerifiesEd25519() {
        KeyPair keyPair = engine.generateEd25519KeyPair().value();
        CryptoResult<byte[]> signature = engine.signEd25519(keyPair, bytes("message"));

        CryptoResult<Void> verified = engine.verifyEd25519(keyPair.getPublic(), bytes("message"), signature.value());

        assertThat(signature.success()).isTrue();
        assertThat(verified.success()).isTrue();
    }

    @Test
    void rejectsInvalidEd25519Signature() {
        KeyPair keyPair = engine.generateEd25519KeyPair().value();
        byte[] signature = engine.signEd25519(keyPair, bytes("message")).value();

        CryptoResult<Void> verified = engine.verifyEd25519(keyPair.getPublic(), bytes("tampered"), signature);

        assertThat(verified.success()).isFalse();
        assertThat(verified.error().code()).isEqualTo(CryptoErrorCode.INVALID_SIGNATURE);
    }

    @Test
    void generatesSecureRandomBytes() {
        CryptoResult<byte[]> first = engine.secureRandomBytes(32);
        CryptoResult<byte[]> second = engine.secureRandomBytes(32);

        assertThat(first.success()).isTrue();
        assertThat(first.value()).hasSize(32);
        assertThat(first.value()).isNotEqualTo(second.value());
    }

    @Test
    void rotatesAesKeyByCreatingNextVersion() {
        KeyMaterialRef current = engine.generateAes256Key("payload", 1, Instant.now().plusSeconds(3600)).value();

        CryptoResult<KeyRotationResult> rotated = engine.rotateAes256Key(current, Instant.now().plusSeconds(7200));

        assertThat(rotated.success()).isTrue();
        assertThat(rotated.value().activeKey().keyId()).isEqualTo(current.keyId());
        assertThat(rotated.value().activeKey().version()).isEqualTo(2);
        assertThat(rotated.value().activeKey().encodedKey()).isNotEqualTo(current.encodedKey());
    }

    @Test
    void rejectsExpiredCredentials() {
        KeyMaterialRef expired = engine.generateAes256Key("payload", 1, Instant.now().minusSeconds(1)).value();

        CryptoResult<AesGcmEncryptedMessage> result = engine.encryptAes256Gcm(expired, bytes("hello"), new byte[0]);

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.EXPIRED_CREDENTIAL);
    }

    @Test
    void rejectsReplayedRequests() {
        ReplayCheck replayCheck = new ReplayCheck("request-1", Instant.now());

        CryptoResult<Void> first = engine.verifyFreshRequest(replayCheck);
        CryptoResult<Void> second = engine.verifyFreshRequest(replayCheck);

        assertThat(first.success()).isTrue();
        assertThat(second.success()).isFalse();
        assertThat(second.error().code()).isEqualTo(CryptoErrorCode.REPLAYED_REQUEST);
    }

    @Test
    void rejectsStaleRequests() {
        ReplayCheck replayCheck = new ReplayCheck("request-2", Instant.now().minus(Duration.ofMinutes(20)));

        CryptoResult<Void> result = engine.verifyFreshRequest(replayCheck);

        assertThat(result.success()).isFalse();
        assertThat(result.error().code()).isEqualTo(CryptoErrorCode.REPLAYED_REQUEST);
    }

    private byte[] bytes(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}
