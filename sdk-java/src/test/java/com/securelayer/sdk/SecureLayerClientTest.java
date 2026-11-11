package com.securelayer.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SecureLayerClientTest {

    private SecureLayerClient client;
    private byte[] aesKey;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() {
        aesKey = new byte[32];
        new SecureRandom().nextBytes(aesKey);
        keyPair = SecureLayerClient.generateEd25519KeyPair();

        client = SecureLayerClient.builder()
                .tenantId("tenant-bank-101")
                .application("app-client-1", "Banking Portal")
                .device("dev-laptop-1", "CERT_PEM_MOCK")
                .signingKeyPair(keyPair)
                .signingKeyId("key-ed-1")
                .encryptionKey(aesKey)
                .hmacKey("hmac-secret-12345678901234567890".getBytes(StandardCharsets.UTF_8))
                .clockSkewTolerance(Duration.ofMinutes(5))
                .build();

        SecureLayer.initialize(client);
    }

    @Test
    void hashesDataDeterministically() {
        String data = "Hello SecureLayer";
        String hash1 = client.hash(data);
        String hash2 = client.hash(data.getBytes(StandardCharsets.UTF_8));

        assertThat(hash1).isNotEmpty();
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void encryptsAndDecryptsWithAes256Gcm() {
        String plaintext = "Confidential Banking Account Balance: $500,000.00";
        EncryptedPayload encrypted = client.encrypt(plaintext);

        assertThat(encrypted.algorithm()).isEqualTo("AES-256-GCM");
        assertThat(encrypted.nonce()).isNotEmpty();
        assertThat(encrypted.ciphertext()).isNotEmpty();
        assertThat(encrypted.authTag()).isNotEmpty();

        String decrypted = client.decryptString(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void detectsTamperedCiphertext() {
        EncryptedPayload encrypted = client.encrypt("Sensitive wire instructions");

        // Tamper with authentication tag
        EncryptedPayload tampered = new EncryptedPayload(
                encrypted.algorithm(),
                encrypted.nonce(),
                encrypted.ciphertext(),
                Base64.getEncoder().encodeToString(new byte[16]),
                encrypted.associatedData()
        );

        assertThatThrownBy(() -> client.decrypt(tampered))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("AES-256-GCM decryption failed");
    }

    @Test
    void signsAndVerifiesEd25519DigitalSignatures() {
        String transaction = "TRANSFER:ACC-1001->ACC-2002:AMOUNT=2500";
        String signature = client.sign(transaction);

        assertThat(signature).isNotEmpty();

        // Valid signature on identical transaction
        boolean valid = client.verify(transaction, signature);
        assertThat(valid).isTrue();

        // Modified transaction fails verification
        String tampered = "TRANSFER:ACC-1001->ACC-2002:AMOUNT=2500000";
        boolean invalid = client.verify(tampered, signature);
        assertThat(invalid).isFalse();
    }

    @Test
    void protectsAndVerifiesHttpRequests() {
        byte[] body = "{\"orderId\":\"42\"}".getBytes(StandardCharsets.UTF_8);
        ProtectedRequest protectedReq = client.protectRequest("POST", "/orders", Map.of(), body);

        assertThat(protectedReq.headers()).containsKey("x-request-id");
        assertThat(protectedReq.headers()).containsKey("x-request-timestamp");
        assertThat(protectedReq.headers()).containsKey("x-message-sha256");
        assertThat(protectedReq.headers()).containsKey("x-securelayer-signature");
        assertThat(protectedReq.headers().get("x-securelayer-tenant-id")).isEqualTo("tenant-bank-101");

        RequestVerificationResult result = client.verifyRequest("POST", "/orders", protectedReq.headers(), body);
        assertThat(result.verified()).isTrue();

        // Tampered body
        byte[] tamperedBody = "{\"orderId\":\"43\"}".getBytes(StandardCharsets.UTF_8);
        RequestVerificationResult tamperedResult = client.verifyRequest("POST", "/orders", protectedReq.headers(), tamperedBody);
        assertThat(tamperedResult.verified()).isFalse();
        assertThat(tamperedResult.reason()).isEqualTo("Request body hash mismatch");
    }

    @Test
    void rejectsRequestsExceedingClockSkew() {
        SecureLayerClient strictClient = SecureLayerClient.builder()
                .tenantId("tenant-1")
                .clockSkewTolerance(Duration.ofSeconds(10))
                .build();

        Map<String, String> headers = Map.of(
                "x-request-id", "req-1",
                "x-request-timestamp", Instant.now().minus(Duration.ofMinutes(15)).toString()
        );

        RequestVerificationResult result = strictClient.verifyRequest("GET", "/health", headers, new byte[0]);
        assertThat(result.verified()).isFalse();
        assertThat(result.reason()).isEqualTo("Request timestamp outside acceptable tolerance window");
    }

    @Test
    void staticFacadeMirrorsAllClientMethods() {
        String msg = "Payload for static test";
        EncryptedPayload encrypted = SecureLayer.encrypt(msg);
        assertThat(SecureLayer.decryptString(encrypted)).isEqualTo(msg);

        String sig = SecureLayer.sign(msg);
        assertThat(SecureLayer.verify(msg, sig)).isTrue();
        assertThat(SecureLayer.verify("different", sig)).isFalse();
    }
}
