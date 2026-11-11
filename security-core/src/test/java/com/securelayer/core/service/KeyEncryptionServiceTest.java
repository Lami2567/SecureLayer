package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.securelayer.core.crypto.SecureLayerCrypto;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeyEncryptionServiceTest {
    @Test
    void wrapsKeyMaterialWithAesGcm() {
        String masterKey = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
        KeyEncryptionService service = new KeyEncryptionService(new SecureLayerCrypto(), masterKey);
        byte[] plaintext = "private-key-material".getBytes(StandardCharsets.UTF_8);

        KeyEncryptionService.EncryptedKey encrypted = service.encrypt(plaintext, "tenant:key");
        byte[] decrypted = service.decrypt(encrypted.ciphertext(), encrypted.nonce(), "tenant:key");

        assertThat(encrypted.ciphertext()).isNotEqualTo(plaintext);
        assertThat(encrypted.nonce()).hasSize(12);
        assertThat(decrypted).isEqualTo(plaintext);
    }
}
