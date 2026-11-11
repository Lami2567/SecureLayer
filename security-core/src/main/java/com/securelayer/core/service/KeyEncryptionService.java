package com.securelayer.core.service;

import com.securelayer.core.crypto.AeadCiphertext;
import com.securelayer.core.crypto.CryptoException;
import com.securelayer.core.crypto.SecureLayerCrypto;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class KeyEncryptionService {
    private final SecureLayerCrypto crypto;
    private final SecretKey masterKey;

    public KeyEncryptionService(SecureLayerCrypto crypto,
            @Value("${securelayer.security.key-encryption-master-key:}") String configuredKey) {
        this.crypto = crypto;
        this.masterKey = new SecretKeySpec(resolveMasterKey(configuredKey), "AES");
    }

    public EncryptedKey encrypt(byte[] plaintextKey, String associatedData) {
        AeadCiphertext ciphertext = crypto.encryptAes256Gcm(masterKey, plaintextKey, associatedData.getBytes(StandardCharsets.UTF_8));
        return new EncryptedKey(ciphertext.ciphertext(), ciphertext.nonce());
    }

    public byte[] decrypt(byte[] ciphertext, byte[] nonce, String associatedData) {
        return crypto.decryptAes256Gcm(masterKey, new AeadCiphertext(nonce, ciphertext, associatedData.getBytes(StandardCharsets.UTF_8)));
    }

    private byte[] resolveMasterKey(String configuredKey) {
        if (configuredKey != null && !configuredKey.isBlank()) {
            byte[] decoded = Base64.getDecoder().decode(configuredKey);
            if (decoded.length != 32) {
                throw new IllegalStateException("SECURELAYER_KEY_ENCRYPTION_MASTER_KEY must be a base64 encoded 256-bit key");
            }
            return decoded;
        }
        try {
            return MessageDigest.getInstance("SHA-256").digest("securelayer-local-development-key".getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("SHA-256 is unavailable", ex);
        }
    }

    public record EncryptedKey(byte[] ciphertext, byte[] nonce) {
    }
}
