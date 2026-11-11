package com.securelayer.sdk;

public record EncryptedPayload(
        String algorithm,
        String nonce,
        String ciphertext,
        String authTag,
        String associatedData
) {}
