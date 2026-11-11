package com.securelayer.core.crypto;

import java.time.Instant;

public record KeyMaterialRef(String keyId, int version, byte[] encodedKey, Instant notAfter) {
    public KeyMaterialRef {
        encodedKey = encodedKey == null ? new byte[0] : encodedKey.clone();
    }

    @Override
    public byte[] encodedKey() {
        return encodedKey.clone();
    }

    public boolean expired(Instant now) {
        return notAfter != null && !now.isBefore(notAfter);
    }
}
