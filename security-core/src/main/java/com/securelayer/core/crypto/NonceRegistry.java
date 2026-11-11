package com.securelayer.core.crypto;

import java.time.Duration;

public interface NonceRegistry {
    boolean reserve(String keyId, int keyVersion, byte[] nonce, Duration ttl);
}
