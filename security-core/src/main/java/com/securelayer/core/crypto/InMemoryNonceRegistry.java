package com.securelayer.core.crypto;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class InMemoryNonceRegistry implements NonceRegistry {
    private final Map<String, Instant> reservations = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryNonceRegistry() {
        this(Clock.systemUTC());
    }

    InMemoryNonceRegistry(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean reserve(String keyId, int keyVersion, byte[] nonce, Duration ttl) {
        purgeExpired();
        String registryKey = keyId + ":" + keyVersion + ":" + Base64.getEncoder().encodeToString(Arrays.copyOf(nonce, nonce.length));
        return reservations.putIfAbsent(registryKey, clock.instant().plus(ttl)) == null;
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        reservations.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }
}
