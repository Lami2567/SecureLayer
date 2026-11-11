package com.securelayer.core.crypto;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class InMemoryReplayProtector implements ReplayProtector {
    private final Map<String, Instant> seenRequests = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryReplayProtector() {
        this(Clock.systemUTC());
    }

    InMemoryReplayProtector(Clock clock) {
        this.clock = clock;
    }

    @Override
    public CryptoResult<Void> verifyFresh(String requestId, Instant issuedAt, Duration maxClockSkew, Duration replayTtl) {
        if (requestId == null || requestId.isBlank() || issuedAt == null) {
            return CryptoResult.failure(CryptoErrorCode.INVALID_REQUEST, "Request id and issued-at timestamp are required");
        }
        purgeExpired();
        Instant now = clock.instant();
        if (issuedAt.isBefore(now.minus(maxClockSkew)) || issuedAt.isAfter(now.plus(maxClockSkew))) {
            return CryptoResult.failure(CryptoErrorCode.REPLAYED_REQUEST, "Request timestamp is outside the accepted clock window");
        }
        if (seenRequests.putIfAbsent(requestId, now.plus(replayTtl)) != null) {
            return CryptoResult.failure(CryptoErrorCode.REPLAYED_REQUEST, "Request id has already been processed");
        }
        return CryptoResult.success(null);
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        seenRequests.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }
}
