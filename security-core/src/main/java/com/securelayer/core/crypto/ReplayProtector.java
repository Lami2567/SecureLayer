package com.securelayer.core.crypto;

import java.time.Duration;
import java.time.Instant;

public interface ReplayProtector {
    CryptoResult<Void> verifyFresh(String requestId, Instant issuedAt, Duration maxClockSkew, Duration replayTtl);
}
