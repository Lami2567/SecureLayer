package com.securelayer.core.crypto;

import java.time.Instant;

public record ReplayCheck(String requestId, Instant issuedAt) {
}
