package com.securelayer.gateway.error;

import java.time.Instant;
import java.util.Map;

public record ApiError(
        String code,
        String message,
        String correlationId,
        Instant timestamp,
        Map<String, Object> details
) {
}

