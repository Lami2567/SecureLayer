package com.securelayer.core.api;

import com.securelayer.core.domain.DeviceState;
import java.time.Instant;
import java.util.UUID;

public record DeviceAuthenticationResponse(
        boolean authenticated,
        UUID deviceId,
        DeviceState state,
        String reason,
        Instant certificateExpiresAt) {
}
