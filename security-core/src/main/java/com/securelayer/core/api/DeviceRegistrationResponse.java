package com.securelayer.core.api;

import com.securelayer.core.domain.DeviceState;
import java.time.Instant;
import java.util.UUID;

public record DeviceRegistrationResponse(
        UUID deviceId,
        UUID certificateId,
        DeviceState state,
        String pemCertificate,
        String certificateFingerprintSha256,
        Instant expiresAt) {
}
