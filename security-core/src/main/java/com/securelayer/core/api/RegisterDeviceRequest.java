package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record RegisterDeviceRequest(
        @NotBlank String name,
        @NotBlank String deviceIdentifier,
        @NotBlank String certificateSigningRequestPem) {
}
