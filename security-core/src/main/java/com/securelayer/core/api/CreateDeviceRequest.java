package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record CreateDeviceRequest(
        @NotBlank String name,
        @NotBlank String deviceIdentifier) {
}
