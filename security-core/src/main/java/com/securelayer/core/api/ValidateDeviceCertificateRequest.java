package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record ValidateDeviceCertificateRequest(
        @NotBlank String deviceIdentifier,
        @NotBlank String pemCertificate) {
}
