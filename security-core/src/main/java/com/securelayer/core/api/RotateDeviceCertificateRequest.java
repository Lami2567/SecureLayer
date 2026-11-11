package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record RotateDeviceCertificateRequest(@NotBlank String certificateSigningRequestPem) {
}
