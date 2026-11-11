package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public record ImportCertificateRequest(
        @NotBlank String subject,
        @NotBlank String serialNumber,
        @NotBlank String pemCertificate,
        @NotNull Instant notBefore,
        @NotNull Instant notAfter) {
}
