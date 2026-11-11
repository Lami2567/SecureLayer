package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record RecordAuditRequest(
        @NotBlank String subject,
        @NotBlank String action,
        @NotBlank String resource,
        @NotBlank String eventHashBase64,
        String signatureBase64) {
}
