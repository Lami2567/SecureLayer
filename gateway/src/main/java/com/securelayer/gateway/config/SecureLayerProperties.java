package com.securelayer.gateway.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "securelayer")
public record SecureLayerProperties(
        @NotBlank String environment,
        @Valid @NotNull Security security,
        @Valid @NotNull Audit audit,
        @Valid @NotNull Gateway gateway,
        @Valid @NotNull ControlPlane controlPlane
) {
    public record Security(
            @NotBlank String oidcIssuerUri,
            @NotBlank String audience
    ) {
    }

    public record Audit(
            boolean enabled,
            @NotBlank String hashAlgorithm,
            @NotBlank String signingAlgorithm
    ) {
    }

    public record Gateway(
            boolean enabled,
            @NotBlank String tenantId,
            @NotBlank String policyName,
            @NotBlank String upstreamBaseUrl,
            boolean requireRequestIntegrity,
            boolean requireDeviceCertificate,
            @NotBlank String requestIntegrityHeader,
            @NotBlank String applicationIdHeader,
            @NotBlank String deviceIdentifierHeader,
            @NotBlank String certificateHeader
    ) {
    }

    public record ControlPlane(
            @NotBlank String baseUrl,
            String bearerToken
    ) {
    }
}

