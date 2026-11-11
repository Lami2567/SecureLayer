package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;

public record EvaluatePolicyRequest(
        String policyName,
        UUID userId,
        String username,
        UUID deviceId,
        String deviceIdentifier,
        UUID applicationId,
        String clientId,
        @NotBlank String requestedResource,
        @NotBlank String httpMethod,
        Map<String, Object> requestContext,
        Collection<String> principalScopes,
        Collection<String> userRoles,
        String certificateFingerprintSha256,
        String ipAddress,
        Instant evaluatedAt) {
}
