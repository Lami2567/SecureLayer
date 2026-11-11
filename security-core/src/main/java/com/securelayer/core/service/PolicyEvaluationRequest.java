package com.securelayer.core.service;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;

public record PolicyEvaluationRequest(
        UUID tenantId,
        String policyName,
        UUID userId,
        String username,
        UUID deviceId,
        String deviceIdentifier,
        UUID applicationId,
        String clientId,
        String requestedResource,
        String httpMethod,
        Map<String, Object> requestContext,
        Collection<String> principalScopes,
        Collection<String> userRoles,
        String certificateFingerprintSha256,
        X509Certificate deviceCertificate,
        String ipAddress,
        Instant evaluatedAt) {

    public String effectivePolicyName() {
        return policyName == null || policyName.isBlank() ? "default" : policyName;
    }

    public Instant effectiveEvaluationTime() {
        return evaluatedAt == null ? Instant.now() : evaluatedAt;
    }
}
