package com.securelayer.gateway.security;

import com.securelayer.gateway.config.SecureLayerProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class SecureLayerControlPlaneClient {
    private final SecureLayerProperties properties;
    private final RestClient restClient;

    public SecureLayerControlPlaneClient(SecureLayerProperties properties, RestClient.Builder builder) {
        this.properties = properties;
        RestClient.Builder restClientBuilder = builder.baseUrl(properties.controlPlane().baseUrl());
        String bearerToken = properties.controlPlane().bearerToken();
        if (bearerToken != null && !bearerToken.isBlank()) {
            restClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        this.restClient = restClientBuilder.build();
    }

    public CertificateValidation validateDeviceCertificate(String tenantId, String deviceIdentifier, String pemCertificate) {
        if (deviceIdentifier == null || deviceIdentifier.isBlank() || pemCertificate == null || pemCertificate.isBlank()) {
            return new CertificateValidation(false, null, null, "Missing device identifier or certificate", null);
        }

        return restClient.post()
                .uri("/api/v1/admin/tenants/{tenantId}/device-certificate-validations", tenantId)
                .body(Map.of("deviceIdentifier", deviceIdentifier, "pemCertificate", pemCertificate))
                .retrieve()
                .body(CertificateValidation.class);
    }

    public SecureLayerDecision evaluatePolicy(PolicyEvaluation evaluation) {
        SecureLayerDecision decision = restClient.post()
                .uri("/api/v1/admin/tenants/{tenantId}/policy-evaluations", properties.gateway().tenantId())
                .body(evaluation)
                .retrieve()
                .body(SecureLayerDecision.class);
        return decision == null ? SecureLayerDecision.deny("SecureLayer returned no policy decision") : decision;
    }

    public void audit(AuditEvent event) {
        if (!properties.audit().enabled()) {
            return;
        }
        restClient.post()
                .uri("/api/v1/admin/tenants/{tenantId}/audit-events", properties.gateway().tenantId())
                .body(event)
                .retrieve()
                .toBodilessEntity();
    }

    public record CertificateValidation(
            boolean authenticated,
            String deviceId,
            String state,
            String reason,
            Instant certificateExpiresAt
    ) {
    }

    public record PolicyEvaluation(
            String policyName,
            String username,
            String deviceIdentifier,
            String clientId,
            String requestedResource,
            String httpMethod,
            Map<String, Object> requestContext,
            Collection<String> principalScopes,
            Collection<String> userRoles,
            String certificateFingerprintSha256,
            String ipAddress,
            Instant evaluatedAt
    ) {
    }

    public record AuditEvent(
            String subject,
            String action,
            String resource,
            String eventHashBase64,
            String signatureBase64
    ) {
        public static AuditEvent gatewayDecision(String subject, String action, String resource, String hashBase64) {
            return new AuditEvent(subject, action, resource, hashBase64, null);
        }
    }
}
