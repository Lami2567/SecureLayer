package com.securelayer.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securelayer.gateway.config.SecureLayerProperties;
import com.securelayer.gateway.error.ApiError;
import com.securelayer.gateway.logging.SecurityEventLogger;
import com.securelayer.gateway.security.ClientCertificateExtractor;
import com.securelayer.gateway.security.GatewayPrincipal;
import com.securelayer.gateway.security.RequestIntegrityService;
import com.securelayer.gateway.security.SecureLayerControlPlaneClient;
import com.securelayer.gateway.security.SecureLayerDecision;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reusable middleware that enforces SecureLayer policies, request integrity,
 * device certificate validation, and audit logging for applications without
 * altering their business logic.
 */
@Component
public class SecureLayerGatewayFilter extends OncePerRequestFilter {
    public static final String DECISION_ATTRIBUTE = "securelayer.decision";

    private final SecureLayerProperties properties;
    private final RequestIntegrityService integrityService;
    private final ClientCertificateExtractor certificateExtractor;
    private final SecureLayerControlPlaneClient controlPlaneClient;
    private final SecurityEventLogger securityLogger;
    private final ObjectMapper objectMapper;

    public SecureLayerGatewayFilter(SecureLayerProperties properties, RequestIntegrityService integrityService,
                                   ClientCertificateExtractor certificateExtractor, SecureLayerControlPlaneClient controlPlaneClient,
                                   SecurityEventLogger securityLogger, ObjectMapper objectMapper) {
        this.properties = properties;
        this.integrityService = integrityService;
        this.certificateExtractor = certificateExtractor;
        this.controlPlaneClient = controlPlaneClient;
        this.securityLogger = securityLogger;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator/health") || path.startsWith("/api/v1/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.gateway().enabled()) {
            reject(response, request, HttpStatus.SERVICE_UNAVAILABLE, "GATEWAY_DISABLED", "SecureLayer protection is disabled");
            return;
        }

        GatewayPrincipal principal = GatewayPrincipal.from(SecurityContextHolder.getContext().getAuthentication());
        String clientId = request.getHeader(properties.gateway().applicationIdHeader());
        String deviceId = request.getHeader(properties.gateway().deviceIdentifierHeader());
        securityLogger.requestReceived(request, principal.subject(), clientId, deviceId);

        // 1. Verify Request Integrity
        byte[] body = request.getInputStream().readAllBytes();
        RequestIntegrityService.IntegrityResult integrity = integrityService.verify(
                request, body, properties.gateway().requestIntegrityHeader(), properties.gateway().requireRequestIntegrity());

        if (!integrity.verified()) {
            securityLogger.integrityFailure(request, principal.subject(), integrity.reason());
            audit(principal.subject(), "gateway-deny", request.getRequestURI(), integrity.reason().getBytes());
            reject(response, request, HttpStatus.BAD_REQUEST, "REQUEST_INTEGRITY_FAILED", integrity.reason());
            return;
        }

        // 2. Validate Device Certificate
        String certPem = certificateExtractor.extractPem(request, properties.gateway().certificateHeader());
        if (properties.gateway().requireDeviceCertificate() || (deviceId != null && certPem != null)) {
            var validation = controlPlaneClient.validateDeviceCertificate(properties.gateway().tenantId(), deviceId, certPem);
            if (validation == null || !validation.authenticated()) {
                String reason = validation == null ? "Device certificate validation failed" : validation.reason();
                securityLogger.certificateFailure(request, principal.subject(), reason);
                audit(principal.subject(), "gateway-deny", request.getRequestURI(), reason.getBytes());
                reject(response, request, HttpStatus.FORBIDDEN, "DEVICE_CERTIFICATE_DENIED", reason);
                return;
            }
        }

        // 3. Evaluate Policy (Default DENY unless explicitly allowed)
        SecureLayerDecision decision;
        try {
            var evalRequest = new SecureLayerControlPlaneClient.PolicyEvaluation(
                    properties.gateway().policyName(),
                    principal.subject(),
                    deviceId,
                    clientId,
                    request.getRequestURI(),
                    request.getMethod(),
                    requestContext(request),
                    principal.scopes(),
                    principal.roles(),
                    null,
                    request.getRemoteAddr(),
                    Instant.now()
            );
            decision = controlPlaneClient.evaluatePolicy(evalRequest);
        } catch (Exception ex) {
            decision = SecureLayerDecision.deny("Control plane evaluation failed: " + ex.getMessage());
        }

        securityLogger.policyDecision(request, principal.subject(), clientId, decision);
        audit(principal.subject(), "gateway-policy-decision", request.getRequestURI(),
                (decision.decision() + ":" + decision.reason()).getBytes());

        if (!decision.allowed()) {
            String reason = decision.reason() != null ? decision.reason() : "Access denied by SecureLayer policy";
            reject(response, request, HttpStatus.FORBIDDEN, "POLICY_DENIED", reason);
            return;
        }

        // 4. Request Allowed: enrich headers and proceed without changing application business logic
        request.setAttribute(DECISION_ATTRIBUTE, decision);
        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, HttpServletRequest request, HttpStatus status, String code, String message) throws IOException {
        securityLogger.requestDenied(request, code, message, status.value());
        response.setStatus(status.value());
        response.setContentType("application/json");

        ApiError error = new ApiError(code, message, MDC.get("correlationId"), Instant.now(),
                Map.of("path", request.getRequestURI(), "defaultBehavior", "DENY"));

        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    private Map<String, Object> requestContext(HttpServletRequest request) {
        Map<String, Object> context = new HashMap<>();
        context.put("query", request.getQueryString());
        context.put("scheme", request.getScheme());
        context.put("secure", request.isSecure());
        context.put("correlationId", MDC.get("correlationId"));
        return context;
    }

    private void audit(String subject, String action, String resource, byte[] payload) {
        if (!properties.audit().enabled()) return;
        controlPlaneClient.audit(SecureLayerControlPlaneClient.AuditEvent.gatewayDecision(
                subject, action, resource, integrityService.sha256(payload)));
    }
}
