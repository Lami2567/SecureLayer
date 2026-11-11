package com.securelayer.gateway.proxy;

import com.securelayer.gateway.config.SecureLayerProperties;
import com.securelayer.gateway.error.ApiError;
import com.securelayer.gateway.logging.SecurityEventLogger;
import com.securelayer.gateway.security.ClientCertificateExtractor;
import com.securelayer.gateway.security.GatewayPrincipal;
import com.securelayer.gateway.security.RequestIntegrityService;
import com.securelayer.gateway.security.SecureLayerControlPlaneClient;
import com.securelayer.gateway.security.SecureLayerDecision;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GatewayProxyController {
    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length");

    private final SecureLayerProperties properties;
    private final RequestIntegrityService integrityService;
    private final ClientCertificateExtractor certificateExtractor;
    private final SecureLayerControlPlaneClient controlPlaneClient;
    private final SecurityEventLogger securityLogger;
    private final HttpClient httpClient;

    public GatewayProxyController(SecureLayerProperties properties, RequestIntegrityService integrityService,
            ClientCertificateExtractor certificateExtractor, SecureLayerControlPlaneClient controlPlaneClient,
            SecurityEventLogger securityLogger) {
        this.properties = properties;
        this.integrityService = integrityService;
        this.certificateExtractor = certificateExtractor;
        this.controlPlaneClient = controlPlaneClient;
        this.securityLogger = securityLogger;
        this.httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @RequestMapping("/**")
    public ResponseEntity<?> protectAndProxy(HttpServletRequest request, Authentication authentication, @RequestBody(required = false) byte[] body)
            throws IOException, InterruptedException {
        if (!properties.gateway().enabled()) {
            return deny("GATEWAY_DISABLED", "SecureLayer gateway protection is disabled", request);
        }

        byte[] requestBody = body == null ? new byte[0] : body;
        GatewayPrincipal principal = GatewayPrincipal.from(authentication);
        String deviceIdentifier = request.getHeader(properties.gateway().deviceIdentifierHeader());
        String clientId = request.getHeader(properties.gateway().applicationIdHeader());

        securityLogger.requestReceived(request, principal.subject(), clientId, deviceIdentifier);

        // 1. Verify Message Integrity
        RequestIntegrityService.IntegrityResult integrity = integrityService.verify(request, requestBody,
                properties.gateway().requestIntegrityHeader(), properties.gateway().requireRequestIntegrity());
        if (!integrity.verified()) {
            securityLogger.integrityFailure(request, principal.subject(), integrity.reason());
            audit(principal.subject(), "gateway-deny", request.getRequestURI(), integrity.reason().getBytes());
            return deny("REQUEST_INTEGRITY_FAILED", integrity.reason(), request);
        }

        // 2. Validate Device Certificate
        String certificatePem = certificateExtractor.extractPem(request, properties.gateway().certificateHeader());
        if (properties.gateway().requireDeviceCertificate() || (deviceIdentifier != null && certificatePem != null)) {
            SecureLayerControlPlaneClient.CertificateValidation validation =
                    controlPlaneClient.validateDeviceCertificate(properties.gateway().tenantId(), deviceIdentifier, certificatePem);
            if (validation == null || !validation.authenticated()) {
                String reason = validation == null ? "Device certificate validation failed" : validation.reason();
                securityLogger.certificateFailure(request, principal.subject(), reason);
                audit(principal.subject(), "gateway-deny", request.getRequestURI(), reason.getBytes());
                return deny("DEVICE_CERTIFICATE_DENIED", reason, request);
            }
        }

        // 3. Evaluate Policy (Default DENY unless explicitly allowed)
        SecureLayerDecision decision;
        try {
            decision = controlPlaneClient.evaluatePolicy(policyEvaluation(request, principal, deviceIdentifier, clientId));
        } catch (Exception ex) {
            decision = SecureLayerDecision.deny("Control plane policy evaluation failed: " + ex.getMessage());
        }

        securityLogger.policyDecision(request, principal.subject(), clientId, decision);
        audit(principal.subject(), "gateway-policy-decision", request.getRequestURI(),
                (decision.decision() + ":" + decision.reason()).getBytes());

        if (!decision.allowed()) {
            return deny("POLICY_DENIED", decision.reason() == null ? "Denied by SecureLayer policy" : decision.reason(), request);
        }

        return forward(request, requestBody, principal, clientId, decision);
    }

    private SecureLayerControlPlaneClient.PolicyEvaluation policyEvaluation(HttpServletRequest request, GatewayPrincipal principal,
            String deviceIdentifier, String clientId) {
        return new SecureLayerControlPlaneClient.PolicyEvaluation(
                properties.gateway().policyName(),
                principal.subject(),
                deviceIdentifier,
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
    }

    private Map<String, Object> requestContext(HttpServletRequest request) {
        Map<String, Object> context = new HashMap<>();
        context.put("query", request.getQueryString());
        context.put("scheme", request.getScheme());
        context.put("secure", request.isSecure());
        context.put("correlationId", MDC.get("correlationId"));
        return context;
    }

    private ResponseEntity<byte[]> forward(HttpServletRequest request, byte[] body, GatewayPrincipal principal, String clientId,
            SecureLayerDecision decision) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        URI target = targetUri(request);

        HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                .method(request.getMethod(), HttpRequest.BodyPublishers.ofByteArray(body));

        request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
            if (!HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase(Locale.ROOT))) {
                request.getHeaders(headerName).asIterator().forEachRemaining(value -> builder.header(headerName, value));
            }
        });
        builder.header("X-SecureLayer-Subject", principal.subject());
        if (clientId != null && !clientId.isBlank()) {
            builder.header("X-SecureLayer-Client-Id", clientId);
        }
        builder.header("X-SecureLayer-Policy-Decision", decision.decision());
        builder.header("X-SecureLayer-Policy-Name", decision.policyName());
        builder.header("X-SecureLayer-Policy-Version", Integer.toString(decision.policyVersion()));

        HttpResponse<byte[]> upstream = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        long duration = System.currentTimeMillis() - start;
        securityLogger.requestForwarded(request, target.toString(), upstream.statusCode(), duration);

        HttpHeaders responseHeaders = new HttpHeaders();
        upstream.headers().map().forEach((name, values) -> {
            if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                responseHeaders.addAll(name, values);
            }
        });
        return new ResponseEntity<>(upstream.body(), responseHeaders, HttpStatus.valueOf(upstream.statusCode()));
    }

    private URI targetUri(HttpServletRequest request) {
        String query = request.getQueryString();
        return URI.create(properties.gateway().upstreamBaseUrl() + request.getRequestURI() + (query == null ? "" : "?" + query));
    }

    private void audit(String subject, String action, String resource, byte[] eventPayload) {
        if (!properties.audit().enabled()) {
            return;
        }
        controlPlaneClient.audit(SecureLayerControlPlaneClient.AuditEvent.gatewayDecision(subject, action, resource,
                integrityService.sha256(eventPayload)));
    }

    private ResponseEntity<ApiError> deny(String code, String message, HttpServletRequest request) {
        securityLogger.requestDenied(request, code, message, HttpStatus.FORBIDDEN.value());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiError(code, message, MDC.get("correlationId"), Instant.now(),
                Map.of("path", request.getRequestURI(), "defaultBehavior", "DENY")));
    }
}
