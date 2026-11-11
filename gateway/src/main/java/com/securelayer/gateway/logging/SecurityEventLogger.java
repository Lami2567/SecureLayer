package com.securelayer.gateway.logging;

import com.securelayer.gateway.security.SecureLayerDecision;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventLogger {
    private static final Logger log = LoggerFactory.getLogger(SecurityEventLogger.class);

    public void requestReceived(HttpServletRequest request, String subject, String clientId, String deviceId) {
        log.atInfo()
                .addKeyValue("event", "gateway.request_received")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("subject", subject)
                .addKeyValue("clientId", clientId)
                .addKeyValue("deviceId", deviceId)
                .addKeyValue("remoteAddr", request.getRemoteAddr())
                .addKeyValue("scheme", request.getScheme())
                .addKeyValue("secure", request.isSecure())
                .log("SecureLayer gateway intercepted request");
    }

    public void integrityFailure(HttpServletRequest request, String subject, String reason) {
        log.atWarn()
                .addKeyValue("event", "gateway.integrity_failed")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("subject", subject)
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("remoteAddr", request.getRemoteAddr())
                .addKeyValue("reason", reason)
                .log("SecureLayer gateway denied request integrity check");
    }

    public void certificateFailure(HttpServletRequest request, String subject, String reason) {
        log.atWarn()
                .addKeyValue("event", "gateway.device_certificate_failed")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("subject", subject)
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("remoteAddr", request.getRemoteAddr())
                .addKeyValue("reason", reason)
                .log("SecureLayer gateway denied device certificate validation");
    }

    public void policyDecision(HttpServletRequest request, String subject, String clientId, SecureLayerDecision decision) {
        var event = decision.allowed() ? log.atInfo() : log.atWarn();
        event.addKeyValue("event", "gateway.policy_decision")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("subject", subject)
                .addKeyValue("clientId", clientId)
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("remoteAddr", request.getRemoteAddr())
                .addKeyValue("allowed", decision.allowed())
                .addKeyValue("decision", decision.decision())
                .addKeyValue("policyName", decision.policyName())
                .addKeyValue("policyVersion", decision.policyVersion())
                .addKeyValue("reason", decision.reason())
                .log("SecureLayer gateway policy evaluation evaluated to {}", decision.decision());
    }

    public void requestForwarded(HttpServletRequest request, String upstreamUrl, int statusCode, long durationMs) {
        log.atInfo()
                .addKeyValue("event", "gateway.request_forwarded")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("upstreamUrl", upstreamUrl)
                .addKeyValue("upstreamStatus", statusCode)
                .addKeyValue("durationMs", durationMs)
                .log("SecureLayer gateway forwarded request to upstream application");
    }

    public void requestDenied(HttpServletRequest request, String code, String reason, int httpStatus) {
        log.atWarn()
                .addKeyValue("event", "gateway.request_denied")
                .addKeyValue("correlationId", correlationId())
                .addKeyValue("method", request.getMethod())
                .addKeyValue("path", request.getRequestURI())
                .addKeyValue("code", code)
                .addKeyValue("reason", reason)
                .addKeyValue("httpStatus", httpStatus)
                .log("SecureLayer gateway blocked access with status {}", httpStatus);
    }

    private String correlationId() {
        String id = MDC.get("correlationId");
        return id != null ? id : "none";
    }
}
