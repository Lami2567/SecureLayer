package com.securelayer.gateway.health;

import com.securelayer.gateway.config.SecureLayerProperties;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class GatewayHealthService {
    private final SecureLayerProperties properties;
    private final RestClient restClient;

    public GatewayHealthService(SecureLayerProperties properties, RestClient.Builder builder) {
        this.properties = properties;
        this.restClient = builder.baseUrl(properties.controlPlane().baseUrl()).build();
    }

    public GatewayHealth checkLiveness() {
        return new GatewayHealth("UP", true, true, Map.of(
                "gateway", properties.gateway().enabled() ? "ENABLED" : "DISABLED",
                "environment", properties.environment()
        ), Instant.now());
    }

    public GatewayHealth checkReadiness() {
        if (!properties.gateway().enabled()) {
            return new GatewayHealth("DOWN", true, true, Map.of(
                    "gateway", "DISABLED",
                    "reason", "SecureLayer gateway is administratively disabled"
            ), Instant.now());
        }

        Map<String, Object> details = new HashMap<>();
        details.put("policyName", properties.gateway().policyName());
        details.put("tenantId", properties.gateway().tenantId());
        details.put("upstreamBaseUrl", properties.gateway().upstreamBaseUrl());
        details.put("stateless", true);
        details.put("multipleInstancesSupported", true);

        try {
            var response = restClient.get()
                    .uri("/api/v1/health/live")
                    .retrieve()
                    .toBodilessEntity();

            if (response.getStatusCode().is2xxSuccessful()) {
                details.put("controlPlane", "REACHABLE");
            } else {
                details.put("controlPlane", "DEGRADED (" + response.getStatusCode() + ")");
            }
        } catch (Exception ex) {
            details.put("controlPlane", "STANDALONE_OR_UNREACHABLE");
            details.put("controlPlaneError", ex.getMessage());
        }

        return new GatewayHealth("UP", true, true, details, Instant.now());
    }

    public record GatewayHealth(
            String status,
            boolean stateless,
            boolean multiInstanceReady,
            Map<String, Object> details,
            Instant timestamp
    ) {}
}
