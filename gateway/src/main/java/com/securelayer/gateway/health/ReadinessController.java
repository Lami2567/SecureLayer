package com.securelayer.gateway.health;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/health")
public class ReadinessController {
    private final GatewayHealthService healthService;

    public ReadinessController(GatewayHealthService healthService) {
        this.healthService = healthService;
    }

    @GetMapping("/live")
    public ResponseEntity<GatewayHealthService.GatewayHealth> live() {
        return ResponseEntity.ok(healthService.checkLiveness());
    }

    @GetMapping("/ready")
    public ResponseEntity<GatewayHealthService.GatewayHealth> ready() {
        GatewayHealthService.GatewayHealth health = healthService.checkReadiness();
        boolean isUp = "UP".equals(health.status());
        return ResponseEntity.status(isUp ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).body(health);
    }
}
