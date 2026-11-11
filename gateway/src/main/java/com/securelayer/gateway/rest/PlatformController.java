package com.securelayer.gateway.rest;

import com.securelayer.gateway.config.SecureLayerProperties;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/platform")
public class PlatformController {
    private final SecureLayerProperties properties;

    public PlatformController(SecureLayerProperties properties) {
        this.properties = properties;
    }

    @GetMapping
    Map<String, Object> platform() {
        return Map.of(
                "name", "SecureLayer",
                "environment", properties.environment(),
                "securityGoals", new String[]{"confidentiality", "integrity", "authentication", "non-repudiation"}
        );
    }
}

