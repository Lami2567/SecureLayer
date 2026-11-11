package com.securelayer.gateway.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

public record GatewayPrincipal(
        String subject,
        Collection<String> scopes,
        Collection<String> roles
) {
    public static GatewayPrincipal from(Authentication authentication) {
        if (authentication == null) {
            return new GatewayPrincipal("anonymous", List.of(), List.of());
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof Jwt jwt) {
            return new GatewayPrincipal(jwt.getSubject(), scopes(jwt.getClaims()), roles(jwt.getClaims()));
        }

        return new GatewayPrincipal(authentication.getName(), List.of(), authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .toList());
    }

    private static Collection<String> scopes(Map<String, Object> claims) {
        Object scope = claims.get("scope");
        if (scope instanceof String value && !value.isBlank()) {
            return List.of(value.split(" "));
        }
        Object scp = claims.get("scp");
        if (scp instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private static Collection<String> roles(Map<String, Object> claims) {
        Object roles = claims.get("roles");
        if (roles instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
