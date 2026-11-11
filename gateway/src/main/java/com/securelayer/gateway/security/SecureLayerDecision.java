package com.securelayer.gateway.security;

public record SecureLayerDecision(
        boolean allowed,
        String decision,
        String policyName,
        int policyVersion,
        String reason
) {
    public static SecureLayerDecision allow(String policyName, int policyVersion) {
        return new SecureLayerDecision(true, "ALLOW", policyName, policyVersion, "Allowed by SecureLayer policy");
    }

    public static SecureLayerDecision deny(String reason) {
        return new SecureLayerDecision(false, "DENY", "gateway", 0, reason);
    }
}
