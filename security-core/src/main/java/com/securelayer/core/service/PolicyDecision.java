package com.securelayer.core.service;

public record PolicyDecision(
        boolean allowed,
        PolicyDecisionType decision,
        String policyName,
        int policyVersion,
        String reason) {

    public static PolicyDecision deny(String policyName, int policyVersion, String reason) {
        return new PolicyDecision(false, PolicyDecisionType.DENY, policyName, policyVersion, reason);
    }

    public static PolicyDecision of(PolicyDecisionType decision, String policyName, int policyVersion, String reason) {
        return new PolicyDecision(decision == PolicyDecisionType.ALLOW, decision, policyName, policyVersion, reason);
    }
}
