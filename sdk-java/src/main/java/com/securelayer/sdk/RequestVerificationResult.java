package com.securelayer.sdk;

public record RequestVerificationResult(
        boolean verified,
        String reason,
        String requestId,
        String timestamp,
        String tenantId
) {
    public static RequestVerificationResult success(String requestId, String timestamp, String tenantId) {
        return new RequestVerificationResult(true, null, requestId, timestamp, tenantId);
    }

    public static RequestVerificationResult failure(String reason, String requestId, String timestamp, String tenantId) {
        return new RequestVerificationResult(false, reason, requestId, timestamp, tenantId);
    }
}
