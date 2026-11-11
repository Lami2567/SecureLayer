package com.securelayer.sdk;

public record ApplicationIdentity(
        String applicationId,
        String clientId,
        String name
) {
    public static ApplicationIdentity of(String clientId, String name) {
        return new ApplicationIdentity(null, clientId, name);
    }
}
