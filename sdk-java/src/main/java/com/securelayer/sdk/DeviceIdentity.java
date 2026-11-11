package com.securelayer.sdk;

public record DeviceIdentity(
        String deviceId,
        String deviceIdentifier,
        String certificatePem,
        String state
) {
    public static DeviceIdentity of(String deviceIdentifier, String certificatePem) {
        return new DeviceIdentity(null, deviceIdentifier, certificatePem, "ACTIVE");
    }
}
