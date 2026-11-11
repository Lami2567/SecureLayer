package com.securelayer.sdk;

import com.securelayer.proto.v1.AuthorizeResponse;
import com.securelayer.proto.v1.RecordAuditEventResponse;
import com.securelayer.proto.v1.ValidateCertificateResponse;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

/**
 * Developer-friendly static facade for SecureLayer operations.
 */
public final class SecureLayer {
    private static volatile SecureLayerClient defaultClient;

    private SecureLayer() {}

    public static SecureLayerClient initialize(SecureLayerClient client) {
        defaultClient = Objects.requireNonNull(client, "client");
        return defaultClient;
    }

    public static SecureLayerClient client() {
        SecureLayerClient c = defaultClient;
        if (c == null) {
            throw new IllegalStateException("SecureLayer.initialize(client) must be called before using the static facade");
        }
        return c;
    }

    public static String hash(byte[] data) {
        return client().hash(data);
    }

    public static String hash(String data) {
        return client().hash(data);
    }

    public static EncryptedPayload encrypt(byte[] plaintext, byte[] associatedData) {
        return client().encrypt(plaintext, associatedData);
    }

    public static EncryptedPayload encrypt(String plaintext) {
        return client().encrypt(plaintext);
    }

    public static byte[] decrypt(EncryptedPayload payload) {
        return client().decrypt(payload);
    }

    public static String decryptString(EncryptedPayload payload) {
        return client().decryptString(payload);
    }

    public static String sign(byte[] data) {
        return client().sign(data);
    }

    public static String sign(String data) {
        return client().sign(data);
    }

    public static boolean verify(byte[] data, String signatureBase64) {
        return client().verify(data, signatureBase64);
    }

    public static boolean verify(byte[] data, String signatureBase64, PublicKey publicKey) {
        return client().verify(data, signatureBase64, publicKey);
    }

    public static boolean verify(String data, String signatureBase64) {
        return client().verify(data, signatureBase64);
    }

    public static ProtectedRequest protectRequest(String method, String path, Map<String, String> headers, byte[] body) {
        return client().protectRequest(method, path, headers, body);
    }

    public static RequestVerificationResult verifyRequest(String method, String path, Map<String, String> headers, byte[] body) {
        return client().verifyRequest(method, path, headers, body);
    }

    public static AuthorizeResponse authorize(String subject, Collection<String> roles, Collection<String> scopes,
                                              String action, String resource, Map<String, String> attributes, String policyName) {
        return client().authorize(subject, roles, scopes, action, resource, attributes, policyName);
    }

    public static ValidateCertificateResponse validateDeviceCertificate(String deviceIdentifier, String pemCertificate) {
        return client().validateDeviceCertificate(deviceIdentifier, pemCertificate);
    }

    public static RecordAuditEventResponse recordAuditEvent(String subject, String action, String resource, String outcome, byte[] data) {
        return client().recordAuditEvent(subject, action, resource, outcome, data);
    }
}
