package com.securelayer.sdk;

import com.google.protobuf.ByteString;
import com.google.protobuf.Struct;
import com.google.protobuf.Timestamp;
import com.google.protobuf.Value;
import com.securelayer.proto.v1.Application;
import com.securelayer.proto.v1.AuditServiceGrpc;
import com.securelayer.proto.v1.Authentication;
import com.securelayer.proto.v1.AuthorizeRequest;
import com.securelayer.proto.v1.AuthorizeResponse;
import com.securelayer.proto.v1.Certificate;
import com.securelayer.proto.v1.ControlPlaneServiceGrpc;
import com.securelayer.proto.v1.DataPlaneServiceGrpc;
import com.securelayer.proto.v1.Device;
import com.securelayer.proto.v1.DeviceState;
import com.securelayer.proto.v1.Principal;
import com.securelayer.proto.v1.ProtocolEnvelope;
import com.securelayer.proto.v1.RecordAuditEventRequest;
import com.securelayer.proto.v1.RecordAuditEventResponse;
import com.securelayer.proto.v1.RequestContext;
import com.securelayer.proto.v1.Role;
import com.securelayer.proto.v1.TenantRef;
import com.securelayer.proto.v1.ValidateCertificateRequest;
import com.securelayer.proto.v1.ValidateCertificateResponse;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public final class SecureLayerClient implements AutoCloseable {
    public static final String PROTOCOL_VERSION = "securelayer.v1";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_NONCE_LENGTH_BYTES = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final String tenantId;
    private final ApplicationIdentity application;
    private final DeviceIdentity device;
    private final KeyPair signingKeyPair;
    private final byte[] encryptionKey;
    private final byte[] hmacKey;
    private final String signingKeyId;
    private final Duration clockSkewTolerance;
    private final Channel channel;
    private final boolean managesChannel;

    private final DataPlaneServiceGrpc.DataPlaneServiceBlockingStub dataPlaneStub;
    private final ControlPlaneServiceGrpc.ControlPlaneServiceBlockingStub controlPlaneStub;
    private final AuditServiceGrpc.AuditServiceBlockingStub auditStub;

    private SecureLayerClient(Builder builder) {
        this.tenantId = builder.tenantId != null ? builder.tenantId : "default-tenant";
        this.application = builder.application;
        this.device = builder.device;
        this.signingKeyPair = builder.signingKeyPair;
        this.encryptionKey = builder.encryptionKey != null ? builder.encryptionKey.clone() : null;
        this.hmacKey = builder.hmacKey != null ? builder.hmacKey.clone() : null;
        this.signingKeyId = builder.signingKeyId;
        this.clockSkewTolerance = builder.clockSkewTolerance != null ? builder.clockSkewTolerance : Duration.ofMinutes(5);

        if (builder.channel != null) {
            this.channel = builder.channel;
            this.managesChannel = false;
        } else if (builder.grpcHost != null && builder.grpcPort > 0) {
            ManagedChannel managed = ManagedChannelBuilder.forAddress(builder.grpcHost, builder.grpcPort)
                    .usePlaintext()
                    .build();
            this.channel = managed;
            this.managesChannel = true;
        } else {
            this.channel = null;
            this.managesChannel = false;
        }

        if (this.channel != null) {
            this.dataPlaneStub = DataPlaneServiceGrpc.newBlockingStub(this.channel);
            this.controlPlaneStub = ControlPlaneServiceGrpc.newBlockingStub(this.channel);
            this.auditStub = AuditServiceGrpc.newBlockingStub(this.channel);
        } else {
            this.dataPlaneStub = null;
            this.controlPlaneStub = null;
            this.auditStub = null;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public String tenantId() {
        return tenantId;
    }

    public ApplicationIdentity application() {
        return application;
    }

    public DeviceIdentity device() {
        return device;
    }

    public KeyPair signingKeyPair() {
        return signingKeyPair;
    }

    // =========================================================================
    // Cryptography: Hashing (SHA-256)
    // =========================================================================

    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    public static String sha256Base64(byte[] input) {
        return Base64.getEncoder().encodeToString(sha256(input));
    }

    public static String sha256Base64(String input) {
        return sha256Base64(input.getBytes(StandardCharsets.UTF_8));
    }

    public String hash(byte[] input) {
        return sha256Base64(input);
    }

    public String hash(String input) {
        return sha256Base64(input);
    }

    // =========================================================================
    // Cryptography: Symmetric Encryption (AES-256-GCM)
    // =========================================================================

    public static EncryptedPayload encryptAes256Gcm(byte[] keyBytes, byte[] plaintext, byte[] associatedData) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            byte[] cipherWithTag = cipher.doFinal(plaintext);
            int ciphertextLength = cipherWithTag.length - 16;
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[16];
            System.arraycopy(cipherWithTag, 0, ciphertext, 0, ciphertextLength);
            System.arraycopy(cipherWithTag, ciphertextLength, tag, 0, 16);

            return new EncryptedPayload(
                    "AES-256-GCM",
                    Base64.getEncoder().encodeToString(nonce),
                    Base64.getEncoder().encodeToString(ciphertext),
                    Base64.getEncoder().encodeToString(tag),
                    associatedData != null ? Base64.getEncoder().encodeToString(associatedData) : null
            );
        } catch (Exception ex) {
            throw new RuntimeException("AES-256-GCM encryption failed", ex);
        }
    }

    public static byte[] decryptAes256Gcm(byte[] keyBytes, EncryptedPayload payload) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
        try {
            byte[] nonce = Base64.getDecoder().decode(payload.nonce());
            byte[] ciphertext = Base64.getDecoder().decode(payload.ciphertext());
            byte[] tag = Base64.getDecoder().decode(payload.authTag());
            byte[] cipherWithTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, cipherWithTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, cipherWithTag, ciphertext.length, tag.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            if (payload.associatedData() != null) {
                cipher.updateAAD(Base64.getDecoder().decode(payload.associatedData()));
            }

            return cipher.doFinal(cipherWithTag);
        } catch (Exception ex) {
            throw new RuntimeException("AES-256-GCM decryption failed", ex);
        }
    }

    public EncryptedPayload encrypt(byte[] plaintext, byte[] associatedData) {
        if (this.encryptionKey == null) {
            throw new IllegalStateException("No encryption key configured on SecureLayerClient");
        }
        return encryptAes256Gcm(this.encryptionKey, plaintext, associatedData);
    }

    public EncryptedPayload encrypt(String plaintext) {
        return encrypt(plaintext.getBytes(StandardCharsets.UTF_8), tenantId.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decrypt(EncryptedPayload payload) {
        if (this.encryptionKey == null) {
            throw new IllegalStateException("No encryption key configured on SecureLayerClient");
        }
        return decryptAes256Gcm(this.encryptionKey, payload);
    }

    public String decryptString(EncryptedPayload payload) {
        return new String(decrypt(payload), StandardCharsets.UTF_8);
    }

    // =========================================================================
    // Cryptography: Asymmetric Signing & Verification (Ed25519)
    // =========================================================================

    public static KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
                return generator.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Ed25519 is unavailable", e);
            }
        }
    }

    public static byte[] signEd25519(PrivateKey privateKey, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            try {
                Signature signature = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                signature.initSign(privateKey);
                signature.update(message);
                return signature.sign();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Ed25519 signing failed", e);
            }
        }
    }

    public static boolean verifyEd25519(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException ex) {
            try {
                Signature signature = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                signature.initVerify(publicKey);
                signature.update(message);
                return signature.verify(signatureBytes);
            } catch (GeneralSecurityException e) {
                return false;
            }
        }
    }

    public String sign(byte[] data) {
        if (this.signingKeyPair == null || this.signingKeyPair.getPrivate() == null) {
            throw new IllegalStateException("No Ed25519 private key configured for signing");
        }
        byte[] sig = signEd25519(this.signingKeyPair.getPrivate(), data);
        return Base64.getEncoder().encodeToString(sig);
    }

    public String sign(String data) {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    public boolean verify(byte[] data, String signatureBase64) {
        if (this.signingKeyPair == null || this.signingKeyPair.getPublic() == null) {
            throw new IllegalStateException("No Ed25519 public key configured for verification");
        }
        return verify(data, signatureBase64, this.signingKeyPair.getPublic());
    }

    public boolean verify(byte[] data, String signatureBase64, PublicKey publicKey) {
        try {
            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            return verifyEd25519(publicKey, data, sigBytes);
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean verify(String data, String signatureBase64) {
        return verify(data.getBytes(StandardCharsets.UTF_8), signatureBase64);
    }

    // =========================================================================
    // Cryptography: HMAC-SHA-256
    // =========================================================================

    public String hmac(byte[] data) {
        if (this.hmacKey == null) {
            throw new IllegalStateException("No HMAC key configured");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.hmacKey, "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal(data));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("HMAC-SHA-256 computation failed", ex);
        }
    }

    public boolean verifyHmac(byte[] data, String expectedHmac) {
        String actual = hmac(data);
        return MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8),
                expectedHmac.getBytes(StandardCharsets.UTF_8)
        );
    }

    // =========================================================================
    // Secure Communication: Request Protection & Verification
    // =========================================================================

    public ProtectedRequest protectRequest(String method, String path, Map<String, String> existingHeaders, byte[] body) {
        byte[] safeBody = body != null ? body : new byte[0];
        String bodyHash = sha256Base64(safeBody);
        String requestId = UUID.randomUUID().toString();
        String timestamp = Instant.now().toString();

        Map<String, String> headers = new LinkedHashMap<>();
        if (existingHeaders != null) {
            headers.putAll(existingHeaders);
        }
        headers.put("x-request-id", requestId);
        headers.put("x-request-timestamp", timestamp);
        headers.put("x-message-sha256", bodyHash);
        headers.put("x-securelayer-protocol", PROTOCOL_VERSION);
        headers.put("x-securelayer-tenant-id", this.tenantId);

        String canonical = canonicalRequest(method, path, bodyHash);
        String signature = null;
        if (this.signingKeyPair != null && this.signingKeyPair.getPrivate() != null) {
            signature = sign(canonical);
            headers.put("x-securelayer-signature", signature);
            if (this.signingKeyId != null) {
                headers.put("x-securelayer-key-id", this.signingKeyId);
            }
        }

        if (this.hmacKey != null) {
            headers.put("x-securelayer-hmac-sha256", hmac(canonical.getBytes(StandardCharsets.UTF_8)));
        }

        return new ProtectedRequest(method, path, headers, safeBody, bodyHash, signature, requestId, timestamp);
    }

    public RequestVerificationResult verifyRequest(String method, String path, Map<String, String> headers, byte[] body) {
        Map<String, String> normalized = new HashMap<>();
        if (headers != null) {
            headers.forEach((k, v) -> normalized.put(k.toLowerCase(), v));
        }

        String requestId = normalized.get("x-request-id");
        String timestamp = normalized.get("x-request-timestamp");
        String tenantId = normalized.get("x-securelayer-tenant-id");

        if (requestId == null || timestamp == null) {
            return RequestVerificationResult.failure("Missing SecureLayer request metadata", requestId, timestamp, tenantId);
        }

        // Clock skew verification
        try {
            Instant requestTime = Instant.parse(timestamp);
            Duration skew = Duration.between(requestTime, Instant.now()).abs();
            if (skew.compareTo(clockSkewTolerance) > 0) {
                return RequestVerificationResult.failure("Request timestamp outside acceptable tolerance window", requestId, timestamp, tenantId);
            }
        } catch (Exception ex) {
            return RequestVerificationResult.failure("Malformed request timestamp", requestId, timestamp, tenantId);
        }

        byte[] safeBody = body != null ? body : new byte[0];
        String expectedHash = normalized.get("x-message-sha256");
        String actualHash = sha256Base64(safeBody);
        if (expectedHash != null && !expectedHash.equals(actualHash)) {
            return RequestVerificationResult.failure("Request body hash mismatch", requestId, timestamp, tenantId);
        }

        String canonical = canonicalRequest(method, path, actualHash);
        String signature = normalized.get("x-securelayer-signature");
        if (signature != null && this.signingKeyPair != null && this.signingKeyPair.getPublic() != null) {
            if (!verify(canonical.getBytes(StandardCharsets.UTF_8), signature)) {
                return RequestVerificationResult.failure("Request signature verification failed", requestId, timestamp, tenantId);
            }
        }

        String hmacHeader = normalized.get("x-securelayer-hmac-sha256");
        if (hmacHeader != null && this.hmacKey != null) {
            if (!verifyHmac(canonical.getBytes(StandardCharsets.UTF_8), hmacHeader)) {
                return RequestVerificationResult.failure("Request HMAC verification failed", requestId, timestamp, tenantId);
            }
        }

        return RequestVerificationResult.success(requestId, timestamp, tenantId);
    }

    private String canonicalRequest(String method, String path, String bodyHash) {
        return (method != null ? method.toUpperCase() : "GET") + ":" + (path != null ? path : "/") + ":" + bodyHash;
    }

    private ProtocolEnvelope createEnvelope() {
        Instant now = Instant.now();
        return ProtocolEnvelope.newBuilder()
                .setRequestId(UUID.randomUUID().toString())
                .setTenant(TenantRef.newBuilder().setTenantId(tenantId).build())
                .setTimestamp(Timestamp.newBuilder().setSeconds(now.getEpochSecond()).setNanos(now.getNano()).build())
                .setProtocolVersion(PROTOCOL_VERSION)
                .build();
    }

    // =========================================================================
    // Control Plane & Data Plane gRPC Operations
    // =========================================================================

    public AuthorizeResponse authorize(String subject, Collection<String> roles, Collection<String> scopes,
                                       String action, String resource, Map<String, String> attributes, String policyName) {
        if (this.dataPlaneStub == null) {
            throw new IllegalStateException("gRPC channel not configured on SecureLayerClient");
        }

        ProtocolEnvelope envelope = createEnvelope();

        Principal.Builder principal = Principal.newBuilder()
                .setSubject(subject != null ? subject : "anonymous");
        if (scopes != null) principal.addAllScopes(scopes);
        if (roles != null) {
            for (String r : roles) {
                try {
                    principal.addRoles(Role.valueOf(r.toUpperCase()));
                } catch (Exception ignored) {}
            }
        }

        RequestContext.Builder context = RequestContext.newBuilder()
                .setResource(resource != null ? resource : "/")
                .setHttpMethod(action != null ? action : "GET");
        if (attributes != null && !attributes.isEmpty()) {
            Struct.Builder struct = Struct.newBuilder();
            attributes.forEach((k, v) -> struct.putFields(k, Value.newBuilder().setStringValue(v).build()));
            context.setAttributes(struct.build());
        }

        Authentication.Builder auth = Authentication.newBuilder()
                .setPrincipal(principal);
        if (this.application != null) {
            auth.setApplication(Application.newBuilder()
                    .setApplicationId(this.application.applicationId() != null ? this.application.applicationId() : "")
                    .setClientId(this.application.clientId() != null ? this.application.clientId() : "")
                    .setName(this.application.name() != null ? this.application.name() : "")
                    .setApproved(true)
                    .build());
        }
        if (this.device != null) {
            auth.setDevice(Device.newBuilder()
                    .setDeviceId(this.device.deviceId() != null ? this.device.deviceId() : "")
                    .setDeviceIdentifier(this.device.deviceIdentifier() != null ? this.device.deviceIdentifier() : "")
                    .setState(DeviceState.ACTIVE)
                    .setRegistered(true)
                    .build());
            if (this.device.certificatePem() != null) {
                auth.setCertificate(Certificate.newBuilder()
                        .setPemCertificate(ByteString.copyFromUtf8(this.device.certificatePem()))
                        .build());
            }
        }

        AuthorizeRequest request = AuthorizeRequest.newBuilder()
                .setTenant(TenantRef.newBuilder().setTenantId(tenantId).build())
                .setPrincipal(principal.build())
                .setAction(action)
                .setResource(resource)
                .setEnvelope(envelope)
                .setContext(context.build())
                .setAuthentication(auth.build())
                .build();

        return this.dataPlaneStub.authorize(request);
    }

    public ValidateCertificateResponse validateDeviceCertificate(String deviceIdentifier, String pemCertificate) {
        if (this.controlPlaneStub == null) {
            throw new IllegalStateException("gRPC channel not configured on SecureLayerClient");
        }

        ProtocolEnvelope envelope = createEnvelope();

        ValidateCertificateRequest request = ValidateCertificateRequest.newBuilder()
                .setEnvelope(envelope)
                .setTenant(TenantRef.newBuilder().setTenantId(tenantId).build())
                .setDeviceIdentifier(deviceIdentifier)
                .setCertificate(Certificate.newBuilder().setPemCertificate(ByteString.copyFromUtf8(pemCertificate)).build())
                .build();

        return this.controlPlaneStub.validateCertificate(request);
    }

    public RecordAuditEventResponse recordAuditEvent(String subject, String action, String resource, String outcome, byte[] data) {
        if (this.auditStub == null) {
            throw new IllegalStateException("gRPC channel not configured on SecureLayerClient");
        }

        ProtocolEnvelope envelope = createEnvelope();

        byte[] safeData = data != null ? data : new byte[0];
        byte[] eventHash = sha256(safeData);
        byte[] signatureBytes = this.signingKeyPair != null && this.signingKeyPair.getPrivate() != null
                ? signEd25519(this.signingKeyPair.getPrivate(), eventHash)
                : new byte[0];

        RecordAuditEventRequest request = RecordAuditEventRequest.newBuilder()
                .setTenant(TenantRef.newBuilder().setTenantId(tenantId).build())
                .setPrincipal(Principal.newBuilder().setSubject(subject != null ? subject : "system").build())
                .setAction(action)
                .setResource(resource)
                .setEventHashSha256(ByteString.copyFrom(eventHash))
                .setEd25519Signature(ByteString.copyFrom(signatureBytes))
                .setEnvelope(envelope)
                .build();

        return this.auditStub.recordAuditEvent(request);
    }

    @Override
    public void close() {
        if (managesChannel && channel instanceof ManagedChannel managed) {
            managed.shutdownNow();
        }
    }

    // =========================================================================
    // Builder Pattern
    // =========================================================================

    public static final class Builder {
        private String tenantId;
        private ApplicationIdentity application;
        private DeviceIdentity device;
        private KeyPair signingKeyPair;
        private byte[] encryptionKey;
        private byte[] hmacKey;
        private String signingKeyId;
        private Duration clockSkewTolerance;
        private Channel channel;
        private String grpcHost;
        private int grpcPort;

        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder application(ApplicationIdentity application) {
            this.application = application;
            return this;
        }

        public Builder application(String clientId, String name) {
            this.application = ApplicationIdentity.of(clientId, name);
            return this;
        }

        public Builder device(DeviceIdentity device) {
            this.device = device;
            return this;
        }

        public Builder device(String deviceIdentifier, String certificatePem) {
            this.device = DeviceIdentity.of(deviceIdentifier, certificatePem);
            return this;
        }

        public Builder signingKeyPair(KeyPair signingKeyPair) {
            this.signingKeyPair = signingKeyPair;
            return this;
        }

        public Builder signingKeyId(String signingKeyId) {
            this.signingKeyId = signingKeyId;
            return this;
        }

        public Builder privateKeyPem(String pem) {
            try (PEMParser parser = new PEMParser(new StringReader(pem))) {
                Object obj = parser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                if (obj instanceof PrivateKeyInfo pki) {
                    PrivateKey priv = converter.getPrivateKey(pki);
                    PublicKey pub = this.signingKeyPair != null ? this.signingKeyPair.getPublic() : null;
                    this.signingKeyPair = new KeyPair(pub, priv);
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException("Invalid private key PEM", ex);
            }
            return this;
        }

        public Builder publicKeyPem(String pem) {
            try (PEMParser parser = new PEMParser(new StringReader(pem))) {
                Object obj = parser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                if (obj instanceof SubjectPublicKeyInfo spki) {
                    PublicKey pub = converter.getPublicKey(spki);
                    PrivateKey priv = this.signingKeyPair != null ? this.signingKeyPair.getPrivate() : null;
                    this.signingKeyPair = new KeyPair(pub, priv);
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException("Invalid public key PEM", ex);
            }
            return this;
        }

        public Builder encryptionKey(byte[] encryptionKey) {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public Builder encryptionKeyBase64(String base64Key) {
            this.encryptionKey = Base64.getDecoder().decode(base64Key);
            return this;
        }

        public Builder hmacKey(byte[] hmacKey) {
            this.hmacKey = hmacKey;
            return this;
        }

        public Builder hmacKeyBase64(String base64Key) {
            this.hmacKey = Base64.getDecoder().decode(base64Key);
            return this;
        }

        public Builder clockSkewTolerance(Duration clockSkewTolerance) {
            this.clockSkewTolerance = clockSkewTolerance;
            return this;
        }

        public Builder channel(Channel channel) {
            this.channel = channel;
            return this;
        }

        public Builder grpcTarget(String host, int port) {
            this.grpcHost = host;
            this.grpcPort = port;
            return this;
        }

        public SecureLayerClient build() {
            return new SecureLayerClient(this);
        }
    }
}
