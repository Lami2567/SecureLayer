# SecureLayer Java SDK (`sdk-java`)

The **SecureLayer Java SDK** is an enterprise-grade client library designed for Spring Boot and modern Java applications. It integrates directly with the SecureLayer Control Plane and Data Plane over gRPC (using Protocol Buffers v1) and provides local cryptographic operations using established primitives (Bouncy Castle & JCE).

---

## Features

- **Application Identity:** First-class binding to registered applications (`clientId`, `applicationId`, approval checks).
- **Device Identity:** Trusted device registration and validation using X.509 certificates and PKCS#10 CSR proof-of-possession.
- **Authentication:** Device certificate authentication and credential verification.
- **Confidentiality:** AES-256-GCM authenticated encryption with 12-byte cryptographically random nonces and 128-bit authentication tags.
- **Integrity:** SHA-256 deterministic hashing and HMAC-SHA-256 verification.
- **Non-Repudiation:** Ed25519 digital signature generation and verification.
- **Policy Enforcement:** Direct gRPC integration with the centralized Data Plane policy engine (`ALLOW`, `DENY`, `REQUIRE_MFA`, `REQUIRE_DEVICE_CERTIFICATE`).
- **Secure Communication:** Automated HTTP request protection (`x-request-id`, `x-request-timestamp`, `x-message-sha256`, `x-securelayer-signature`, `x-securelayer-tenant-id`) with replay clock-skew tolerance.
- **Audit Trail:** Tamper-evident audit event recording with cryptographic hash chaining.
- **Spring Boot Native:** Auto-configuration, `@ConfigurationProperties`, and `OncePerRequestFilter`.

---

## Maven Dependency

Add the SDK dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.securelayer</groupId>
    <artifactId>sdk-java</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

---

## Spring Boot Configuration (`application.yml`)

Configure the SDK easily in your Spring Boot application:

```yaml
securelayer:
  tenant-id: "tenant-bank-101"
  grpc-host: "localhost"
  grpc-port: 9090
  client-id: "retail-banking-client"
  application-name: "Retail Banking Portal"
  device-identifier: "srv-banking-node-01"
  certificate-pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  private-key-pem: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  public-key-pem: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  encryption-key-base64: "dGVzdC1rZXktMzItYnl0ZXMtbG9uZy1zZWN1cmVsYXllcjE="
  clock-skew-seconds: 300
```

With `SecureLayerAutoConfiguration` enabled, Spring automatically injects a fully configured `SecureLayerClient` bean and initializes the static `SecureLayer` facade.

---

## Quick Start: Builder Pattern

For programmatic or non-Spring use:

```java
import com.securelayer.sdk.SecureLayerClient;
import com.securelayer.sdk.EncryptedPayload;
import com.securelayer.sdk.SecureLayer;

SecureLayerClient client = SecureLayerClient.builder()
    .tenantId("tenant-bank-101")
    .application("retail-banking-client", "Retail Banking Portal")
    .device("srv-banking-node-01", certificatePem)
    .privateKeyPem(privateKeyPem)
    .publicKeyPem(publicKeyPem)
    .encryptionKeyBase64(aesKeyBase64)
    .grpcTarget("localhost", 9090)
    .build();

// Initialize the static facade
SecureLayer.initialize(client);
```

---

## Developer APIs

### 1. Encryption & Decryption (AES-256-GCM)

```java
// Encrypt sensitive data
EncryptedPayload payload = SecureLayer.encrypt("Account Balance: $1,250,000.00");

// Decrypt back to plaintext
String decrypted = SecureLayer.decryptString(payload);
```

### 2. Digital Signatures (Ed25519)

```java
// Create a digital signature
String signature = SecureLayer.sign("TRANSFER:ACC-101->ACC-202:AMOUNT=5000");

// Verify signature
boolean isValid = SecureLayer.verify("TRANSFER:ACC-101->ACC-202:AMOUNT=5000", signature);
// Returns true for identical data, false if tampered
```

### 3. Cryptographic Hashing (SHA-256)

```java
String hash = SecureLayer.hash("structured payload data");
```

### 4. HTTP Request Protection & Verification

Protect outbound HTTP calls:
```java
ProtectedRequest outbound = SecureLayer.protectRequest(
    "POST",
    "/banking/transfer",
    Map.of("Content-Type", "application/json"),
    jsonBytes
);

// outbound.headers() contains:
// - x-request-id
// - x-request-timestamp
// - x-message-sha256
// - x-securelayer-signature
// - x-securelayer-tenant-id
```

Verify inbound HTTP calls:
```java
RequestVerificationResult result = SecureLayer.verifyRequest(
    request.getMethod(),
    request.getRequestURI(),
    headersMap,
    requestBodyBytes
);

if (!result.verified()) {
    throw new SecurityException("Verification failed: " + result.reason());
}
```

### 5. Policy Checks (gRPC Data Plane)

```java
AuthorizeResponse decision = client.authorize(
    "alice@bank.example",
    List.of("TELLER"),
    List.of("accounts:read", "transfers:write"),
    "POST",
    "/banking/transfers",
    Map.of("risk", "low"),
    "banking-policy"
);

if (!decision.getAllowed()) {
    throw new AccessDeniedException("Access denied: " + decision.getDecision().getReason());
}
```

### 6. Audit Trail Ingestion (gRPC Control Plane)

```java
client.recordAuditEvent(
    "alice@bank.example",
    "EXECUTE_TRANSFER",
    "/banking/transfers",
    "ALLOW",
    transactionBytes
);
```

---

## Spring Boot Integration Example

See [`BankingApplicationExample.java`](file:///c:/Users/USER/Documents/BCS/21/DATA%20CODING%20AND%20ENCRYPTION/Coursework/sdk-java/src/main/java/com/securelayer/sdk/example/BankingApplicationExample.java):

```java
@RestController
@RequestMapping("/banking")
public class BankingController {
    private final SecureLayerClient secureLayer;

    public BankingController(SecureLayerClient secureLayer) {
        this.secureLayer = secureLayer;
    }

    @PostMapping("/transfers")
    public ResponseEntity<?> executeTransfer(@RequestBody TransferRequest req) {
        // 1. Sign transaction
        String signature = secureLayer.sign("TX:" + req.fromAccount() + "->" + req.toAccount());

        // 2. Encrypt sensitive record
        EncryptedPayload encrypted = secureLayer.encrypt(req.toString());

        // 3. Emit audit log
        secureLayer.recordAuditEvent("teller@bank.com", "TRANSFER", "/banking/transfers", "ALLOW", req.toString().getBytes());

        return ResponseEntity.ok(Map.of("signature", signature, "record", encrypted));
    }
}
```

---

## Running Tests

```bash
mvn test -pl sdk-java -am
```
