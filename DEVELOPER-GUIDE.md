# SecureLayer Developer & SDK Integration Guide

## 1. Introduction

SecureLayer provides official SDKs for **Node.js / TypeScript**, **Python**, and **Java** that encapsulate cryptographic operations, request protection headers, and control plane interactions.

---

## 2. Node.js / TypeScript SDK (`@securelayer/sdk-node`)

### Installation
```bash
npm install @securelayer/sdk-node
```

### 2.1. Initialization
```typescript
import { SecureLayer } from "@securelayer/sdk-node";

await SecureLayer.initialize({
  tenantId: "00000000-0000-0000-0000-000000000001",
  gatewayUrl: "http://localhost:8080",
  application: {
    clientId: "banking-app",
  },
});
```

### 2.2. Protecting an Outgoing HTTP Request
The SDK automatically calculates `X-Message-Sha256` and appends device identity headers:
```typescript
const payload = JSON.stringify({ amount: 5000, toAccount: "ACC-CHARLIE-200" });

const protectedRequest = SecureLayer.protectRequest({
  url: "http://localhost:8080/banking/transfers",
  method: "POST",
  body: payload,
  deviceId: "dev-a-active-1001",
});

// Sends headers:
// X-Message-Sha256: <Base64 SHA-256 Digest>
// X-SecureLayer-Client-Id: banking-app
// X-SecureLayer-Device-Id: dev-a-active-1001
const response = await fetch(protectedRequest.url, {
  method: protectedRequest.method,
  headers: protectedRequest.headers,
  body: protectedRequest.body,
});
```

### 2.3. End-to-End AEAD Encryption (AES-256-GCM)
```typescript
import { encryptAes256Gcm, decryptAes256Gcm } from "@securelayer/sdk-node";

const secretData = JSON.stringify({ routingNumber: "021000021", ssn: "000-11-2222" });
const masterKeyB64 = "o1z+9oY4cWzE5YJq9P0M7+t6W9z0/4kK6yZ+8oQ2d1Y=";

// 1. Encrypt
const encryptedEnvelope = encryptAes256Gcm(secretData, { key: masterKeyB64 });
// encryptedEnvelope contains: { nonce, ciphertext, authTag }

// 2. Decrypt
const decryptedBuffer = decryptAes256Gcm(encryptedEnvelope, { key: masterKeyB64 });
const recoveredData = decryptedBuffer.toString("utf8");
console.log(recoveredData === secretData); // true
```

### 2.4. Digital Signatures & Non-Repudiation (Ed25519)
```typescript
import { generateKeyPairSync, sign, verify } from "node:crypto";

// Generate key pair
const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const transaction = JSON.stringify({ txId: "TX-9021", amount: 1500 });
const signature = sign(null, Buffer.from(transaction), privateKey).toString("base64");

// Verifying signature
const isAuthentic = verify(null, Buffer.from(transaction), publicKey, Buffer.from(signature, "base64"));
console.log(`Transaction Signature Authentic: ${isAuthentic}`); // true
```

---

## 3. Python SDK (`securelayer-sdk`)

### Installation
```bash
pip install -e ./sdk-python
```

### 3.1. AES-256-GCM Authenticated Encryption
```python
import base64
import securelayer

master_key = base64.b64decode("o1z+9oY4cWzE5YJq9P0M7+t6W9z0/4kK6yZ+8oQ2d1Y=")
plaintext = b"Confidential Financial Wire Payload"

# Encrypt (returns dict with nonce, ciphertext, authTag)
encrypted = securelayer.encrypt_aes_256_gcm(master_key, plaintext)

# Decrypt
recovered = securelayer.decrypt_aes_256_gcm(master_key, encrypted)
assert recovered == plaintext
```

### 3.2. Ed25519 Signing & Verification
```python
import securelayer

# Generate Device Asymmetric Key Pair
priv_pem, pub_pem = securelayer.generate_ed25519_keypair()

message = b"Authorize wire transfer $50,000 to Bob"

# Sign
signature_b64 = securelayer.sign_ed25519(priv_pem, message)

# Verify
is_valid = securelayer.verify_ed25519(pub_pem, message, signature_b64)
assert is_valid is True
```

---

## 4. Java SDK (`sdk-java`)

### Maven Dependency
```xml
<dependency>
    <groupId>com.securelayer</groupId>
    <artifactId>sdk-java</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

### Spring Boot Filter Integration
```java
@Configuration
public class SecurityFilterConfig {

    @Bean
    public FilterRegistrationBean<SecureLayerGatewayFilter> secureLayerFilter(SecureLayerGatewayFilter filter) {
        FilterRegistrationBean<SecureLayerGatewayFilter> registration = new FilterRegistrationBean<>(filter);
        registration.addUrlPatterns("/banking/*", "/api/*");
        registration.setOrder(1);
        return registration;
    }
}
```
All incoming requests to `/banking/*` will automatically undergo SHA-256 message integrity checking and device validation before executing your `@RestController` methods.
