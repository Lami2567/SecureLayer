# SecureLayer Node.js & TypeScript SDK (`@securelayer/sdk-node`)

The **SecureLayer Node SDK** is a professional, production-grade security client that enables developers to integrate the SecureLayer platform into existing Node.js and TypeScript applications in minutes.

The SDK delivers:
- **Confidentiality:** AES-256-GCM authenticated symmetric encryption with 12-byte cryptographically secure nonces and authentication tags.
- **Integrity:** SHA-256 deterministic canonical JSON payload hashing and HMAC-SHA-256 message authentication.
- **Authentication:** Device-bound identity verification using X.509 certificates and PKCS#10 proof-of-possession.
- **Non-Repudiation:** Asymmetric digital signatures via standard Ed25519 elliptic curve cryptography.
- **Centralized Control Plane & Data Plane Policy Enforcement:** Zero duplication of security rules—all policy decisions (`ALLOW`, `DENY`, `REQUIRE_MFA`, `REQUIRE_DEVICE_CERTIFICATE`) and audit logs are delegated to the SecureLayer platform over the unified protocol.

---

## Installation

```bash
npm install @securelayer/sdk-node
```

---

## Quick Start: Static API

```typescript
import { SecureLayer } from "@securelayer/sdk-node";

// 1. Initialize once at application bootstrap
SecureLayer.initialize({
  tenantId: process.env.SECURELAYER_TENANT_ID!,
  gatewayUrl: process.env.SECURELAYER_GATEWAY_URL!,
  bearerToken: process.env.SECURELAYER_BEARER_TOKEN,
  application: {
    clientId: "banking-api",
    name: "Retail Banking Service",
  },
  device: {
    deviceIdentifier: "srv-node-prod-01",
    certificatePem: process.env.SECURELAYER_DEVICE_CERT_PEM,
  },
  keys: {
    privateKeyPem: process.env.SECURELAYER_PRIVATE_KEY_PEM,
    publicKeyPem: process.env.SECURELAYER_PUBLIC_KEY_PEM,
    signingKeyId: "key-ed25519-v1",
    encryptionKey: {
      key: process.env.SECURELAYER_DATA_KEY_BASE64!,
      keyId: "aes-master-key-v1",
      keyVersion: 1,
    },
  },
});
```

---

## API Reference

### 1. Request Protection & Verification

#### Outbound HTTP Request (`protectRequest`)
Wraps any HTTP-style request with SecureLayer protocol headers (`x-request-id`, `x-request-timestamp`, `x-message-sha256`, `x-securelayer-signature`, `x-securelayer-tenant-id`):

```typescript
const protectedRequest = await SecureLayer.protectRequest({
  method: "POST",
  path: "/banking/transactions/transfer",
  headers: { "content-type": "application/json" },
  body: {
    fromAccount: "ACC-100293",
    toAccount: "ACC-849102",
    amount: 5000.00,
  },
});

// Send with standard fetch, axios, or got
const response = await fetch("https://api.bank.com/banking/transactions/transfer", {
  method: protectedRequest.request.method,
  headers: protectedRequest.request.headers,
  body: JSON.stringify(protectedRequest.request.body),
});
```

#### Inbound Request Verification (`verifyRequest`)
Validates request timestamps, body hash integrity, and Ed25519/HMAC signatures in one call:

```typescript
const verification = await SecureLayer.verifyRequest({
  method: req.method,
  path: req.path,
  headers: req.headers,
  body: req.body,
});

if (!verification.verified) {
  res.status(401).json({ error: verification.reason });
  return;
}
```

#### Express Middleware (`secureLayerMiddleware`)
For zero-boilerplate protection in Express/Connect applications:

```typescript
import express from "express";
import { SecureLayer, secureLayerMiddleware } from "@securelayer/sdk-node";

const app = express();
app.use(express.json());

// Protect all /api routes
app.use("/api", secureLayerMiddleware({
  onFailure: (reason, req, res) => res.status(403).json({ error: reason }),
}));
```

---

### 2. Cryptographic Engine

#### Digital Signatures (`sign` and `verify`)
Provides cryptographic non-repudiation with Ed25519:

```typescript
// Create a signed transaction
const signature = SecureLayer.sign(transactionPayload);

// Verify signature authenticity
const isValid = SecureLayer.verify(transactionPayload, signature);
// Returns true for pristine payload, false if tampered
```

#### Symmetric Encryption (`encrypt` and `decrypt`)
Authenticated encryption using AES-256-GCM:

```typescript
// Encrypt sensitive fields (supports objects, strings, buffers)
const encrypted = SecureLayer.encrypt({ balance: 250000.00, currency: "USD" });

// Decrypt back to Buffer
const decryptedBuffer = SecureLayer.decrypt(encrypted);
const original = JSON.parse(decryptedBuffer.toString("utf8"));
```

#### Cryptographic Hashing (`hash`)
Deterministic SHA-256 canonical hashing across objects and data:

```typescript
const digestBase64 = SecureLayer.hash({ b: 2, a: 1 });
// Guaranteed identical hash regardless of JSON object key ordering
```

---

### 3. Application & Device Management

#### Register Application
Registers a client application in the SecureLayer Control Plane:

```typescript
const app = await SecureLayer.registerApplication({
  name: "Retail Banking Portal",
  clientId: "retail-banking-client",
  clientSecret: "client-secret-key-123",
  redirectUris: ["https://retail.bank.com/oauth/callback"],
  scopes: ["accounts:read", "transfers:write"],
});
```

#### Register Device
Registers a trusted device with a PKCS#10 Certificate Signing Request (CSR):

```typescript
const device = await SecureLayer.registerDevice({
  name: "Corporate iPad - Branch 42",
  deviceIdentifier: "device-corp-ipad-42",
  certificateSigningRequestPem: csrPemString,
});
```

#### Authenticate Device
Validates a device's X.509 certificate and checks its revocation status:

```typescript
const authResult = await SecureLayer.authenticate({
  deviceIdentifier: "device-corp-ipad-42",
  pemCertificate: certificatePemString,
});

if (authResult.authenticated) {
  console.log(`Device state: ${authResult.status}`); // ACTIVE
}
```

---

### 4. Policy Checks & Audit Ingestion

#### Policy Evaluation (`policyCheck`)
Evaluates user identity, device state, roles, IP network, and context against versioned policies:

```typescript
const decision = await SecureLayer.policyCheck({
  principal: {
    subject: "alice@bank.example",
    roles: ["TELLER"],
    scopes: ["transfers:write"],
  },
  action: "POST",
  resource: "/banking/transactions/transfer",
  policyName: "banking-policy",
  context: {
    ipAddress: "192.168.1.100",
    attributes: { amount: 5000.00 },
  },
});

if (!decision.allowed) {
  throw new Error(`Policy denied: ${decision.decision?.reason}`);
}
```

#### Audit Event Logging (`auditEvent`)
Emits tamper-evident audit records bound to tenant identity and cryptographic digests:

```typescript
await SecureLayer.auditEvent({
  principal: { subject: "alice@bank.example" },
  action: "EXECUTE_TRANSFER",
  resource: "/banking/transactions/transfer",
  outcome: "ALLOW",
  data: { transactionId: "tx_98214", amount: 5000.00 },
});
```

---

## Instance-Based Client (`SecureLayerClient`)

For multi-tenant architectures or test doubles, instantiate clients directly:

```typescript
import { SecureLayerClient } from "@securelayer/sdk-node";

const client = new SecureLayerClient({
  tenantId: "tenant-custom",
  gatewayUrl: "https://gateway.internal:8443",
  keys: { ... },
});

const encrypted = client.encrypt("tenant-secret");
```

---

## Testing

Run the full SDK test suite:

```bash
npm --workspace @securelayer/sdk-node test
```
