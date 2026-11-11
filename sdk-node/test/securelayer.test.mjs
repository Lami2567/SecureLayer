import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import test from "node:test";
import {
  SecureLayer,
  SecureLayerClient,
  secureLayerMiddleware,
  sha256,
} from "../dist/index.js";

function keys() {
  const pair = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function client(overrides = {}) {
  const signing = keys();
  return new SecureLayerClient({
    tenantId: "tenant-1",
    gatewayUrl: "https://securelayer.example",
    keys: {
      ...signing,
      signingKeyId: "signing-key-1",
      encryptionKey: {
        key: randomBytes(32).toString("base64"),
        keyId: "data-key-1",
        keyVersion: 1,
      },
      hmacKey: randomBytes(32).toString("base64"),
    },
    ...overrides,
  });
}

test("hashes structured data deterministically", () => {
  assert.equal(sha256({ b: 2, a: 1 }), sha256({ a: 1, b: 2 }));
  assert.equal(sha256("test-string"), sha256(Buffer.from("test-string")));
});

test("encrypts and decrypts with AES-256-GCM metadata and raw keys", () => {
  const sdk = client();
  const encrypted = sdk.encrypt({ message: "hello" });
  const decrypted = sdk.decrypt(encrypted).toString("utf8");

  assert.equal(encrypted.algorithm, "AES-256-GCM");
  assert.equal(encrypted.keyId, "data-key-1");
  assert.match(decrypted, /hello/);

  // Test encryption with raw base64 string
  const rawKeyBase64 = randomBytes(32).toString("base64");
  const enc2 = sdk.encrypt("secret payload", rawKeyBase64);
  const dec2 = sdk.decrypt(enc2, rawKeyBase64).toString("utf8");
  assert.equal(dec2, "secret payload");

  // Test encryption with raw Buffer key
  const bufferKey = randomBytes(32);
  const enc3 = sdk.encrypt({ amount: 1000 }, bufferKey);
  const dec3 = JSON.parse(sdk.decrypt(enc3, bufferKey).toString("utf8"));
  assert.equal(dec3.amount, 1000);
});

test("detects tampered ciphertext during AES-256-GCM decryption", () => {
  const sdk = client();
  const encrypted = sdk.encrypt({ sensitive: "data" });

  const tamperedTag = {
    ...encrypted,
    authTag: Buffer.alloc(16, 0).toString("base64"),
  };
  assert.throws(() => sdk.decrypt(tamperedTag), /Unsupported state or unable to authenticate/);
});

test("signs and verifies Ed25519 detached signatures", () => {
  const sdk = client();
  const signature = sdk.sign({ action: "read", resource: "/orders/42" });

  assert.equal(signature.algorithm, "Ed25519");
  assert.equal(sdk.verify({ resource: "/orders/42", action: "read" }, signature), true);
  assert.equal(sdk.verify({ resource: "/orders/43", action: "read" }, signature), false);

  // Verification with raw signature string
  assert.equal(sdk.verify({ resource: "/orders/42", action: "read" }, signature.signature), true);

  // Verification with external keypair
  const otherKeys = keys();
  const otherSig = sdk.sign("transfer", otherKeys.privateKeyPem);
  assert.equal(sdk.verify("transfer", otherSig, otherKeys.publicKeyPem), true);
  assert.equal(sdk.verify("transfer", otherSig, sdk.config.keys.publicKeyPem), false);
});

test("protects and verifies HTTP-style requests", async () => {
  const sdk = client();
  const protectedRequest = await sdk.protectRequest({
    method: "POST",
    path: "/orders",
    headers: { "content-type": "application/json" },
    body: { orderId: "42" },
  });

  assert.ok(protectedRequest.request.headers["x-request-id"]);
  assert.ok(protectedRequest.request.headers["x-message-sha256"]);
  assert.ok(protectedRequest.request.headers["x-securelayer-signature"]);
  assert.equal(protectedRequest.request.headers["x-securelayer-tenant-id"], "tenant-1");

  assert.deepEqual(await sdk.verifyRequest(protectedRequest.request), {
    verified: true,
    envelope: {
      requestId: protectedRequest.request.headers["x-request-id"],
      timestamp: protectedRequest.request.headers["x-request-timestamp"],
      tenantId: "tenant-1",
    },
  });

  // Tampered request body
  const tampered = {
    ...protectedRequest.request,
    body: { orderId: "43" },
  };
  const result = await sdk.verifyRequest(tampered);
  assert.equal(result.verified, false);
  assert.equal(result.reason, "Request body hash mismatch");

  // Missing metadata
  const missing = { method: "POST", path: "/orders", headers: {} };
  const missingResult = await sdk.verifyRequest(missing);
  assert.equal(missingResult.verified, false);
  assert.equal(missingResult.reason, "Missing SecureLayer request metadata");
});

test("rejects request when timestamp exceeds clock skew tolerance", async () => {
  const sdk = client({ timestampToleranceMs: 5000 });
  const protectedRequest = await sdk.protectRequest({
    method: "GET",
    path: "/health",
    headers: {},
  });

  // Alter timestamp to 10 minutes ago
  const oldHeaders = {
    ...protectedRequest.request.headers,
    "x-request-timestamp": new Date(Date.now() - 600000).toISOString(),
  };

  const check = await sdk.verifyRequest({
    ...protectedRequest.request,
    headers: oldHeaders,
  });

  assert.equal(check.verified, false);
  assert.equal(check.reason, "Request timestamp outside acceptable tolerance window");
});

test("delegates registration, authentication, policy, and audit flows to transport", async () => {
  const calls = [];
  const transport = {
    async registerApplication(tenantId, request, metadata) {
      calls.push(["registerApplication", tenantId, request, metadata]);
      return { id: "app-123" };
    },
    async registerDevice(tenantId, request, metadata) {
      calls.push(["registerDevice", tenantId, request, metadata]);
      return { deviceId: "dev-456", state: "ACTIVE" };
    },
    async validateCertificate(request, metadata) {
      calls.push(["validateCertificate", request, metadata]);
      return { status: "ACTIVE", decision: { decision: "ALLOW", allowed: true } };
    },
    async authorize(request, metadata) {
      calls.push(["authorize", request, metadata]);
      return {
        allowed: true,
        policyName: request.decisionPolicyName,
        policyVersion: 7,
        decision: { decision: "ALLOW", allowed: true },
      };
    },
    async recordAuditEvent(request, metadata) {
      calls.push(["recordAuditEvent", request, metadata]);
      return { auditEventId: "audit-1" };
    },
  };

  const sdk = client({ gatewayUrl: undefined, transport });

  const appRes = await sdk.registerApplication({
    name: "Payment App",
    clientId: "payment-app",
    clientSecret: "sec-123",
    redirectUris: ["https://example.com/callback"],
    scopes: ["pay"],
  });
  assert.equal(appRes.id, "app-123");

  const devRes = await sdk.registerDevice({
    name: "Laptop",
    deviceIdentifier: "laptop-1",
    certificateSigningRequestPem: "CSR-PEM",
  });
  assert.equal(devRes.deviceId, "dev-456");

  const authRes = await sdk.authenticate({
    deviceIdentifier: "laptop-1",
    pemCertificate: "CERT-PEM",
  });
  assert.equal(authRes.authenticated, true);
  assert.equal(authRes.status, "ACTIVE");

  const decision = await sdk.policyCheck({
    principal: { subject: "alice", scopes: ["orders:read"] },
    action: "GET",
    resource: "/orders/42",
    policyName: "orders",
  });
  assert.equal(decision.allowed, true);

  const audit = await sdk.auditEvent({
    principal: { subject: "alice" },
    action: "GET",
    resource: "/orders/42",
    outcome: "ALLOW",
  });
  assert.equal(audit.auditEventId, "audit-1");

  assert.equal(calls.length, 5);
});

test("static facade provides all APIs simply", async () => {
  const sdk = client();
  SecureLayer.initialize(sdk.config);

  // Hash
  assert.equal(SecureLayer.hash({ a: 1 }), sha256({ a: 1 }));

  // Encrypt / Decrypt
  const encrypted = SecureLayer.encrypt("confidential record");
  const decrypted = SecureLayer.decrypt(encrypted).toString("utf8");
  assert.equal(decrypted, "confidential record");

  // Sign / Verify
  const sig = SecureLayer.sign("wire transfer $500");
  assert.equal(SecureLayer.verify("wire transfer $500", sig), true);
  assert.equal(SecureLayer.verify("wire transfer $999", sig), false);

  // Protect / Verify request
  const protectedRequest = await SecureLayer.protectRequest({ path: "/status", body: { ok: true } });
  assert.equal((await SecureLayer.verifyRequest(protectedRequest.request)).verified, true);
});

test("secureLayerMiddleware automatically validates incoming requests", async () => {
  const sdk = client();
  SecureLayer.initialize(sdk.config);

  const middleware = secureLayerMiddleware();
  const protectedReq = await SecureLayer.protectRequest({
    method: "GET",
    path: "/api/data",
    headers: {},
  });

  // Valid request passes to next()
  let nextCalled = false;
  const mockReq = {
    method: "GET",
    url: "/api/data",
    headers: protectedReq.request.headers,
    body: undefined,
  };
  const mockRes = {
    statusCode: 200,
    setHeader: () => {},
    end: () => {},
  };

  await middleware(mockReq, mockRes, () => {
    nextCalled = true;
  });
  assert.equal(nextCalled, true);
  assert.equal(mockReq.secureLayer.verified, true);

  // Tampered request rejected with 401
  let failedStatus = 0;
  let failedPayload = null;
  const tamperedRes = {
    statusCode: 200,
    setHeader: () => {},
    end: (content) => {
      failedPayload = JSON.parse(content);
    },
  };
  Object.defineProperty(tamperedRes, "statusCode", {
    set(v) {
      failedStatus = v;
    },
  });

  const tamperedReq = {
    method: "GET",
    url: "/api/data",
    headers: {
      ...protectedReq.request.headers,
      "x-message-sha256": "invalid-hash",
    },
  };

  let tamperedNextCalled = false;
  await middleware(tamperedReq, tamperedRes, () => {
    tamperedNextCalled = true;
  });

  assert.equal(tamperedNextCalled, false);
  assert.equal(failedStatus, 401);
  assert.equal(failedPayload.code, "SECURELAYER_VERIFICATION_FAILED");
});
