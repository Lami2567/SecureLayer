import assert from "node:assert/strict";
import test from "node:test";
import {
  ensureDeviceKey,
  publicJwk,
  publicJwkThumbprint,
  sha256Base64,
  signContext,
  verifySignature,
  resetKeyForTesting,
} from "../dist/crypto.js";

test("Web Crypto: generates non-extractable device ECDSA P-256 key pair", async () => {
  resetKeyForTesting();
  const keyPair = await ensureDeviceKey();

  assert.ok(keyPair.publicKey);
  assert.ok(keyPair.privateKey);
  assert.equal(keyPair.publicKey.algorithm.name, "ECDSA");
  assert.equal(keyPair.privateKey.extractable, false, "Private key MUST NOT be extractable");

  // Attempting to export the private key must throw an error in Web Crypto
  await assert.rejects(
    async () => {
      await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    },
    /key is not extractable/i,
  );
});

test("Web Crypto: calculates SHA-256 digest accurately", async () => {
  const digest1 = await sha256Base64("SecureLayer Banking Test Payload");
  const digest2 = await sha256Base64("SecureLayer Banking Test Payload");
  const digestDiff = await sha256Base64("Tampered Banking Payload");

  assert.equal(digest1, digest2);
  assert.notEqual(digest1, digestDiff);
  assert.ok(digest1.length > 0);
});

test("Web Crypto: generates valid public JWK thumbprint", async () => {
  resetKeyForTesting();
  const keyPair = await ensureDeviceKey();
  const thumbprint = await publicJwkThumbprint(keyPair);
  const jwk = await publicJwk(keyPair);

  assert.ok(thumbprint.length > 0);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.ok(jwk.x);
  assert.ok(jwk.y);
});

test("Web Crypto: signs payload and verifies signature, detects tampering", async () => {
  resetKeyForTesting();
  const keyPair = await ensureDeviceKey();

  const auditPayload = {
    applicationId: "banking-web",
    decision: "ALLOW",
    deviceIdentifier: "dev-active-1001",
    url: "https://bank.example.com/accounts",
    evaluatedAt: "2026-10-11T12:00:00Z",
  };

  const signature = await signContext(auditPayload, keyPair);
  assert.ok(signature.length > 0);

  // Verification with identical payload succeeds
  const isValid = await verifySignature(auditPayload, signature, keyPair.publicKey);
  assert.equal(isValid, true, "Signature on original payload must be valid");

  // Verification on tampered payload fails
  const tamperedPayload = { ...auditPayload, decision: "DENIED_TAMPERED" };
  const isTamperedValid = await verifySignature(tamperedPayload, signature, keyPair.publicKey);
  assert.equal(isTamperedValid, false, "Tampered payload verification must fail");
});
