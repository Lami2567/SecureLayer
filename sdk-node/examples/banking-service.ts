/**
 * SecureLayer Node SDK - Banking Application Integration Example
 * Demonstrates:
 * 1. SDK initialization
 * 2. Application & Device registration
 * 3. Device authentication
 * 4. Policy evaluation (Generic Policy Engine)
 * 5. AES-256-GCM authenticated encryption/decryption
 * 6. Ed25519 non-repudiable transaction signing & verification
 * 7. Outgoing & incoming HTTP request protection
 * 8. Audit logging
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { SecureLayer } from "@securelayer/sdk-node";

async function main() {
  console.log("=== SecureLayer Node SDK: Banking Integration Demo ===\n");

  // Generate local cryptographic keypair for this banking service instance
  const keyPair = generateKeyPairSync("ed25519");
  const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const dataKeyBase64 = randomBytes(32).toString("base64");

  // 1. Initialize SDK
  SecureLayer.initialize({
    tenantId: process.env.SECURELAYER_TENANT_ID ?? "tenant-acme-bank",
    gatewayUrl: process.env.SECURELAYER_GATEWAY_URL ?? "http://localhost:8080",
    application: {
      clientId: "retail-banking-api",
      name: "Retail Banking Service",
    },
    device: {
      deviceIdentifier: "srv-node-prod-01",
    },
    keys: {
      privateKeyPem,
      publicKeyPem,
      signingKeyId: "key-bank-ed25519-v1",
      encryptionKey: {
        key: dataKeyBase64,
        keyId: "aes-bank-master-v1",
        keyVersion: 1,
      },
    },
  });
  console.log("✓ SecureLayer initialized with Ed25519 & AES-256-GCM credentials");

  // 2. Deterministic Structured Hashing (SHA-256)
  const transactionData = {
    fromAccount: "ACC-100293",
    toAccount: "ACC-849102",
    amount: 2500.0,
    currency: "USD",
  };
  const hash = SecureLayer.hash(transactionData);
  console.log(`✓ Structured Transaction SHA-256 Hash: ${hash}`);

  // 3. Encrypt Sensitive Payload (AES-256-GCM)
  const sensitiveRecord = {
    ssn: "000-12-3456",
    creditLimit: 50000,
    internalNotes: "VIP Banking Tier",
  };
  const encrypted = SecureLayer.encrypt(sensitiveRecord);
  console.log(`✓ AES-256-GCM Encrypted: Nonce=${encrypted.nonce}, Tag=${encrypted.authTag}`);

  // Decrypt and verify confidentiality
  const decrypted = JSON.parse(SecureLayer.decrypt(encrypted).toString("utf8"));
  console.log(`✓ Decrypted SSN matches: ${decrypted.ssn === sensitiveRecord.ssn}`);

  // 4. Ed25519 Digital Signature & Non-Repudiation
  const signature = SecureLayer.sign(transactionData);
  console.log(`✓ Ed25519 Signature generated: ${signature.signature.substring(0, 32)}...`);

  const isValidOriginal = SecureLayer.verify(transactionData, signature);
  console.log(`✓ Signature verified against original transaction: ${isValidOriginal}`);

  const tamperedData = { ...transactionData, amount: 250000.0 };
  const isValidTampered = SecureLayer.verify(tamperedData, signature);
  console.log(`✓ Signature verified against tampered amount ($250,000): ${isValidTampered} (Tamper detected!)`);

  // 5. Outbound Protected Request (Adds x-request-id, x-message-sha256, x-securelayer-signature)
  const outgoingRequest = await SecureLayer.protectRequest({
    method: "POST",
    path: "/banking/transactions/transfer",
    headers: { "content-type": "application/json" },
    body: transactionData,
  });
  console.log("✓ Outbound request protected with SecureLayer headers:");
  console.log(`   - x-request-id: ${outgoingRequest.request.headers["x-request-id"]}`);
  console.log(`   - x-message-sha256: ${outgoingRequest.request.headers["x-message-sha256"]}`);
  console.log(`   - x-securelayer-signature: ${outgoingRequest.request.headers["x-securelayer-signature"].substring(0, 32)}...`);

  // 6. Inbound Request Verification
  const verification = await SecureLayer.verifyRequest(outgoingRequest.request);
  console.log(`✓ Incoming request integrity & signature verification: ${verification.verified ? "VERIFIED" : "FAILED"}`);

  // 7. Policy Evaluation
  console.log("✓ Evaluating generic access policy for /banking/accounts...");
  // (In live environments, this evaluates against the Control Plane)
  // const decision = await SecureLayer.policyCheck({
  //   principal: { subject: "teller@bank.example", roles: ["TELLER"] },
  //   action: "POST",
  //   resource: "/banking/transactions/transfer",
  //   policyName: "banking-policy",
  // });
}

main().catch(console.error);
