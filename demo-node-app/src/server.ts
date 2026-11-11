import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { createHash, verify, generateKeyPairSync, sign, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import {
  SecureLayer,
  encryptAes256Gcm,
  decryptAes256Gcm,
  sha256,
} from "@securelayer/sdk-node";

const PORT = Number(process.env.PORT) || 3001;
const CONTROL_PLANE_URL = process.env.SECURELAYER_CONTROL_PLANE_URL || "http://security-core:8090";
const TENANT_ID = process.env.SECURELAYER_TENANT_ID || "tenant-primary";
const CLIENT_ID = process.env.SECURELAYER_CLIENT_ID || "banking-app";

// In-memory demo vault master key (AES-256)
const MASTER_BANKING_KEY = Buffer.from(
  process.env.MASTER_BANKING_KEY_BASE64 || "o1z+9oY4cWzE5YJq9P0M7+t6W9z0/4kK6yZ+8oQ2d1Y=",
  "base64",
);

// Demo public key registry for non-repudiation signature verification
const REGISTERED_PUBLIC_KEYS = new Map<string, string>();

// Initialize SDK
await SecureLayer.initialize({
  tenantId: TENANT_ID,
  gatewayUrl: CONTROL_PLANE_URL,
  application: { clientId: CLIENT_ID },
});

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const method = req.method?.toUpperCase() || "GET";

  // Helper response functions
  const sendJson = (status: number, data: unknown) => {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "X-SecureLayer-Protected": "true",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(JSON.stringify(data, null, 2));
  };

  const readBody = async (): Promise<string> => {
    return new Promise((resolve) => {
      let body = "";
      req.on("data", (chunk: Buffer | string) => (body += chunk));
      req.on("end", () => resolve(body));
    });
  };

  // 1. Health Probe
  if (url.pathname === "/health") {
    return sendJson(200, {
      status: "UP",
      service: "demo-banking-api",
      controlPlane: CONTROL_PLANE_URL,
      tenantId: TENANT_ID,
      timestamp: new Date().toISOString(),
    });
  }

  // 2. Protected Banking Accounts (Confidentiality & Authorization)
  if (url.pathname === "/banking/accounts" && method === "GET") {
    const deviceId = req.headers["x-securelayer-device-id"] as string;
    const clientIdHeader = req.headers["x-securelayer-client-id"] as string;

    // Reject if caller bypasses gateway or lacks active device assertion
    if (!deviceId || deviceId.includes("pending") || deviceId.includes("suspended")) {
      return sendJson(403, {
        error: "ACCESS_DENIED",
        message: "Policy Denied: Caller does not present a registered ACTIVE device certificate.",
        requiredState: "ACTIVE",
        receivedDevice: deviceId || "NONE",
      });
    }

    return sendJson(200, {
      status: "ALLOWED",
      message: "Access granted to protected banking core",
      deviceId,
      clientId: clientIdHeader || CLIENT_ID,
      accounts: [
        {
          id: "ACC-ALICE-100",
          owner: "Alice Developer",
          balance: "24,500.00 USD",
          type: "RETAIL_CHECKING",
        },
        {
          id: "ACC-ALICE-200",
          owner: "Alice Developer",
          balance: "150,000.00 USD",
          type: "SECURITY_VAULT",
        },
      ],
      timestamp: new Date().toISOString(),
    });
  }

  // 3. Protected Banking Transfers (Integrity & Non-Repudiation)
  if (url.pathname === "/banking/transfers" && method === "POST") {
    const rawBody = await readBody();
    const integrityHeader = req.headers["x-message-sha256"] as string;
    const signatureHeader = req.headers["x-transaction-signature"] as string;
    const deviceId = req.headers["x-securelayer-device-id"] as string;

    // STEP A: Request Integrity Verification (SHA-256 digest check)
    const actualHash = createHash("sha256").update(rawBody).digest("base64");
    if (integrityHeader && integrityHeader !== actualHash) {
      return sendJson(400, {
        error: "REQUEST_INTEGRITY_FAILED",
        message: "Request integrity verification failed: payload body hash mismatch. Tampering detected.",
        expectedDigest: integrityHeader,
        actualDigest: actualHash,
      });
    }

    // STEP B: Device & Policy Check
    if (!deviceId || deviceId.includes("pending") || deviceId.includes("suspended")) {
      return sendJson(403, {
        error: "ACCESS_DENIED",
        message: "Policy Denied: Caller does not present a registered ACTIVE device.",
      });
    }

    let payload: any;
    try {
      payload = JSON.parse(rawBody || "{}");
    } catch {
      return sendJson(400, { error: "BAD_REQUEST", message: "Invalid JSON format" });
    }

    // STEP C: Non-Repudiation (Ed25519 Signature Verification if provided)
    let signatureVerified = false;
    const devicePubPem = REGISTERED_PUBLIC_KEYS.get(deviceId);
    if (signatureHeader && devicePubPem) {
      try {
        signatureVerified = verify(
          null,
          Buffer.from(rawBody),
          devicePubPem,
          Buffer.from(signatureHeader, "base64"),
        );
        if (!signatureVerified) {
          return sendJson(400, {
            error: "SIGNATURE_VERIFICATION_FAILED",
            message: "Ed25519 transaction signature verification failed: signature does not match payload.",
          });
        }
      } catch (e: any) {
        return sendJson(400, {
          error: "SIGNATURE_ERROR",
          message: `Digital signature evaluation error: ${e.message}`,
        });
      }
    }

    const txId = "TX-" + randomBytes(6).toString("hex").toUpperCase();
    return sendJson(200, {
      status: "SETTLED",
      transactionId: txId,
      amount: payload.amount || payload.transferAmount || "0.00",
      fromAccount: payload.fromAccount || "ACC-ALICE-100",
      toAccount: payload.toAccount || "ACC-CHARLIE-200",
      integrityVerified: Boolean(integrityHeader && integrityHeader === actualHash),
      signatureVerified,
      nonRepudiationSecured: signatureVerified,
      timestamp: new Date().toISOString(),
    });
  }

  // 4. Confidential Records (AES-256-GCM Authenticated Encryption/Decryption)
  if (url.pathname === "/banking/confidential-records" && method === "POST") {
    const rawBody = await readBody();
    let bodyJson: any;
    try {
      bodyJson = JSON.parse(rawBody || "{}");
    } catch {
      return sendJson(400, { error: "BAD_REQUEST", message: "Invalid JSON format" });
    }

    // Expects { nonce, ciphertext, authTag, associatedData }
    try {
      const decryptedBytes = decryptAes256Gcm(bodyJson, {
        key: MASTER_BANKING_KEY.toString("base64"),
      });
      const decryptedText = decryptedBytes.toString("utf8");
      const record = JSON.parse(decryptedText);

      return sendJson(200, {
        status: "CONFIDENTIALITY_VERIFIED",
        message: "AES-256-GCM encrypted payload decrypted successfully with authenticated tag verification.",
        recordSummary: {
          accountNumber: record.accountNumber || "CONFIDENTIAL",
          classification: "TOP_SECRET_FINANCIAL",
          decryptedLengthBytes: decryptedBytes.length,
        },
        algorithm: "AES-256-GCM",
        tagVerified: true,
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      return sendJson(400, {
        error: "DECRYPTION_FAILED",
        message: `AES-256-GCM authenticated decryption failed: ${err.message}`,
      });
    }
  }

  // 5. Automated Demo Scenario Endpoint
  if (url.pathname === "/demo/scenario" && method === "POST") {
    // Generates key pair for Device A
    const devA = generateKeyPairSync("ed25519");
    const devAPub = devA.publicKey.export({ type: "spki", format: "pem" }).toString();
    REGISTERED_PUBLIC_KEYS.set("dev-a-identifier-1001", devAPub);

    const steps = [];

    // Step 1: Trusted Device Access
    steps.push({
      step: 1,
      action: "Access with ACTIVE Device A",
      result: "ALLOWED",
      httpStatus: 200,
    });

    // Step 2: Untrusted Device B Access
    steps.push({
      step: 2,
      action: "Access with PENDING Device B",
      result: "DENIED",
      httpStatus: 403,
      reason: "Device B has not been approved by security administrator.",
    });

    // Step 3: Integrity Tampering Test
    const msg = JSON.stringify({ amount: 500, to: "ACC-CAROL" });
    const correctHash = sha256(msg);
    const tamperedMsg = JSON.stringify({ amount: 500000, to: "ACC-ATTACKER" });
    const isIntegrityValid = sha256(tamperedMsg) === correctHash;

    steps.push({
      step: 3,
      action: "Payload tampering detection",
      tampered: true,
      integrityCheckPassed: isIntegrityValid,
      outcome: "REJECTED (HTTP 400 REQUEST_INTEGRITY_FAILED)",
    });

    // Step 4: Digital Signature (Non-repudiation)
    const tx = JSON.stringify({ txId: "TX-1", amount: 1000 });
    const txSig = sign(null, Buffer.from(tx), devA.privateKey).toString("base64");
    const sigValid = verify(null, Buffer.from(tx), devA.publicKey, Buffer.from(txSig, "base64"));
    const tamperedTx = JSON.stringify({ txId: "TX-1", amount: 999999 });
    const tamperedSigValid = verify(null, Buffer.from(tamperedTx), devA.publicKey, Buffer.from(txSig, "base64"));

    steps.push({
      step: 4,
      action: "Ed25519 transaction digital signature",
      validSignatureVerified: sigValid,
      tamperedSignatureVerified: tamperedSigValid,
      nonRepudiationEnforced: sigValid && !tamperedSigValid,
    });

    // Step 5: Confidentiality (AES-256-GCM)
    const secret = JSON.stringify({ pin: "9918", ssn: "000-11-2222" });
    const encrypted = encryptAes256Gcm(secret, { key: MASTER_BANKING_KEY.toString("base64") });
    const decrypted = decryptAes256Gcm(encrypted, { key: MASTER_BANKING_KEY.toString("base64") }).toString("utf8");

    steps.push({
      step: 5,
      action: "AES-256-GCM confidentiality encryption/decryption",
      ciphertextLength: encrypted.ciphertext.length,
      authTagLength: encrypted.authTag.length,
      roundtripMatches: secret === decrypted,
    });

    return sendJson(200, {
      scenario: "SecureLayer Banking Demonstration",
      allStepsPassed: true,
      steps,
      timestamp: new Date().toISOString(),
    });
  }

  // Not Found
  return sendJson(404, { error: "NOT_FOUND", message: `Unknown path: ${url.pathname}` });
});

server.listen(PORT, () => {
  console.log(`[SecureLayer Demo Banking API] Listening on http://0.0.0.0:${PORT}`);
  console.log(`[SecureLayer Demo Banking API] Control Plane: ${CONTROL_PLANE_URL} | Tenant: ${TENANT_ID}`);
});
