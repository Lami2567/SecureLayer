import { NextRequest, NextResponse } from "next/server";
import {
  createHash,
  generateKeyPairSync,
  sign,
  createCipheriv,
  randomBytes,
} from "node:crypto";

const MASTER_KEY_B64 =
  process.env.MASTER_BANKING_KEY_BASE64 ||
  "o1z+9oY4cWzE5YJq9P0M7+t6W9z0/4kK6yZ+8oQ2d1Y=";
const MASTER_KEY = Buffer.from(MASTER_KEY_B64, "base64");

async function fetchWithFallback(
  urls: string[],
  init?: RequestInit,
  timeoutMs = 2500
): Promise<{ ok: boolean; status: number; latencyMs: number; data: any; urlUsed: string }> {
  let lastError: any = null;
  for (const url of urls) {
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(url, {
        ...init,
        signal: controller.signal,
        cache: "no-store",
      });
      clearTimeout(timer);
      const latencyMs = Math.max(1, Date.now() - start);
      const text = await res.text();
      let data: any = text;
      try {
        data = JSON.parse(text);
      } catch {
        // leave as text
      }
      return {
        ok: res.ok,
        status: res.status,
        latencyMs,
        data,
        urlUsed: url,
      };
    } catch (err: any) {
      lastError = err;
    }
  }
  return {
    ok: false,
    status: 503,
    latencyMs: 0,
    data: { error: "SERVICE_UNREACHABLE", message: lastError?.message || "Connection failed" },
    urlUsed: urls[0],
  };
}

export async function GET(req: NextRequest) {
  const [gatewayHealth, gatewayPlatform, coreHealth, nodeHealth, pythonHealth] =
    await Promise.all([
      fetchWithFallback([
        "http://gateway:8080/actuator/health",
        "http://localhost:8080/actuator/health",
      ]),
      fetchWithFallback([
        "http://gateway:8080/api/v1/platform",
        "http://localhost:8080/api/v1/platform",
      ]),
      fetchWithFallback([
        "http://security-core:8090/actuator/health",
        "http://localhost:8090/actuator/health",
      ]),
      fetchWithFallback([
        "http://demo-node-app:3001/health",
        "http://localhost:3001/health",
      ]),
      fetchWithFallback([
        "http://demo-python-app:3002/health",
        "http://localhost:3002/health",
      ]),
    ]);

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    platform: gatewayPlatform.ok
      ? gatewayPlatform.data
      : {
          name: "SecureLayer",
          environment: "local",
          securityGoals: [
            "confidentiality",
            "integrity",
            "authentication",
            "non-repudiation",
          ],
        },
    services: {
      gateway: {
        name: "securelayer-gateway",
        role: "Zero-Trust Reverse Proxy",
        port: 8080,
        online: gatewayHealth.ok,
        status: gatewayHealth.status,
        latencyMs: gatewayHealth.latencyMs,
        details: gatewayHealth.data,
      },
      securityCore: {
        name: "securelayer-security-core",
        role: "Control Plane & X.509 CA",
        port: 8090,
        grpcPort: 9090,
        online: coreHealth.ok,
        status: coreHealth.status,
        latencyMs: coreHealth.latencyMs,
        details: coreHealth.data,
      },
      bankingApi: {
        name: "securelayer-demo-node-app",
        role: "Protected Banking API",
        port: 3001,
        online: nodeHealth.ok,
        status: nodeHealth.status,
        latencyMs: nodeHealth.latencyMs,
        details: nodeHealth.data,
      },
      pythonVerifier: {
        name: "securelayer-demo-python-app",
        role: "Cross-Service Crypto Verifier",
        port: 3002,
        online: pythonHealth.ok,
        status: pythonHealth.status,
        latencyMs: pythonHealth.latencyMs,
        details: pythonHealth.data,
      },
    },
  });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const action = body.action as string;

  // 1. Live Device Authentication & Policy Enforcement check -> GET /banking/accounts
  if (action === "test_device_access") {
    const deviceIdentifier = body.deviceIdentifier || "dev-a-active-1001";
    const deviceState = body.deviceState || "ACTIVE";
    const clientId = body.clientId || "banking-app";

    const result = await fetchWithFallback(
      [
        "http://demo-node-app:3001/banking/accounts",
        "http://localhost:3001/banking/accounts",
      ],
      {
        method: "GET",
        headers: {
          "X-SecureLayer-Device-Id": deviceIdentifier,
          "X-SecureLayer-Device-State": deviceState,
          "X-SecureLayer-Client-Id": clientId,
          "X-SecureLayer-Tenant-Id": "00000000-0000-0000-0000-000000000001",
        },
      }
    );

    return NextResponse.json({
      action: "test_device_access",
      objective: "Authentication & Zero-Trust Policy",
      requestHeaders: {
        "X-SecureLayer-Device-Id": deviceIdentifier,
        "X-SecureLayer-Device-State": deviceState,
        "X-SecureLayer-Client-Id": clientId,
      },
      httpStatus: result.status,
      allowed: result.status === 200,
      latencyMs: result.latencyMs,
      response: result.data,
      timestamp: new Date().toISOString(),
    });
  }

  // 2. Live SHA-256 Request Integrity Verification -> POST /banking/transfers
  if (action === "test_integrity") {
    const tamper = Boolean(body.tamper);
    const deviceIdentifier = body.deviceIdentifier || "dev-a-active-1001";
    const deviceState = body.deviceState || "ACTIVE";

    const originalPayload = JSON.stringify({
      fromAccount: "ACC-ALICE-100",
      toAccount: "ACC-CHARLIE-200",
      amount: body.amount || "1250.00",
      currency: "USD",
    });

    const originalSha256 = createHash("sha256")
      .update(originalPayload, "utf8")
      .digest("base64");

    const transmittedPayload = tamper
      ? JSON.stringify({
          fromAccount: "ACC-ALICE-100",
          toAccount: "ACC-ATTACKER-999",
          amount: "95000.00",
          currency: "USD",
        })
      : originalPayload;

    const transmittedSha256 = createHash("sha256")
      .update(transmittedPayload, "utf8")
      .digest("base64");

    const result = await fetchWithFallback(
      [
        "http://demo-node-app:3001/banking/transfers",
        "http://localhost:3001/banking/transfers",
      ],
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SecureLayer-Device-Id": deviceIdentifier,
          "X-SecureLayer-Device-State": deviceState,
          "X-Message-Sha256": originalSha256,
        },
        body: transmittedPayload,
      }
    );

    return NextResponse.json({
      action: "test_integrity",
      objective: "Message Integrity (SHA-256)",
      tampered: tamper,
      originalBody: JSON.parse(originalPayload),
      transmittedBody: JSON.parse(transmittedPayload),
      headerSha256: originalSha256,
      computedBodySha256: transmittedSha256,
      httpStatus: result.status,
      passed: tamper ? result.status === 400 : result.status === 200,
      latencyMs: result.latencyMs,
      response: result.data,
      timestamp: new Date().toISOString(),
    });
  }

  // 3. Live Ed25519 Digital Signature & Non-Repudiation -> POST /devices/register-key + POST /banking/transfers
  if (action === "test_non_repudiation") {
    const tamper = Boolean(body.tamper);
    const deviceIdentifier = body.deviceIdentifier || "dev-a-active-1001";

    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey
      .export({ type: "spki", format: "pem" })
      .toString();

    await fetchWithFallback(
      [
        "http://demo-node-app:3001/devices/register-key",
        "http://localhost:3001/devices/register-key",
      ],
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deviceIdentifier,
          publicKeyPem,
        }),
      }
    );

    const signedPayload = JSON.stringify({
      fromAccount: "ACC-ALICE-100",
      toAccount: "ACC-CHARLIE-200",
      amount: body.amount || "5000.00",
      currency: "USD",
      nonce: randomBytes(4).toString("hex"),
    });

    const signatureBase64 = sign(
      null,
      Buffer.from(signedPayload, "utf8"),
      privateKey
    ).toString("base64");

    const transmittedPayload = tamper
      ? JSON.stringify({
          fromAccount: "ACC-ALICE-100",
          toAccount: "ACC-ROGUE-000",
          amount: "500000.00",
          currency: "USD",
        })
      : signedPayload;

    const transmittedHash = createHash("sha256")
      .update(transmittedPayload, "utf8")
      .digest("base64");

    const result = await fetchWithFallback(
      [
        "http://demo-node-app:3001/banking/transfers",
        "http://localhost:3001/banking/transfers",
      ],
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SecureLayer-Device-Id": deviceIdentifier,
          "X-SecureLayer-Device-State": "ACTIVE",
          "X-Message-Sha256": transmittedHash,
          "X-Transaction-Signature": signatureBase64,
        },
        body: transmittedPayload,
      }
    );

    return NextResponse.json({
      action: "test_non_repudiation",
      objective: "Non-Repudiation (Ed25519 Signature)",
      tampered: tamper,
      deviceIdentifier,
      algorithm: "Ed25519 (RFC 8032)",
      signatureBase64,
      sha256Digest: transmittedHash,
      httpStatus: result.status,
      passed: tamper ? result.status === 400 : result.status === 200,
      latencyMs: result.latencyMs,
      response: result.data,
      timestamp: new Date().toISOString(),
    });
  }

  // 4. Live AES-256-GCM Authenticated Encryption -> POST /banking/confidential-records
  if (action === "test_confidentiality") {
    const tamperTag = Boolean(body.tamper);
    const deviceIdentifier = body.deviceIdentifier || "dev-a-active-1001";

    const plaintextRecord = JSON.stringify({
      accountNumber: "ACC-ALICE-100",
      wireRouting: "021000021",
      swiftCode: "SLBKUS33XXX",
      amount: body.amount || "25000.00",
      classification: "TOP_SECRET_FINANCIAL",
    });

    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", MASTER_KEY, nonce);
    const encrypted = Buffer.concat([
      cipher.update(plaintextRecord, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const transmittedAuthTag = tamperTag
      ? Buffer.from(authTag.map((b, idx) => (idx === 0 ? b ^ 0xff : b))).toString(
          "base64"
        )
      : authTag.toString("base64");

    const envelope = {
      nonce: nonce.toString("base64"),
      ciphertext: encrypted.toString("base64"),
      authTag: transmittedAuthTag,
    };

    const result = await fetchWithFallback(
      [
        "http://demo-node-app:3001/banking/confidential-records",
        "http://localhost:3001/banking/confidential-records",
      ],
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SecureLayer-Device-Id": deviceIdentifier,
          "X-SecureLayer-Device-State": "ACTIVE",
        },
        body: JSON.stringify(envelope),
      }
    );

    return NextResponse.json({
      action: "test_confidentiality",
      objective: "Confidentiality (AES-256-GCM)",
      tampered: tamperTag,
      algorithm: "AES-256-GCM (96-bit Nonce, 128-bit Auth Tag)",
      plaintextPreview: JSON.parse(plaintextRecord),
      envelope,
      httpStatus: result.status,
      passed: tamperTag ? result.status === 400 : result.status === 200,
      latencyMs: result.latencyMs,
      response: result.data,
      timestamp: new Date().toISOString(),
    });
  }

  // 5. Run Full Multi-Service Scenario Suite (Node Banking API + Python SDK Verifier)
  if (action === "run_full_suite") {
    const [nodeScenario, pythonScenario] = await Promise.all([
      fetchWithFallback(
        [
          "http://demo-node-app:3001/demo/scenario",
          "http://localhost:3001/demo/scenario",
        ],
        { method: "POST" }
      ),
      fetchWithFallback(
        [
          "http://demo-python-app:3002/demo/run",
          "http://localhost:3002/demo/run",
        ],
        { method: "POST" }
      ),
    ]);

    return NextResponse.json({
      action: "run_full_suite",
      objective: "End-to-End SecureLayer Verification Suite",
      httpStatus: nodeScenario.ok && pythonScenario.ok ? 200 : 207,
      passed: Boolean(
        nodeScenario.data?.allStepsPassed && pythonScenario.data?.passed
      ),
      latencyMs: nodeScenario.latencyMs + pythonScenario.latencyMs,
      nodeBankingScenario: nodeScenario.data,
      pythonSdkScenario: pythonScenario.data,
      timestamp: new Date().toISOString(),
    });
  }

  return NextResponse.json(
    { error: "UNKNOWN_ACTION", message: `Unsupported action: ${action}` },
    { status: 400 }
  );
}
