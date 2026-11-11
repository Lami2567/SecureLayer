import type { CertificateStatus, PolicyDecisionRecord, ProtectedApplication, SecureLayerConfig } from "./types.js";

export async function registerDevice(
  config: SecureLayerConfig,
  deviceIdentifier: string,
  publicKeyJwk: JsonWebKey,
): Promise<{
  deviceId?: string;
  certificateStatus: CertificateStatus;
  pemCertificate?: string;
  certificateFingerprintSha256?: string;
}> {
  if (!config.controlPlaneUrl || !config.tenantId) {
    throw new Error("Control plane URL and tenant ID are required for device registration");
  }

  const response = await secureFetch(config, `/api/v1/admin/tenants/${encodeURIComponent(config.tenantId)}/device-registrations`, {
    name: `Chrome Extension ${deviceIdentifier.slice(0, 8)}`,
    deviceIdentifier,
    certificateSigningRequestPem: JSON.stringify({
      type: "browser-public-key",
      algorithm: "ECDSA-P256-SHA256",
      publicKeyJwk,
    }),
  });

  const state = response.state;
  let certificateStatus: CertificateStatus = "UNKNOWN";
  if (state === "ACTIVE") certificateStatus = "VALID";
  else if (state === "REVOKED") certificateStatus = "REVOKED";
  else if (state === "SUSPENDED") certificateStatus = "SUSPENDED";
  else if (state === "PENDING") certificateStatus = "UNKNOWN";

  return {
    deviceId: response.deviceId ?? response.id,
    certificateStatus,
    pemCertificate: response.pemCertificate,
    certificateFingerprintSha256: response.certificateFingerprintSha256,
  };
}

export async function validateDevice(config: SecureLayerConfig): Promise<{
  certificateStatus: CertificateStatus;
  reason?: string;
}> {
  if (!config.controlPlaneUrl || !config.tenantId || !config.deviceIdentifier) {
    return { certificateStatus: "NOT_REGISTERED", reason: "Device has not been registered" };
  }

  try {
    const response = await secureFetch(config, `/api/v1/admin/tenants/${encodeURIComponent(config.tenantId)}/device-certificate-validations`, {
      deviceIdentifier: config.deviceIdentifier,
      pemCertificate: config.pemCertificate ?? "browser-extension-public-key",
    });

    if (response.authenticated && response.state === "ACTIVE") {
      return { certificateStatus: "VALID", reason: "Device certificate and identity active" };
    }
    if (response.state === "SUSPENDED") {
      return { certificateStatus: "SUSPENDED", reason: response.reason ?? "Device is suspended" };
    }
    if (response.state === "REVOKED") {
      return { certificateStatus: "REVOKED", reason: response.reason ?? "Device is revoked" };
    }
    return { certificateStatus: "DENIED", reason: response.reason ?? "Device certificate denied" };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { certificateStatus: config.deviceId ? "UNKNOWN" : "NOT_REGISTERED", reason: message };
  }
}

export async function requestPolicy(config: SecureLayerConfig, application: ProtectedApplication, url: string): Promise<PolicyDecisionRecord> {
  if (!config.controlPlaneUrl || !config.tenantId) {
    return deny(url, application, config.deviceIdentifier, "SecureLayer control plane is not configured");
  }
  if (!config.loggedIn || !config.token) {
    return deny(url, application, config.deviceIdentifier, "User is not authenticated (login required)");
  }
  if (!config.deviceIdentifier || config.certificateStatus !== "VALID") {
    const statusText = config.certificateStatus ?? "NOT_REGISTERED";
    return deny(url, application, config.deviceIdentifier, `Device is untrusted or unregistered (status: ${statusText})`);
  }

  try {
    const response = await secureFetch(config, `/api/v1/admin/tenants/${encodeURIComponent(config.tenantId)}/policy-evaluations`, {
      policyName: application.policyName,
      username: config.username ?? "browser-user",
      deviceId: config.deviceId,
      deviceIdentifier: config.deviceIdentifier,
      clientId: application.applicationId,
      requestedResource: url,
      httpMethod: "GET",
      requestContext: {
        source: "chrome-extension",
        accessControlLayer: "application",
        protocol: "https",
      },
      principalScopes: ["browser:access"],
      userRoles: ["DEVICE"],
      certificateFingerprintSha256: config.certificateFingerprintSha256,
      evaluatedAt: new Date().toISOString(),
    });

    const isAllowed = response.allowed === true;
    return {
      decision: isAllowed ? "ALLOW" : "DENY",
      allowed: isAllowed,
      reason: response.reason ?? (isAllowed ? "SecureLayer policy allowed application access" : "SecureLayer policy denied application access"),
      url,
      applicationId: application.applicationId,
      deviceIdentifier: config.deviceIdentifier,
      evaluatedAt: new Date().toISOString(),
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return deny(url, application, config.deviceIdentifier, `SecureLayer policy evaluation failed: ${message}`);
  }
}

export async function recordAudit(
  config: SecureLayerConfig,
  decision: PolicyDecisionRecord,
  eventHashBase64: string,
  signatureBase64?: string,
): Promise<void> {
  if (!config.controlPlaneUrl || !config.tenantId || !config.loggedIn) {
    return;
  }

  await secureFetch(config, `/api/v1/admin/tenants/${encodeURIComponent(config.tenantId)}/audit-events`, {
    subject: config.deviceIdentifier ?? "browser-extension",
    action: "browser-access",
    resource: decision.url,
    eventHashBase64,
    signatureBase64,
  });
}

async function secureFetch(config: SecureLayerConfig, path: string, body: unknown): Promise<Record<string, any>> {
  const response = await fetch(new URL(path, config.controlPlaneUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      ...(config.token ? { authorization: `Bearer ${config.token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`SecureLayer request failed with HTTP ${response.status}`);
  }
  return response.json();
}

export function deny(url: string, application: ProtectedApplication, deviceIdentifier: string | undefined, reason: string): PolicyDecisionRecord {
  return {
    decision: "DENY",
    allowed: false,
    reason,
    url,
    applicationId: application.applicationId,
    deviceIdentifier,
    evaluatedAt: new Date().toISOString(),
  };
}
