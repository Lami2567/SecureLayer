import { stableJson } from "./encoding.js";
import type {
  AuthorizeRequest,
  AuthorizeResponse,
  RecordAuditEventRequest,
  RecordAuditEventResponse,
  ValidateCertificateRequest,
  ValidateCertificateResponse,
} from "./protocol.js";

export interface SecureLayerTransport {
  authorize(request: AuthorizeRequest, metadata: Record<string, string>): Promise<AuthorizeResponse>;
  validateCertificate(request: ValidateCertificateRequest, metadata: Record<string, string>): Promise<ValidateCertificateResponse>;
  recordAuditEvent(request: RecordAuditEventRequest, metadata: Record<string, string>): Promise<RecordAuditEventResponse>;
  registerApplication?(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<{ id: string }>;
  registerDevice?(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<unknown>;
  authenticate?(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<unknown>;
}

export interface HttpTransportOptions {
  gatewayUrl: string | URL;
  timeoutMs?: number;
  bearerToken?: string;
  fetchImpl?: typeof fetch;
}

export class SecureLayerHttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "SecureLayerHttpError";
  }
}

export class SecureLayerHttpTransport implements SecureLayerTransport {
  private readonly gatewayUrl: URL;
  private readonly timeoutMs: number;
  private readonly bearerToken?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpTransportOptions) {
    this.gatewayUrl = new URL(options.gatewayUrl);
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.bearerToken = options.bearerToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async authorize(request: AuthorizeRequest, metadata: Record<string, string>): Promise<AuthorizeResponse> {
    return this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(request.tenant.tenantId)}/policy-evaluations`, {
      policyName: request.decisionPolicyName,
      username: request.principal.subject,
      requestedResource: request.resource,
      httpMethod: request.context?.httpMethod ?? request.action,
      requestContext: request.context?.attributes ?? {},
      principalScopes: request.principal.scopes ?? [],
      userRoles: request.principal.roles ?? [],
      ipAddress: request.context?.ipAddress,
      evaluatedAt: request.envelope.timestamp,
      deviceIdentifier: request.authentication?.device?.deviceIdentifier,
      clientId: request.authentication?.application?.clientId,
      certificateFingerprintSha256: request.authentication?.certificate?.fingerprintSha256,
    }, metadata) as Promise<AuthorizeResponse>;
  }

  async validateCertificate(request: ValidateCertificateRequest, metadata: Record<string, string>): Promise<ValidateCertificateResponse> {
    const response = await this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(request.tenant.tenantId)}/device-certificate-validations`, {
      deviceIdentifier: request.deviceIdentifier,
      pemCertificate: request.certificate.pemCertificate,
    }, metadata) as {
      authenticated?: boolean;
      state?: string;
      reason?: string;
    };

    return {
      status: response.state,
      decision: {
        decision: response.authenticated ? "ALLOW" : "DENY",
        allowed: response.authenticated === true,
        reason: response.reason,
      },
    };
  }

  async recordAuditEvent(request: RecordAuditEventRequest, metadata: Record<string, string>): Promise<RecordAuditEventResponse> {
    const response = await this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(request.tenant.tenantId)}/audit-events`, {
      subject: request.principal.subject,
      action: request.action,
      resource: request.resource,
      eventHashBase64: request.eventHashSha256,
      signatureBase64: request.ed25519Signature,
    }, metadata) as { id?: string; auditEventId?: string };

    return {
      auditEventId: response.auditEventId ?? response.id ?? "",
    };
  }

  async registerApplication(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<{ id: string }> {
    return this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(tenantId)}/applications`, request, metadata) as Promise<{ id: string }>;
  }

  async registerDevice(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<unknown> {
    return this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(tenantId)}/device-registrations`, request, metadata);
  }

  async authenticate(tenantId: string, request: unknown, metadata: Record<string, string>): Promise<unknown> {
    return this.postJson(`/api/v1/admin/tenants/${encodeURIComponent(tenantId)}/authenticate`, request, metadata);
  }

  private async postJson(path: string, body: unknown, metadata: Record<string, string>): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(new URL(path, this.gatewayUrl), {
        method: "POST",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          ...metadata,
          ...(this.bearerToken ? { authorization: `Bearer ${this.bearerToken}` } : {}),
        },
        body: stableJson(body),
      });

      const text = await response.text();
      const parsed = text ? JSON.parse(text) as unknown : {};
      if (!response.ok) {
        throw new SecureLayerHttpError(`SecureLayer request failed with HTTP ${response.status}`, response.status, parsed);
      }

      return parsed;
    } finally {
      clearTimeout(timeout);
    }
  }
}
