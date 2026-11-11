import {
  decryptAes256Gcm,
  encryptAes256Gcm,
  hmacSha256,
  sha256,
  signEd25519,
  verifyEd25519,
  verifyHmacSha256,
  type EncryptedPayload,
  type SignOptions,
  type SignatureResult,
  type SymmetricKey,
  type SymmetricKeyInput,
  type VerifyOptions,
} from "./crypto.js";
import { Buffer } from "node:buffer";
import { stableJson, type DataLike } from "./encoding.js";
import { createEnvelope, protocolMetadata, type Authentication, type AuthorizeResponse, type Principal, type RequestContext } from "./protocol.js";
import { SecureLayerHttpTransport, type SecureLayerTransport } from "./transport.js";

export interface SecureLayerConfig {
  tenantId: string;
  gatewayUrl?: string | URL;
  bearerToken?: string;
  timeoutMs?: number;
  timestampToleranceMs?: number;
  application?: {
    applicationId?: string;
    clientId?: string;
    name?: string;
  };
  device?: {
    deviceId?: string;
    deviceIdentifier?: string;
    certificatePem?: string;
  };
  keys?: {
    encryptionKey?: SymmetricKeyInput;
    hmacKey?: string | Uint8Array;
    privateKeyPem?: string;
    publicKeyPem?: string;
    signingKeyId?: string;
  };
  transport?: SecureLayerTransport;
}

export interface RegisterApplicationInput {
  name: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scopes: string[];
}

export interface RegisterDeviceInput {
  name: string;
  deviceIdentifier: string;
  certificateSigningRequestPem: string;
}

export interface AuthenticateInput {
  deviceIdentifier?: string;
  pemCertificate?: string;
  clientId?: string;
  clientSecret?: string;
  username?: string;
  password?: string;
  token?: string;
}

export interface AuthenticationResult {
  authenticated: boolean;
  status?: string;
  subject?: string;
  roles?: string[];
  scopes?: string[];
  token?: string;
  reason?: string;
}

export interface PolicyCheckInput {
  principal: Principal;
  action: string;
  resource: string;
  authentication?: Authentication;
  context?: RequestContext;
  policyName?: string;
}

export interface AuditEventInput {
  principal: Principal;
  action: string;
  resource: string;
  outcome?: string;
  data?: DataLike;
}

export interface ProtectableRequest {
  method?: string;
  url?: string;
  path?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: DataLike;
}

export interface ProtectedRequest<TRequest extends ProtectableRequest = ProtectableRequest> {
  request: TRequest & { headers: Record<string, string> };
  envelope: ReturnType<typeof createEnvelope>;
  bodyHash: string;
  signature?: SignatureResult;
}

export interface VerifyRequestOptions {
  publicKeyPem?: string;
  hmacKey?: string | Uint8Array;
  timestampToleranceMs?: number;
}

export interface VerifyRequestResult {
  verified: boolean;
  reason?: string;
  envelope?: {
    requestId?: string;
    timestamp?: string;
    tenantId?: string;
  };
}

export class SecureLayerClient {
  readonly config: SecureLayerConfig;
  readonly transport: SecureLayerTransport;

  constructor(config: SecureLayerConfig) {
    this.config = config;
    if (config.transport) {
      this.transport = config.transport;
    } else if (config.gatewayUrl) {
      this.transport = new SecureLayerHttpTransport({
        gatewayUrl: config.gatewayUrl,
        bearerToken: config.bearerToken,
        timeoutMs: config.timeoutMs,
      });
    } else {
      throw new Error("SecureLayer requires either gatewayUrl or a custom transport");
    }
  }

  async registerApplication(input: RegisterApplicationInput): Promise<unknown> {
    const transport = this.transport as SecureLayerHttpTransport;
    if (typeof transport.registerApplication !== "function") {
      throw new Error("registerApplication requires a transport supporting application registration");
    }
    const envelope = createEnvelope(this.config.tenantId);
    return transport.registerApplication(this.config.tenantId, input, protocolMetadata(envelope, sha256(input)));
  }

  async authenticate(input: AuthenticateInput = {}): Promise<AuthenticationResult> {
    const deviceIdentifier = input.deviceIdentifier ?? this.config.device?.deviceIdentifier;
    const pemCertificate = input.pemCertificate ?? this.config.device?.certificatePem;

    if (deviceIdentifier && pemCertificate) {
      const envelope = createEnvelope(this.config.tenantId);
      const request = {
        envelope,
        tenant: { tenantId: this.config.tenantId },
        deviceIdentifier,
        certificate: { pemCertificate },
      };
      const response = await this.transport.validateCertificate(request, protocolMetadata(envelope, sha256(request)));
      const isAllowed = response.decision?.allowed === true || response.status === "VALID" || response.status === "ACTIVE";
      return {
        authenticated: isAllowed,
        status: response.status ?? (isAllowed ? "ACTIVE" : "DENIED"),
        subject: deviceIdentifier,
        reason: response.decision?.reason,
      };
    }

    const envelope = createEnvelope(this.config.tenantId);
    if (typeof this.transport.authenticate === "function") {
      const response = (await this.transport.authenticate(
        this.config.tenantId,
        input,
        protocolMetadata(envelope, sha256(input)),
      )) as Record<string, unknown> | undefined;
      return {
        authenticated: response?.authenticated !== false,
        status: (response?.status as string) ?? "ACTIVE",
        subject: (response?.subject as string) ?? input.username ?? input.clientId,
        roles: response?.roles as string[] | undefined,
        scopes: response?.scopes as string[] | undefined,
        token: response?.token as string | undefined,
        reason: response?.reason as string | undefined,
      };
    }

    if (input.clientId || input.username || this.config.bearerToken) {
      return {
        authenticated: true,
        status: "ACTIVE",
        subject: input.username ?? input.clientId ?? this.config.application?.clientId ?? "authenticated-principal",
      };
    }

    throw new Error("No authentication credentials provided or configured on client");
  }

  async registerDevice(input: RegisterDeviceInput): Promise<unknown> {
    const transport = this.transport as SecureLayerHttpTransport;
    if (typeof transport.registerDevice !== "function") {
      throw new Error("registerDevice requires a transport supporting device registration");
    }
    const envelope = createEnvelope(this.config.tenantId);
    return transport.registerDevice(this.config.tenantId, input, protocolMetadata(envelope, sha256(input)));
  }

  encrypt(input: DataLike, key: SymmetricKeyInput = required(this.config.keys?.encryptionKey, "encryptionKey")): EncryptedPayload {
    return encryptAes256Gcm(input, key, { tenantId: this.config.tenantId, protocolVersion: "securelayer.v1" });
  }

  decrypt(payload: EncryptedPayload, key: SymmetricKeyInput = required(this.config.keys?.encryptionKey, "encryptionKey")): Buffer {
    return decryptAes256Gcm(payload, key);
  }

  hash(input: DataLike): string {
    return sha256(input);
  }

  sign(input: DataLike, options?: SignOptions | string): SignatureResult {
    const opts = typeof options === "string" ? { privateKeyPem: options } : options;
    return signEd25519(input, {
      privateKeyPem: opts?.privateKeyPem ?? this.config.keys?.privateKeyPem,
      keyId: opts?.keyId ?? this.config.keys?.signingKeyId,
    });
  }

  verify(input: DataLike, signature: string | SignatureResult, options?: VerifyOptions | string): boolean {
    const opts = typeof options === "string" ? { publicKeyPem: options } : options;
    return verifyEd25519(input, typeof signature === "string" ? signature : signature.signature, {
      publicKeyPem: opts?.publicKeyPem ?? this.config.keys?.publicKeyPem,
    });
  }

  async protectRequest<TRequest extends ProtectableRequest>(request: TRequest): Promise<ProtectedRequest<TRequest>> {
    const envelope = createEnvelope(this.config.tenantId);
    const bodyHash = sha256(request.body ?? "");
    const protectedHeaders = normalizeHeaders({
      ...request.headers,
      ...protocolMetadata(envelope, bodyHash),
      "x-securelayer-protocol": envelope.protocolVersion,
      "x-securelayer-tenant-id": this.config.tenantId,
    });
    const requestForSigning = { ...request, headers: protectedHeaders };
    const canonicalRequest = canonicalizeRequest(requestForSigning, bodyHash);
    const signature = this.config.keys?.privateKeyPem ? this.sign(canonicalRequest) : undefined;
    const hmac = this.config.keys?.hmacKey ? hmacSha256(canonicalRequest, this.config.keys.hmacKey) : undefined;

    return {
      request: {
        ...request,
        headers: normalizeHeaders({
          ...protectedHeaders,
          ...(signature ? { "x-securelayer-signature": signature.signature } : {}),
          ...(signature?.keyId ? { "x-securelayer-key-id": signature.keyId } : {}),
          ...(hmac ? { "x-securelayer-hmac-sha256": hmac } : {}),
        }),
      },
      envelope,
      bodyHash,
      signature,
    };
  }

  async verifyRequest(request: ProtectableRequest, options?: VerifyRequestOptions): Promise<VerifyRequestResult> {
    const headers = normalizeHeaders(request.headers ?? {});
    const requestId = headers["x-request-id"];
    const timestamp = headers["x-request-timestamp"];
    const tenantId = headers["x-securelayer-tenant-id"];

    if (!requestId || !timestamp) {
      return { verified: false, reason: "Missing SecureLayer request metadata" };
    }

    const tolerance = options?.timestampToleranceMs ?? this.config.timestampToleranceMs;
    if (tolerance && tolerance > 0) {
      const parsedTime = Date.parse(timestamp);
      if (!Number.isNaN(parsedTime) && Math.abs(Date.now() - parsedTime) > tolerance) {
        return {
          verified: false,
          reason: "Request timestamp outside acceptable tolerance window",
          envelope: { requestId, timestamp, tenantId },
        };
      }
    }

    const expectedBodyHash = headers["x-message-sha256"];
    const actualBodyHash = sha256(request.body ?? "");
    if (expectedBodyHash && expectedBodyHash !== actualBodyHash) {
      return { verified: false, reason: "Request body hash mismatch", envelope: { requestId, timestamp, tenantId } };
    }

    const canonicalRequest = canonicalizeRequest(request, actualBodyHash);
    const signature = headers["x-securelayer-signature"];
    const publicKeyPem = options?.publicKeyPem ?? this.config.keys?.publicKeyPem;
    if (signature && publicKeyPem && !this.verify(canonicalRequest, signature, publicKeyPem)) {
      return { verified: false, reason: "Request signature verification failed", envelope: { requestId, timestamp, tenantId } };
    }

    const hmac = headers["x-securelayer-hmac-sha256"];
    const hmacKey = options?.hmacKey ?? this.config.keys?.hmacKey;
    if (hmac && hmacKey && !verifyHmacSha256(canonicalRequest, hmac, hmacKey)) {
      return { verified: false, reason: "Request HMAC verification failed", envelope: { requestId, timestamp, tenantId } };
    }

    return { verified: true, envelope: { requestId, timestamp, tenantId } };
  }

  async policyCheck(input: PolicyCheckInput): Promise<AuthorizeResponse> {
    const envelope = createEnvelope(this.config.tenantId);
    const request = {
      tenant: { tenantId: this.config.tenantId },
      principal: input.principal,
      action: input.action,
      resource: input.resource,
      requestHashSha256: sha256(input),
      envelope,
      authentication: input.authentication ?? this.defaultAuthentication(input.principal),
      context: input.context,
      decisionPolicyName: input.policyName,
    };
    return this.transport.authorize(request, protocolMetadata(envelope, request.requestHashSha256));
  }

  async auditEvent(input: AuditEventInput): Promise<unknown> {
    const envelope = createEnvelope(this.config.tenantId);
    const data = input.data ?? {
      principal: input.principal,
      action: input.action,
      resource: input.resource,
      outcome: input.outcome,
      createdAt: envelope.timestamp,
    };
    const eventHashSha256 = sha256(data);
    const signature = this.config.keys?.privateKeyPem ? this.sign(data).signature : undefined;
    const request = {
      tenant: { tenantId: this.config.tenantId },
      principal: input.principal,
      action: input.action,
      resource: input.resource,
      eventHashSha256,
      ed25519Signature: signature,
      envelope,
      auditEvent: {
        principal: input.principal,
        action: input.action,
        resource: input.resource,
        eventHashSha256,
        outcome: input.outcome,
        createdAt: envelope.timestamp,
      },
      integrity: {
        algorithm: "SHA-256" as const,
        messageHashSha256: eventHashSha256,
      },
    };
    return this.transport.recordAuditEvent(request, protocolMetadata(envelope, sha256(request)));
  }

  private defaultAuthentication(principal: Principal): Authentication {
    return {
      principal,
      application: this.config.application,
      device: this.config.device,
      certificate: this.config.device?.certificatePem ? { pemCertificate: this.config.device.certificatePem } : undefined,
      scopes: principal.scopes,
    };
  }
}

export class SecureLayer {
  private static defaultClient?: SecureLayerClient;

  static initialize(config: SecureLayerConfig): SecureLayerClient {
    this.defaultClient = new SecureLayerClient(config);
    return this.defaultClient;
  }

  static client(): SecureLayerClient {
    if (!this.defaultClient) {
      throw new Error("SecureLayer.initialize(config) must be called before using static APIs");
    }
    return this.defaultClient;
  }

  static registerApplication(input: RegisterApplicationInput): Promise<unknown> {
    return this.client().registerApplication(input);
  }

  static authenticate(input?: AuthenticateInput): Promise<AuthenticationResult> {
    return this.client().authenticate(input);
  }

  static registerDevice(input: RegisterDeviceInput): Promise<unknown> {
    return this.client().registerDevice(input);
  }

  static encrypt(input: DataLike, key?: SymmetricKeyInput): EncryptedPayload {
    return this.client().encrypt(input, key);
  }

  static decrypt(payload: EncryptedPayload, key?: SymmetricKeyInput): Buffer {
    return this.client().decrypt(payload, key);
  }

  static hash(input: DataLike): string {
    return this.client().hash(input);
  }

  static sign(input: DataLike, options?: SignOptions | string): SignatureResult {
    return this.client().sign(input, options);
  }

  static verify(input: DataLike, signature: string | SignatureResult, options?: VerifyOptions | string): boolean {
    return this.client().verify(input, signature, options);
  }

  static protectRequest<TRequest extends ProtectableRequest>(request: TRequest): Promise<ProtectedRequest<TRequest>> {
    return this.client().protectRequest(request);
  }

  static verifyRequest(request: ProtectableRequest, options?: VerifyRequestOptions): Promise<VerifyRequestResult> {
    return this.client().verifyRequest(request, options);
  }

  static policyCheck(input: PolicyCheckInput): Promise<AuthorizeResponse> {
    return this.client().policyCheck(input);
  }

  static auditEvent(input: AuditEventInput): Promise<unknown> {
    return this.client().auditEvent(input);
  }
}

function required<T>(value: T | undefined, name: string): T {
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function normalizeHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key.toLowerCase(), Array.isArray(value) ? value.join(",") : String(value)]),
  );
}

function canonicalizeRequest(request: ProtectableRequest, bodyHash: string): Record<string, unknown> {
  const headers = normalizeHeaders(request.headers ?? {});
  delete headers["x-securelayer-signature"];
  delete headers["x-securelayer-hmac-sha256"];
  delete headers["x-securelayer-key-id"];
  return {
    method: request.method?.toUpperCase() ?? "GET",
    target: request.url ?? request.path ?? "/",
    bodyHash,
    headers,
  };
}

export function canonicalRequestJson(request: ProtectableRequest): string {
  return stableJson(request);
}
