export const SECURELAYER_PROTOCOL_VERSION = "securelayer.v1";

export type ProtocolDirection = "CLIENT_TO_SERVER" | "SERVER_TO_CLIENT" | "SERVER_TO_SERVER";
export type SecurityDecisionType = "ALLOW" | "DENY" | "REQUIRE_MFA" | "REQUIRE_DEVICE_CERTIFICATE";
export type DeviceState = "PENDING" | "ACTIVE" | "SUSPENDED" | "REVOKED";

export interface TenantRef {
  tenantId: string;
}

export interface Principal {
  subject: string;
  scopes?: string[];
  roles?: string[];
  identityId?: string;
}

export interface ProtocolEnvelope {
  requestId: string;
  timestamp: string;
  direction: ProtocolDirection;
  tenant: TenantRef;
  protocolVersion: string;
}

export interface Authentication {
  principal?: Principal;
  device?: {
    deviceId?: string;
    deviceIdentifier?: string;
    state?: DeviceState;
    registered?: boolean;
  };
  application?: {
    applicationId?: string;
    clientId?: string;
    name?: string;
    approved?: boolean;
  };
  certificate?: {
    certificateId?: string;
    subject?: string;
    serialNumber?: string;
    pemCertificate?: string;
    fingerprintSha256?: string;
    notBefore?: string;
    notAfter?: string;
    status?: string;
  };
  scopes?: string[];
}

export interface RequestContext {
  resource?: string;
  httpMethod?: string;
  ipAddress?: string;
  attributes?: Record<string, unknown>;
}

export interface Integrity {
  algorithm: "SHA-256" | "HMAC-SHA-256";
  messageHashSha256?: string;
  hmac?: string;
  keyId?: string;
  keyVersion?: number;
}

export interface ProtocolSignature {
  algorithm: "Ed25519";
  signature: string;
  keyId?: string;
  publicKeySha256?: string;
}

export interface SecurityDecision {
  decision: SecurityDecisionType;
  allowed: boolean;
  policyName?: string;
  policyVersion?: number;
  reason?: string;
}

export interface AuthorizeRequest {
  tenant: TenantRef;
  principal: Principal;
  action: string;
  resource: string;
  requestHashSha256?: string;
  envelope: ProtocolEnvelope;
  authentication?: Authentication;
  context?: RequestContext;
  integrity?: Integrity;
  decisionPolicyName?: string;
}

export interface AuthorizeResponse {
  allowed: boolean;
  policyName?: string;
  policyVersion?: number;
  envelope?: ProtocolEnvelope;
  decision?: SecurityDecision;
  integrity?: Integrity;
}

export interface RecordAuditEventRequest {
  tenant: TenantRef;
  principal: Principal;
  action: string;
  resource: string;
  eventHashSha256: string;
  ed25519Signature?: string;
  envelope: ProtocolEnvelope;
  auditEvent?: {
    auditEventId?: string;
    principal?: Principal;
    action?: string;
    resource?: string;
    eventHashSha256?: string;
    signature?: ProtocolSignature;
    outcome?: string;
    createdAt?: string;
  };
  integrity?: Integrity;
}

export interface RecordAuditEventResponse {
  auditEventId: string;
  envelope?: ProtocolEnvelope;
}

export interface ValidateCertificateRequest {
  envelope: ProtocolEnvelope;
  tenant: TenantRef;
  deviceIdentifier: string;
  certificate: {
    pemCertificate: string;
  };
}

export interface ValidateCertificateResponse {
  envelope?: ProtocolEnvelope;
  status?: string;
  decision?: SecurityDecision;
}

export function createEnvelope(tenantId: string, direction: ProtocolDirection = "CLIENT_TO_SERVER"): ProtocolEnvelope {
  return {
    requestId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    direction,
    tenant: { tenantId },
    protocolVersion: SECURELAYER_PROTOCOL_VERSION,
  };
}

export function protocolMetadata(envelope: ProtocolEnvelope, messageHashSha256?: string): Record<string, string> {
  return {
    "x-request-id": envelope.requestId,
    "x-request-timestamp": envelope.timestamp,
    ...(messageHashSha256 ? { "x-message-sha256": messageHashSha256 } : {}),
  };
}
