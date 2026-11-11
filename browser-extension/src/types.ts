export type AccessDecision = "ALLOW" | "DENY" | "UNKNOWN";

export type CertificateStatus =
  | "VALID"
  | "DENIED"
  | "SUSPENDED"
  | "REVOKED"
  | "NOT_REGISTERED"
  | "UNKNOWN";

export interface SecureLayerConfig {
  controlPlaneUrl?: string;
  tenantId?: string;
  token?: string;
  username?: string;
  deviceId?: string;
  deviceIdentifier?: string;
  pemCertificate?: string;
  certificateFingerprintSha256?: string;
  certificateStatus?: CertificateStatus;
  registeredAt?: string;
  loggedIn?: boolean;
  protectedApplications: ProtectedApplication[];
  lastDecision?: PolicyDecisionRecord;
  auditEvents: AuditRecord[];
}

export interface ProtectedApplication {
  originPattern: string;
  applicationId: string;
  policyName: string;
  displayName: string;
}

export interface DetectionResult {
  protected: boolean;
  application?: ProtectedApplication;
}

export interface PolicyDecisionRecord {
  decision: AccessDecision;
  allowed: boolean;
  reason: string;
  url: string;
  applicationId?: string;
  deviceIdentifier?: string;
  evaluatedAt: string;
}

export interface AuditRecord {
  id: string;
  action: string;
  resource: string;
  outcome: string;
  createdAt: string;
  eventHashBase64?: string;
}

export type RuntimeMessageType =
  | "STATUS"
  | "LOGIN"
  | "LOGOUT"
  | "REGISTER_DEVICE"
  | "VALIDATE_DEVICE"
  | "DETECT_PROTECTED_APPLICATION"
  | "CHECK_CURRENT_TAB"
  | "ADD_PROTECTED_APP"
  | "REMOVE_PROTECTED_APP"
  | "CLEAR_AUDIT";

export interface RuntimeMessage {
  type: RuntimeMessageType | string;
  url?: string;
  username?: string;
  token?: string;
  controlPlaneUrl?: string;
  tenantId?: string;
  application?: ProtectedApplication;
  pattern?: string;
}

export interface RuntimeResponse {
  ok: boolean;
  status?: SecureLayerConfig;
  detection?: DetectionResult;
  decision?: PolicyDecisionRecord;
  error?: string;
}
