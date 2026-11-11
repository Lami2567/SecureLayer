export type PageId =
  | "login"
  | "overview"
  | "applications"
  | "devices"
  | "users"
  | "policies"
  | "certificates"
  | "keys"
  | "security-events"
  | "audit-logs"
  | "api-credentials"
  | "settings";

export interface Session {
  apiBaseUrl: string;
  tenantId: string;
  token: string;
  username?: string;
}

export interface ApiState<T> {
  loading: boolean;
  data?: T;
  error?: string;
}

export interface DashboardMetrics {
  activeDevices: number;
  blockedDevices: number;
  registeredApplications: number;
  policyDecisions: number;
  authenticationEvents: number;
  failedRequests: number;
  securityAlerts: number;
  totalAuditEvents: number;
}

export interface ApplicationRecord {
  id: string;
  name: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scopes: string[];
  createdAt: string;
}

export type DeviceState = "ACTIVE" | "PENDING" | "SUSPENDED" | "REVOKED";

export interface DeviceRecord {
  id: string;
  name: string;
  deviceIdentifier: string;
  state: DeviceState;
  certificateId?: string;
  pemCertificate?: string;
  certificateFingerprintSha256?: string;
  expiresAt?: string;
  registeredAt: string;
}

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  roles: string[];
  createdAt: string;
}

export interface PolicyRecord {
  id?: string;
  name: string;
  version: number;
  active: boolean;
  document: Record<string, unknown>;
  createdAt: string;
}

export interface CertificateRecord {
  id: string;
  subject: string;
  serialNumber: string;
  pemCertificate: string;
  fingerprintSha256: string;
  notBefore: string;
  notAfter: string;
  status: "VALID" | "REVOKED" | "EXPIRED";
  importedAt: string;
}

export interface KeyRecord {
  id: string;
  alias: string;
  algorithm: string;
  usage: string;
  keyMaterialBase64: string;
  storedAt: string;
}

export type AlertSeverity = "CRITICAL" | "HIGH" | "WARN" | "INFO";

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: AlertSeverity;
  title: string;
  details: string;
  source: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  subject: string;
  resource: string;
  outcome: string;
  at: string;
  eventHashBase64?: string;
  signatureBase64?: string;
}
