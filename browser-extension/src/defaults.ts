import type { ProtectedApplication, SecureLayerConfig } from "./types.js";

export const DEFAULT_PROTECTED_APPLICATIONS: ProtectedApplication[] = [
  {
    originPattern: "https://bank.example.com/*",
    applicationId: "banking-web",
    policyName: "banking",
    displayName: "Retail Banking Portal",
  },
  {
    originPattern: "http://localhost:3000/banking/*",
    applicationId: "banking-web",
    policyName: "banking",
    displayName: "Local Banking Test Portal",
  },
  {
    originPattern: "http://localhost:8080/banking/*",
    applicationId: "banking-app",
    policyName: "banking-policy",
    displayName: "SecureLayer Core Banking",
  },
];

export const DEFAULT_CONFIG: SecureLayerConfig = {
  controlPlaneUrl: "http://localhost:8080",
  tenantId: "tenant-primary",
  certificateStatus: "NOT_REGISTERED",
  loggedIn: false,
  protectedApplications: DEFAULT_PROTECTED_APPLICATIONS,
  auditEvents: [],
};
