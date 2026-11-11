# SecureLayer Developer Dashboard

A professional, cybersecurity-style developer dashboard and incident console built with **Next.js (App Router)**, **TypeScript**, and **Tailwind CSS**.

---

## Overview & Architecture

The dashboard serves as the administrative control plane console for the SecureLayer platform. It communicates directly with the centralized Spring Boot security core via REST APIs (`/api/v1/admin/...` and `/api/v1/health/...`).

### Core Design Principles
1. **Zero Synthetic / Mock Data**: All metrics, inventory records, and audit logs reflect real interactions with the SecureLayer control plane.
2. **Explicit States**: Every view features interactive **loading skeletons**, descriptive **empty states**, and structured **error diagnostics**.
3. **Cybersecurity Console Theme**: High-contrast dark-mode cyber palette (`#030712`, deep slate/cyan/emerald/rose accents) with monospace metadata formatting.
4. **Responsive Layout**: Fluid layouts adapting to desktop workstations, tablet diagnostics, and mobile viewing.

---

## 12 Dedicated Console Pages

| Page | URL Path / Tab | Description |
| :--- | :--- | :--- |
| **Login** | `login` | Connects the dashboard to the SecureLayer backend API URL, tenant UUID, and bearer token with liveness verification. |
| **Overview** | `overview` | Cyber metrics grid (8 core indicators), live readiness probe status, active policy document viewer, and security alerts stream. |
| **Applications** | `applications` | Protected application registration workflow (OAuth 2.1 / OIDC credentials, redirect URIs, principal scopes). |
| **Devices** | `devices` | Device registration workflow, proof-of-possession verification, certificate validation, and state toggles (Suspend, Enable, Revoke). |
| **Users** | `users` | Identity management workflow with Role-Based Access Control (`SUPER_ADMIN`, `ADMIN`, `DEVELOPER`, `SECURITY_OPERATOR`, `DEVICE`). |
| **Policies** | `policies` | Versioned JSON policy creation workflow, activation/deactivation controls, and interactive real-time Policy Evaluation Simulator. |
| **Certificates** | `certificates` | X.509 device certificate import workflow, expiration tracking, SHA-256 fingerprint viewer, and revocation actions. |
| **Keys** | `keys` | Cryptographic key vault management for Ed25519, AES-256-GCM, and HMAC-SHA256 key material. |
| **Security Events** | `security-events` | Real-time security incident console filtering alerts by severity (`CRITICAL`, `HIGH`, `WARN`, `INFO`). |
| **Audit Logs** | `audit-logs` | Chronological, tamper-evident audit trail table with event action, subject, resource, outcome, and JSON export. |
| **API Credentials** | `api-credentials` | Integration endpoints, active tenant UUID, gRPC / REST addresses, and copyable SDK initialization code snippets. |
| **Settings** | `settings` | Control plane URL settings, audit buffer configurations, and fail-closed enforcement mode diagnostics. |

---

## 8 Monitored Cybersecurity Metrics

1. **Active Devices**: Devices in `ACTIVE` state with valid certificates.
2. **Blocked Devices**: Devices placed in `SUSPENDED` or `REVOKED` state.
3. **Registered Applications**: Protected client applications configured on the control plane.
4. **Policy Decisions**: Total policy evaluations processed by the engine (`ALLOW` vs `DENY`).
5. **Authentication Events**: Device validations, certificate checks, and operator logins.
6. **Failed Requests**: Rejected calls, tampered payloads (`X-Message-Sha256` mismatch), or unauthorized queries.
7. **Security Alerts**: Active security incidents flagged by the platform.
8. **Audit Records**: Total cryptographically signed event records stored in the audit trail.

---

## Workflows

### 1. Application Registration
- Inputs: Name, Client ID, Client Secret, Redirect URIs, Principal Scopes.
- Action: Dispatches `POST /api/v1/admin/tenants/{tenantId}/applications`.
- Result: Client registered with OAuth 2.1 credentials and added to inventory.

### 2. Device Management
- **Registration**: Submits friendly name, device identifier, and CSR PEM to `POST /api/v1/admin/tenants/{tenantId}/device-registrations`.
- **Validation**: Verifies X.509 certificate validity against `POST /api/v1/admin/tenants/{tenantId}/device-certificate-validations`.
- **Lifecycle Control**: Immediately updates device state via `/suspend`, `/enable`, or `/revoke`.

### 3. Policy Creation & Activation
- **Creation**: Submits versioned rule documents to `POST /api/v1/admin/tenants/{tenantId}/policies`.
- **Activation**: Toggles version activation via `POST /policies/{name}/versions/{version}/activate`.
- **Simulator**: Tests simulated requests against `POST /policy-evaluations` to observe immediate `ALLOW` or `DENY` decisions.

### 4. Certificate Management
- **Import**: Submits X.509 PEM certificate, subject, and validity window to `POST /certificates`.
- **Revocation**: Marks certificates invalid on the CA via `POST /certificates/{id}/revoke`.

---

## Running the Dashboard

```bash
# Install dependencies
npm install

# Run development server
npm --workspace @securelayer/dashboard run dev

# Build for production
npm --workspace @securelayer/dashboard run build

# Start production server
npm --workspace @securelayer/dashboard run start
```
