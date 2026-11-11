# SecureLayer API Reference Specification

## Base URLs
- **Security Core (Control Plane REST):** `http://localhost:8090`
- **Security Core (gRPC Server):** `localhost:9090`
- **Security Gateway (Data Plane Proxy):** `http://localhost:8080`
- **Protected Banking Core (Upstream Service):** `http://localhost:3001`
- **Python Demonstration Service:** `http://localhost:3002`

---

## 1. Authentication & Common Error Codes

All `/api/v1/admin/**` endpoints require an OAuth 2.1 Bearer Token with appropriate administrative roles (`SUPER_ADMIN`, `ADMIN`, `SECURITY_OPERATOR`, or `DEVELOPER`).

### Standard Structured Error Response Format
```json
{
  "code": "POLICY_DENIED",
  "message": "Access denied: caller does not present a registered ACTIVE device.",
  "correlationId": "8f2a1b9c-4d3e-4b2a-8f1a-9c4d3e4b2a8f",
  "timestamp": "2026-10-11T21:30:00Z",
  "details": {
    "path": "/banking/accounts",
    "defaultBehavior": "DENY"
  }
}
```

| HTTP Status | Error Code | Description |
| :--- | :--- | :--- |
| `400 Bad Request` | `REQUEST_INTEGRITY_FAILED` | The `X-Message-Sha256` header does not match the computed digest of the payload. |
| `400 Bad Request` | `SIGNATURE_VERIFICATION_FAILED`| The `X-Transaction-Signature` does not match the Ed25519 signature of the payload. |
| `401 Unauthorized` | `UNAUTHORIZED` | Bearer token is missing, expired, or cryptographically invalid. |
| `403 Forbidden` | `DEVICE_CERTIFICATE_DENIED` | Device certificate is missing, expired, or revoked. |
| `403 Forbidden` | `POLICY_DENIED` | Denied by active policy (e.g. Device in `PENDING` or `SUSPENDED` state). |
| `404 Not Found` | `RESOURCE_NOT_FOUND` | Specified tenant, device, or policy does not exist. |

---

## 2. Control Plane Endpoints (`security-core:8090`)

### 2.1. Device Management

#### Register a Device
```http
POST /api/v1/admin/tenants/{tenantId}/device-registrations
Content-Type: application/json
Authorization: Bearer <TOKEN>
```
**Request Body:**
```json
{
  "name": "Alice Workstation (Device A)",
  "deviceIdentifier": "dev-a-active-1001",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...",
  "signedChallenge": "d34f2a...",
  "challenge": "challenge-nonce-12345"
}
```
**Response (201 Created):**
```json
{
  "deviceId": "30000000-0000-0000-0000-000000000001",
  "name": "Alice Workstation (Device A)",
  "deviceIdentifier": "dev-a-active-1001",
  "state": "ACTIVE",
  "certificatePem": "-----BEGIN CERTIFICATE-----\nMIIDXTCC...",
  "serialNumber": "SN-DEV-A-001",
  "fingerprintSha256": "864a0950ae25ce2215217f4a2e8de9994394d0a2b0342ea459bd772f0a821557"
}
```

#### Suspend a Device
```http
POST /api/v1/admin/tenants/{tenantId}/devices/{deviceId}/suspend
Authorization: Bearer <TOKEN>
```
**Response:** `204 No Content`

#### Enable a Device
```http
POST /api/v1/admin/tenants/{tenantId}/devices/{deviceId}/enable
Authorization: Bearer <TOKEN>
```
**Response:** `204 No Content`

#### Revoke a Device
```http
POST /api/v1/admin/tenants/{tenantId}/devices/{deviceId}/revoke
Authorization: Bearer <TOKEN>
```
**Response:** `204 No Content`

---

### 2.2. Policy Evaluation & Management

#### Evaluate Policy
```http
POST /api/v1/admin/tenants/{tenantId}/policy-evaluations
Content-Type: application/json
Authorization: Bearer <TOKEN>
```
**Request Body:**
```json
{
  "policyName": "banking-policy",
  "username": "alice.developer@bank.example.com",
  "deviceIdentifier": "dev-a-active-1001",
  "clientId": "banking-app",
  "requestedResource": "/banking/accounts",
  "httpMethod": "GET",
  "principalScopes": ["accounts:read"],
  "userRoles": ["DEVELOPER"],
  "evaluatedAt": "2026-10-11T21:30:00Z"
}
```
**Response (200 OK):**
```json
{
  "decision": "ALLOW",
  "policyName": "banking-policy",
  "policyVersion": 1,
  "reason": "Access allowed: caller is authenticated with registered ACTIVE device and valid certificate.",
  "matchedRules": ["Active Device Only"]
}
```

---

## 3. Data Plane Endpoints (`gateway:8080`)

All incoming requests are intercepted and evaluated before routing to upstream services.

#### Protected GET Request (Proxying to Banking Core)
```http
GET /banking/accounts
Host: localhost:8080
Authorization: Bearer <TOKEN>
X-Message-Sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
X-SecureLayer-Client-Id: banking-app
X-SecureLayer-Device-Id: dev-a-active-1001
X-SecureLayer-Client-Certificate: -----BEGIN CERTIFICATE-----\n...
```
**Response (200 OK):**
```json
{
  "status": "ALLOWED",
  "message": "Access granted to protected banking core",
  "deviceId": "dev-a-active-1001",
  "accounts": [
    {
      "id": "ACC-ALICE-100",
      "owner": "Alice Developer",
      "balance": "24,500.00 USD",
      "type": "RETAIL_CHECKING"
    }
  ]
}
```

---

## 4. Protected Upstream Banking API Endpoints (`demo-node-app:3001`)

#### Submit Financial Transfer (with Non-Repudiation)
```http
POST /banking/transfers
Host: localhost:3001
Content-Type: application/json
X-Message-Sha256: zG4oP9xL...
X-SecureLayer-Device-Id: dev-a-active-1001
X-Transaction-Signature: wzLiDdNr2jMXiU7B4wH8L+RpRD7vcAdb...

{
  "fromAccount": "ACC-ALICE-100",
  "toAccount": "ACC-CHARLIE-200",
  "amount": "5000.00"
}
```
**Response (200 OK):**
```json
{
  "status": "SETTLED",
  "transactionId": "TX-A7B8C9D0E1F2",
  "amount": "5000.00",
  "fromAccount": "ACC-ALICE-100",
  "toAccount": "ACC-CHARLIE-200",
  "integrityVerified": true,
  "signatureVerified": true,
  "nonRepudiationSecured": true,
  "timestamp": "2026-10-11T21:30:00Z"
}
```

#### Decrypt Confidential Record (AES-256-GCM)
```http
POST /banking/confidential-records
Host: localhost:3001
Content-Type: application/json

{
  "algorithm": "AES-256-GCM",
  "nonce": "iYowxjAtD+B1JfXf",
  "ciphertext": "Tf/h6o53hH9prQVscze5Rfgow6qffgJDTgPL...",
  "authTag": "ebBH27HXPFbtv8At2eLWyg=="
}
```
**Response (200 OK):**
```json
{
  "status": "CONFIDENTIALITY_VERIFIED",
  "message": "AES-256-GCM encrypted payload decrypted successfully with authenticated tag verification.",
  "recordSummary": {
    "accountNumber": "CONFIDENTIAL-9921",
    "classification": "TOP_SECRET_FINANCIAL",
    "decryptedLengthBytes": 42
  },
  "tagVerified": true
}
```
