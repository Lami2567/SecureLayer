# Policy Engine Architecture & Evaluation Model

SecureLayer provides a centralized, generic attribute- and role-based policy evaluation engine (`PolicyEngineService`). There is no hardcoded domain logic; policies are defined as generic JSON rules stored and versioned in PostgreSQL.

---

## 1. Evaluation Dimensions

When evaluating access requests, the policy engine correlates the following contextual attributes:

| Evaluation Dimension | Parameter / Source | Engine Evaluation Logic |
| :--- | :--- | :--- |
| **User Identity** | `userId`, `username` | Matches user `id`, `username`, and account status (`active = true`, `enabled = true`). |
| **Device Identity** | `deviceId`, `deviceIdentifier` | Verifies registration and binding in PostgreSQL `devices` table. |
| **Device Status** | `DeviceState` (`PENDING`, `ACTIVE`, `SUSPENDED`, `REVOKED`) | Rejects suspended, unapproved, or revoked devices. |
| **Application Identity** | `applicationId`, `clientId` | Verifies registration and approval status (`approved = true`) in `applications`. |
| **Requested Resource** | `requestedResource` | Pattern matched with Ant-style wildcards (e.g. `/banking/**`, `/api/v1/transfers/*`). |
| **HTTP Method** | `httpMethod` / `action` | Method matching (`GET`, `POST`, `PUT`, `DELETE`, `*`). |
| **Request Context** | `requestContext` key-value map | Matches arbitrary request metadata attributes (e.g. `risk: low`, `channel: web`). |
| **Certificate Status** | `X509Certificate` / SHA-256 fingerprint | Confirms certificate validity window (`notBefore` to `notAfter`), non-revocation, and CA signature. |
| **User Role** | `userRoles` / Identity roles | Role containment check (`SUPER_ADMIN`, `ADMIN`, `DEVELOPER`, `SECURITY_OPERATOR`, `DEVICE`). |
| **Time Restrictions** | `time` object (`zone`, `daysOfWeek`, `start`, `end`) | Validates local time window and allowed days of the week. |
| **IP / Network Information** | `ipAddress` / `ipNetworks` | Evaluates IP addresses against subnet CIDR masks (e.g. `10.0.0.0/8`, `192.168.1.0/24`). |

---

## 2. Policy Decisions

Every policy rule specifies one of four distinct security outcomes defined in `PolicyDecisionType`:

1. **`ALLOW`**: The request satisfies all required conditions and is permitted to proceed to upstream business logic.
2. **`DENY`**: The request fails required conditions or falls through to default-deny.
3. **`REQUIRE_MFA`**: Step-up multi-factor authentication is required before the request can be allowed.
4. **`REQUIRE_DEVICE_CERTIFICATE`**: A valid device certificate is missing or invalid; caller must present a trusted certificate.

---

## 3. Policy Storage, Versioning & Activation

- **PostgreSQL Persistence**: Policies are stored in the `security_policies` table with unique constraint `(tenant_id, name, version)`.
- **Versioning**: When policies are updated, developers increment the version integer. Older policy versions are preserved for historical audit and rollback.
- **Activation / Deactivation**:
  - `activatePolicyVersion(tenantId, name, version)` marks all other versions of that policy as `active = false` and sets the target version to `active = true`.
  - Lookups use indexed queries:
    ```sql
    SELECT * FROM security_policies 
    WHERE tenant_id = :tenantId AND name = :name AND active = true 
    ORDER BY version DESC LIMIT 1;
    ```

---

## 4. Default Deny Stance

The engine strictly adheres to a **default-deny** security baseline:
1. If no active policy exists for the requested policy name $\rightarrow$ **`DENY`**.
2. If none of the rules in an active policy match the incoming request context $\rightarrow$ **`DENY`**.
3. If policy evaluation encounters an exception or parsing error $\rightarrow$ **`DENY`**.

---

## 5. Audit Trail on Policy Decisions

Every evaluation call automatically creates an immutable audit record in PostgreSQL (`audit_events`):
- **Subject**: Caller username, device ID, or system identity.
- **Action**: `POLICY_EVALUATION`.
- **Resource**: Format `<DECISION>:<POLICY_NAME>`.
- **Hash**: SHA-256 cryptographic digest of the decision and timestamp.
- **Redis Sync**: Most recent tenant audit event cached in Redis with a 300-second TTL.

---

## 6. Generic Banking Example (No Hardcoded Logic)

```json
{
  "name": "banking-policy",
  "version": 1,
  "rules": [
    {
      "effect": "ALLOW",
      "conditions": {
        "user": { "active": true },
        "device": { "registered": true, "state": "ACTIVE" },
        "certificate": { "required": true, "valid": true },
        "application": { "approved": true },
        "resource": "/banking/**",
        "httpMethods": ["GET", "POST"]
      },
      "reason": "Access allowed: authenticated active user with approved application and valid registered active device certificate."
    },
    {
      "effect": "DENY",
      "conditions": {
        "resource": "/banking/**"
      },
      "reason": "Access denied: does not meet active device, user, and certificate requirements."
    }
  ]
}
```
All criteria are evaluated generically against [`EvaluationFacts`](../security-core/src/main/java/com/securelayer/core/service/PolicyEngineService.java).
