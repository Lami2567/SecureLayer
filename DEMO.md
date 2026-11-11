# SecureLayer Interactive Demonstration Script (10–15 Minutes)

This script provides an interactive, live demonstration workflow for cybersecurity evaluators, instructors, and security architects.

---

## Demonstration Setup & Environment Verification

### Prerequisites
1. Clone the repository and ensure dependencies are installed:
   ```bash
   npm install
   ```
2. Start the local Docker Compose cluster:
   ```bash
   docker compose up --build -d
   ```
3. Open the Developer Dashboard in your browser:
   **[http://localhost:3000](http://localhost:3000)**

---

## Step-by-Step Walkthrough (10-15 Minutes)

### Milestone 1: Architecture & System Overview (2 Minutes)
- **Goal:** Explain the separation of the centralized control plane from distributed edge enforcement.
- **Action:** Open [http://localhost:3000/overview](http://localhost:3000/overview).
- **Narrative:**
  > *"SecureLayer eliminates the global bottleneck and single point of failure found in legacy security appliances by decoupling the control plane (`security-core` on port 8090) from stateless, horizontally scalable data plane proxies (`gateway` on port 8080). Notice the active services: PostgreSQL for the append-only relational ledger, Redis for sub-millisecond session and revocation caching, and upstream microservices."*

---

### Milestone 2: Application Registration (1 Minute)
- **Goal:** Demonstrate registration of a protected corporate asset.
- **Action:** Navigate to **Applications** in the Dashboard (`/applications`).
- **Narrative:**
  > *"We see the registered client application `Core Retail Banking Portal` (Client ID: `banking-app`). Applications must be approved before receiving traffic. The gateway requires the `X-SecureLayer-Client-Id` header to tie every incoming request to an authorized application profile."*

---

### Milestone 3: Device Registration & Proof-of-Possession (1.5 Minutes)
- **Goal:** Prove that devices are individually registered with cryptographic proof-of-possession.
- **Action:** Navigate to **Devices** (`/devices`).
- **Narrative:**
  > *"Notice Device A (`dev-a-active-1001`), Device B (`dev-b-pending-2002`), and Device C (`dev-c-suspended-3003`). During registration, Device A generated an asymmetric key pair locally. The server issued a challenge nonce, which Device A signed to verify possession of the private key without ever transmitting it over the wire. Once verified, the control plane CA issued an X.509 certificate."*

---

### Milestone 4: Dual-Factor Authentication & Identity (1 Minute)
- **Goal:** Demonstrate the distinction between user authentication and device authorization.
- **Action:** View the seed credentials in [`init-dev-data.sql`](file:///c:/Users/USER/Documents/BCS/21/DATA%20CODING%20AND%20ENCRYPTION/Coursework/infrastructure/postgres/init-dev-data.sql).
- **Narrative:**
  > *"Alice Developer logs in with Argon2id-hashed credentials, receiving an OAuth 2.1 token. However, presenting this token alone is not enough. SecureLayer enforces dual-factor actor verification: the user identity must be bound to a cryptographically validated, registered device."*

---

### Milestone 5: End-to-End Confidentiality (AES-256-GCM) (1.5 Minutes)
- **Goal:** Demonstrate cross-language payload encryption with authenticated tag verification.
- **Action:** Run the Python verification endpoint:
  ```bash
  curl -X POST http://localhost:3002/demo/encrypt -H "Content-Type: application/json" -d "{\"plaintext\": \"Confidential Wire Balance: $250,000\"}"
  ```
- **Narrative:**
  > *"The payload is sealed using AES-256-GCM. Observe the 96-bit unique CSPRNG nonce, the ciphertext, and the 128-bit authentication tag. Every message uses a freshly generated IV, eliminating nonce-reuse attacks. We verify that ciphertext encrypted in Node.js or Python decrypts reliably across Java 25."*

---

### Milestone 6: Request Integrity Verification (SHA-256) (1.5 Minutes)
- **Goal:** Show that tampering with a single byte in transit causes immediate rejection.
- **Action:** Send a tampered request to the Protected Banking API via the Gateway:
  ```bash
  curl -i -X POST http://localhost:8080/banking/transfers \
    -H "X-SecureLayer-Client-Id: banking-app" \
    -H "X-SecureLayer-Device-Id: dev-a-active-1001" \
    -H "X-Message-Sha256: dGFtcGVyZWQtaGFzaC0wMDAwMDAwMDAwMDAwMDAwMDA=" \
    -H "Content-Type: application/json" \
    -d "{\"amount\": 500000, \"toAccount\": \"ACC-ATTACKER\"}"
  ```
- **Result:** Gateway responds with `HTTP 400 Bad Request`:
  ```json
  { "code": "REQUEST_INTEGRITY_FAILED", "message": "Body hash mismatch" }
  ```
- **Narrative:**
  > *"Because the SHA-256 digest in `X-Message-Sha256` does not match the actual body bytes, the gateway immediately terminates the request. The tampered payload is never parsed by upstream business logic."*

---

### Milestone 7: Non-Repudiation with Ed25519 Digital Signatures (1.5 Minutes)
- **Goal:** Prove that financial transactions cannot be forged or disowned.
- **Action:** View the Ed25519 verification step in `npm run test:e2e`.
- **Narrative:**
  > *"When Alice authorizes a wire transfer, her workstation signs the transaction payload using its private Ed25519 key. The upstream banking service verifies the signature against her public key. If an attacker modifies the recipient or amount after signing, signature verification fails."*

---

### Milestone 8: Policy Enforcement & Trusted Access (1.5 Minutes)
- **Goal:** Show that an authenticated user on an ACTIVE device is granted access.
- **Action:** Request `/banking/accounts` using Device A:
  ```bash
  curl -i -X GET http://localhost:3001/banking/accounts \
    -H "X-SecureLayer-Client-Id: banking-app" \
    -H "X-SecureLayer-Device-Id: dev-a-active-1001"
  ```
- **Result:** `HTTP 200 OK` with Alice's account details.
- **Narrative:**
  > *"Device A is registered, ACTIVE, and satisfies the 'banking-policy' rule. The request is ALLOWED and forwarded."*

---

### Milestone 9: Unauthorized & Suspended Device Rejection (1.5 Minutes)
- **Goal:** Prove that unapproved or suspended devices are denied, even with valid credentials.
- **Action:** Attempt access using Device B (PENDING) and Device C (SUSPENDED):
  ```bash
  curl -i -X GET http://localhost:3001/banking/accounts \
    -H "X-SecureLayer-Client-Id: banking-app" \
    -H "X-SecureLayer-Device-Id: dev-b-pending-2002"
  ```
- **Result:** `HTTP 403 Forbidden` (`ACCESS_DENIED`).
- **Narrative:**
  > *"Device B is known to the system, but an administrator has not approved it. The policy engine evaluates its state as PENDING and enforces the default-DENY rule. Similarly, suspending Device A immediately revokes its access across all gateways."*

---

### Milestone 10: Cryptographic Audit Logging (1.5 Minutes)
- **Goal:** Inspect the tamper-evident audit trail.
- **Action:** Navigate to **Audit Logs** in the Dashboard (`/audit-logs`) or query PostgreSQL:
  ```bash
  docker exec -it securelayer-postgres psql -U securelayer -d securelayer -c "SELECT subject, action, resource, outcome, created_at FROM audit_events ORDER BY created_at DESC LIMIT 10;"
  ```
- **Narrative:**
  > *"Every security-sensitive event—application registration, policy evaluations, certificate rotations, and gateway denials—is recorded in an append-only audit ledger with its deterministic SHA-256 event hash. This creates a provable chain of custody for compliance and forensics."*

---

## Demonstration Script Summary

To execute the entire 10-milestone demonstration automatically in under 10 seconds:

```bash
npm run test:e2e
```
All 14 programmatic assertions will execute sequentially, validating every cryptographic primitive, policy rule, and audit log.
