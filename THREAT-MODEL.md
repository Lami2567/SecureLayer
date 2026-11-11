# SecureLayer Threat Model & STRIDE Analysis

## 1. Scope, System Boundaries & Assumptions

### System Under Analysis
SecureLayer enforces zero-trust access control, payload confidentiality, message integrity, and non-repudiation between client applications (browsers, native SDKs, third-party clients), the stateless Security Gateway, and protected internal enterprise services (e.g., Banking Core).

### Assumed Adversary Capabilities
We evaluate the system against adversaries with the following capabilities:
1. **Full Network Control (Dolev-Yao Model):** The adversary can intercept, inspect, drop, inject, modify, replay, and re-order packets between any client and the gateway.
2. **Untrusted Client Host:** The adversary may run arbitrary scripts on unauthorized machines, modify local browser DOM/JavaScript memory, or attempt credential stuffing using valid corporate user logins.
3. **Malicious Insider / Compromised Employee:** The adversary possesses valid username/password credentials but operates an unapproved, unmanaged, or compromised device.

### Non-Assumptions (Out of Scope)
- Physical extraction of keys from a FIPS 140-3 Level 3 Hardware Security Module (HSM).
- Direct kernel-level compromise or hypervisor breakout on the isolated `security-core` host.

---

## 2. STRIDE Threat Assessment Matrix

| STRIDE Category | Threat Description | Attack Vector | SecureLayer Mitigation | Residual Risk & Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary impersonates an authorized device or user | Stolen username/password used from unapproved machine | **Device-Bound Identity & PoP:** Gateway mandates registered device X.509 cert and active device status. Valid user creds on untrusted hardware are blocked (`HTTP 403`). | If private key is extracted from an insecure client OS disk, the device identity is spoofed. (Mitigate with TPM/Secure Enclave). |
| **Tampering** | Man-in-the-Middle alters financial transfer parameters in transit | Intercepting HTTP payload to change `amount: 50` to `amount: 500000` | **Message Integrity (`X-Message-Sha256`) & AEAD:** Gateway checks payload digest before routing; AES-256-GCM auth tags detect any bit flip. | Plaintext HTTP between Gateway and upstream application if internal network is untrusted (Deploy internal mTLS). |
| **Repudiation** | User executes a wire transfer and later denies authorization | Claiming an unauthorized system process or admin submitted the transfer | **Ed25519 Digital Signatures:** Transactions must be signed by the client device private key. Signatures are verified and archived with immutable timestamps. | Compromise of client signing key allows forged actions until revoked. |
| **Information Disclosure** | Sniffing sensitive financial balances or PII on intermediate networks | Intercepting network traffic across public Wi-Fi or compromised switches | **AES-256-GCM Confidentiality:** Payloads are encrypted at rest and in transit using 256-bit keys and fresh CSPRNG nonces. | Side-channel attacks on weak client runtimes if memory is directly inspected. |
| **Denial of Service** | Flooding Gateway with malformed requests or invalid signatures | Resource exhaustion via expensive cryptographic operations | **Early Dropping & Rate Limiting:** Gateway drops unauthenticated requests before executing expensive asymmetric signature verifications. | Layer 3/4 volumetric DDoS attacks must be mitigated by edge CDN/Cloudflare infrastructure. |
| **Elevation of Privilege** | Normal user accesses administrative endpoints (`/api/v1/admin`) | Parameter tampering or forged role claims in JWT | **Default-DENY Policy Engine:** Policies strictly require `ROLE_SUPER_ADMIN` or `ROLE_ADMIN` evaluated against cryptographic claims from the IdP. | Misconfiguration of JSON policy syntax by an authorized administrator. |

---

## 3. Specific Security Invariants

### Invariant 1: "User Authentication $\neq$ Authorization"
Possessing valid Active Directory or OAuth credentials does **not** grant access to protected resources. Access requires:
$$\text{Valid User Session} \land \text{Device Registered} \land \text{Device State} = \text{ACTIVE} \land \text{Valid Cert} \land \text{Policy Rule} = \text{ALLOW}$$

### Invariant 2: "Default Behavior is Fail-Closed DENY"
If any evaluation component encounters a network timeout, unknown device, missing signature, corrupted digest, or unmapped resource:
$$\text{Decision} \leftarrow \text{DENY}$$

### Invariant 3: "Private Keys Never Leave the Device Boundary"
During device registration and certificate rotation:
- Private keys are generated locally in hardware/secure storage.
- The server receives only public key bytes and a digital signature verifying proof-of-possession over a fresh challenge.
- Private key transmission over any protocol is strictly prohibited.

---

## 4. Why the Browser Extension is NOT a VPN

A critical conceptual distinction in the SecureLayer architecture is the role of the Chrome Browser Extension:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   NETWORK-LEVEL VPN vs. SECURELAYER                   │
├───────────────────────────────────┬────────────────────────────────────┤
│ Traditional Network VPN           │ SecureLayer Browser Extension      │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Operates at OSI Layer 3 (IP)    │ • Operates at OSI Layer 7 (HTTP)   │
│ • Tunnel all host traffic         │ • Intercepts target URLs only      │
│ • Grants perimeter network trust  │ • Enforces zero-trust per request  │
│ • Any malware on device joins LAN │ • Device identity + policy check   │
│ • High bandwidth & CPU overhead   │ • Native Web Crypto API client     │
└───────────────────────────────────┴────────────────────────────────────┘
```

**The browser extension does not create a virtual network interface, tunnel TCP packets, or bypass corporate firewalls.** 

Instead, it acts as an **application-layer policy and identity agent**:
1. When a user navigates to an internal URL (e.g. `https://bank.corp.internal/banking`), the extension detects the protected domain.
2. It queries local isolated extension storage for the device's asymmetric key pair and X.509 certificate.
3. It performs a lightweight zero-trust pre-flight check with the SecureLayer Policy Engine.
4. If the device is `ACTIVE` and approved, it supplies the requisite device authentication headers to the session.
5. If the device is `PENDING`, `SUSPENDED`, or untrusted, it alerts the user and prevents the session from initiating unauthorized calls.
