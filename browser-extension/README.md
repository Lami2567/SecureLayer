# SecureLayer Chrome Extension (Manifest V3)

A production-grade, application-level access control browser extension built with **TypeScript**, **Chrome Extensions Manifest V3**, and the **Web Crypto API**.

> [!IMPORTANT]
> **Application-Level Access Control — Not a VPN**
> SecureLayer is NOT a VPN or network-layer tunnel. It performs direct cryptographic identity binding, device certificate status validation, application origin detection, and centralized policy enforcement at the application and HTTP level.

---

## Security Architecture & Key Protections

```
 +-----------------------------------------------------------------------+
 |                         GOOGLE CHROME BROWSER                         |
 |                                                                       |
 |   [ Webpage / DOM ]                        [ SecureLayer Extension ]  |
 |   https://bank.example.com/*                                          |
 |         |                                                             |
 |         | URL navigation                                              |
 |         v                                                             |
 |   +---------------+  DETECT_PROTECTED_APPLICATION  +---------------+  |
 |   | Content Script| -----------------------------> | Service Worker|  |
 |   | (Isolated DOM)|                                | (MV3 Worker)  |  |
 |   +---------------+                                +-------+-------+  |
 |         ^                                                  |          |
 |         | SECURELAYER_DECISION                             |          |
 |         | (In-Page Banner)                                 |          |
 |         +--------------------------------------------------+          |
 |                                                            |          |
 |                                      Web Crypto API        v          |
 |                                  +---------------------------------+  |
 |                                  | Extension Isolated Storage      |  |
 |                                  | - IndexedDB: Non-extractable    |  |
 |                                  |   ECDSA P-256 private key       |  |
 |                                  | - chrome.storage.local:         |  |
 |                                  |   Session token, policy cache   |  |
 |                                  +---------------------------------+  |
 +------------------------------------------------------------|----------+
                                                              |
                                           HTTPS / REST       v
                                    +------------------------------------+
                                    |    SecureLayer Control Plane       |
                                    |  - Device Identity Service         |
                                    |  - Policy Evaluation Engine        |
                                    |  - Tamper-Evident Audit Trail      |
                                    +------------------------------------+
```

### 1. Non-Extractable Private Keys
- Device asymmetric key pairs are generated inside the background service worker using `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])`.
- Setting `extractable: false` guarantees that **the private key cannot be exported or serialized** by any script, including extension scripts.
- Keys are persisted in extension-isolated IndexedDB. Webpage JavaScript and content scripts have zero access to the private key material.

### 2. Device Proof-of-Possession
- The extension exports only its public JWK and deterministic SHA-256 thumbprint during registration.
- Audit records and evaluation assertions are digitally signed using `crypto.subtle.sign`, proving device possession without transmitting private key bytes.

### 3. Fail-Closed Default Policy Enforcement
- If the control plane is unreachable, the device is unregistered, the certificate is invalid or suspended, or the user is not authenticated: the extension enforces **DENY**.

---

## Features

1. **Device Registration**:
   - Generates browser-bound asymmetric keys and registers device identity with the SecureLayer control plane.
2. **Device Identity**:
   - Unique device identifier derived from the SHA-256 thumbprint of the public key.
3. **Certificate Status**:
   - Verifies certificate lifecycle states (`VALID`, `DENIED`, `SUSPENDED`, `REVOKED`, `NOT_REGISTERED`).
4. **User Authentication (Login & Logout)**:
   - Manages bearer tokens and user credentials stored securely in `chrome.storage.local`.
5. **Protected Application Detection**:
   - Continuously monitors active tab navigation and matches URLs against configured patterns (e.g. `https://bank.example.com/*`, `http://localhost:3000/banking/*`).
6. **Policy Evaluation Request**:
   - Dispatches contextual policy queries (`GET`, path, user identity, device ID, certificate fingerprint) to `/api/v1/admin/tenants/{tenantId}/policy-evaluations`.
7. **Access Allowed/Denied Notifications**:
   - Native desktop notifications (`chrome.notifications.create`).
   - Dynamic extension icon badge (`OK` in green or `DENY` in red).
   - In-page high-visibility security banner injected into protected pages.
8. **Security Status Dashboard**:
   - Popup interface displaying real-time access status, device trust level, certificate health, and configuration.
9. **Tamper-Evident Audit Trail**:
   - Digitally signs and logs every access decision locally and submits them to the centralized SecureLayer audit log.

---

## Scenario Walkthrough

### Scenario A: Trusted Device Visits Banking URL
1. User navigates to `https://bank.example.com/accounts`.
2. Content script detects the protected URL pattern and notifies the background service worker.
3. Service worker obtains the device security context (`ACTIVE` device, valid certificate, active login).
4. SecureLayer policy engine evaluates the request:
   - **Decision**: `ALLOW`
5. Extension sets green `OK` badge, sends browser notification, and displays in-page access banner: `[SECURELAYER] ACCESS ALLOWED`.
6. Event is signed with the device private key and recorded in the audit trail.

### Scenario B: Unknown or Unapproved Device Visits Banking URL
1. Device B visits `https://bank.example.com/accounts` without an approved device certificate.
2. Service worker evaluates policy:
   - **Decision**: `DENY` ("Caller does not present a registered ACTIVE device").
3. Extension sets red `DENY` badge, sends desktop warning, and displays in-page alert: `[SECURELAYER] ACCESS DENIED`.
4. Denial event is signed and stored in the audit trail.

---

## Development & Testing

```bash
# Compile TypeScript files to dist/
npm --workspace @securelayer/browser-extension run build

# Run all unit tests (Web Crypto, Policy Engine, URL Matching, Storage)
npm --workspace @securelayer/browser-extension test
```

### Loading in Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in upper right).
3. Click **Load unpacked**.
4. Select the `browser-extension` folder.
5. Pin the **SecureLayer** shield icon in the Chrome toolbar.
