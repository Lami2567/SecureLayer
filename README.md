# SecureLayer: Enterprise Zero-Trust Cybersecurity Platform

[![Security Standard](https://img.shields.io/badge/Security-Zero--Trust-blue.svg)](#)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20Ed25519%20%7C%20SHA--256-green.svg)](#)
[![Java](https://img.shields.io/badge/Java-25%20(Spring%20Boot%204.1.1)-orange.svg)](#)
[![Node.js](https://img.shields.io/badge/Node.js-22%20LTS-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12-yellow.svg)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](#)

> **SecureLayer** is a cross-language zero-trust cybersecurity platform and academic prototype designed to retrofit microservices and distributed systems with enterprise-grade **Confidentiality**, **Integrity**, **Authentication**, and **Non-Repudiation** without requiring changes to underlying application business logic.

---

## Table of Contents

1. [Architecture & Topology](#architecture--topology)
2. [Prerequisites](#prerequisites)
3. [Quickstart: Running the Application](#quickstart-running-the-application)
4. [Services & Port Mappings](#services--port-mappings)
5. [Automated Testing Suite](#automated-testing-suite)
   - [A. End-to-End Integration Test (`npm run test:e2e`)](#a-end-to-end-integration-test-npm-run-teste2e)
   - [B. Running Container Demo Verifier (`verify-docker-demo.ps1`)](#b-running-container-demo-verifier-verify-docker-demops1)
   - [C. Node.js SDK Unit Tests](#c-nodejs-sdk-unit-tests)
   - [D. Python SDK Cryptographic Tests](#d-python-sdk-cryptographic-tests)
6. [Interactive Manual Testing & Demonstration](#interactive-manual-testing--demonstration)
   - [1. Web Dashboard Exploration](#1-web-dashboard-exploration)
   - [2. Service Health Checks](#2-service-health-checks)
   - [3. Device Policy Enforcement (Fail-Closed DENY)](#3-device-policy-enforcement-fail-closed-deny)
   - [4. Payload Tampering & Integrity Verification](#4-payload-tampering--integrity-verification)
   - [5. Digital Signatures & Non-Repudiation (Ed25519)](#5-digital-signatures--non-repudiation-ed25519)
   - [6. Authenticated Encryption (AES-256-GCM)](#6-authenticated-encryption-aes-256-gcm)
   - [7. Querying the Cryptographic Audit Ledger in PostgreSQL](#7-querying-the-cryptographic-audit-ledger-in-postgresql)
7. [Operational & Troubleshooting Guide](#operational--troubleshooting-guide)
8. [Documentation Index](#documentation-index)

---

## Architecture & Topology

```
                                      CLIENT TIER
  ┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐
  │  Next.js Dashboard    │   │ Chrome Ext (MV3)      │   │ External API Clients  │
  │  (Port 3000)          │   │ (Web Crypto API)      │   │ (Java / Node / Python)│
  └───────────┬───────────┘   └───────────┬───────────┘   └───────────┬───────────┘
              │                           │                           │
══════════════╪═══════════════════════════╪═══════════════════════════╪═════════════════
              │ REST Management           │ Policy Inquiries          │ Protected Calls
              ▼                           ▼                           ▼
  ┌───────────────────────────────────────────────────────────────────────────────┐
  │                     SECURELAYER GATEWAY (Port 8080)                           │
  │  - Stateless HTTP Reverse Proxy            - X-Message-Sha256 Digest Checking │
  │  - Device Certificate Validation          - Fail-Closed Default DENY Gate     │
  └───────────────────────┬───────────────────────────────┬───────────────────────┘
                          │                               │
        Evaluate Policy & │ Validation                    │ Forward Permitted
        Audit Log Inflow  ▼                               ▼
  ┌─────────────────────────────────────────┐   ┌─────────────────────────────────┐
  │      SECURITY CORE (Port 8090/9090)     │   │      UPSTREAM PROTECTED APIS     │
  │  - Java 25 / Spring Boot Control Plane  │   │  - Demo Banking API (Port 3001) │
  │  - Internal X.509 CA & PoP Verifier     │   │  - Demo Python Svc (Port 3002)  │
  │  - Dynamic Policy Engine (RBAC + ABAC)  │   └─────────────────────────────────┘
  │  - Cryptographic Audit Event Logger     │
  └─────────────┬─────────────────────┬─────┘
                │                     │
                ▼                     ▼
  ┌───────────────────────┐ ┌───────────────────┐
  │ PostgreSQL (Port 5432)│ │ Redis (Port 6379) │
  │ Persistent Ledger     │ │ Caching & Tokens  │
  └───────────────────────┘ └───────────────────┘
```

---

## Prerequisites

Before running the platform, ensure the following software is installed on your host system:

| Prerequisite | Recommended Version | Purpose |
|---|---|---|
| **Docker Desktop / Engine** | Docker 24+ / Compose v2 | Runs the 7-container microservice stack |
| **Node.js & npm** | Node.js 20+ LTS (v22 recommended) | Runs client scripts, E2E scenarios, and SDK build |
| **PowerShell** | PowerShell 5.1+ or PowerShell Core 7+ | Runs verification scripts on Windows |
| **Python** *(Optional)* | Python 3.12+ | For local standalone Python SDK testing |
| **Java JDK & Maven** *(Optional)* | Java 25 & Maven 3.9+ | For local native Java builds outside Docker |

> [!IMPORTANT]
> **Ensure Docker Desktop is open and running** before launching the containers. On Windows, verify that Docker is in **Linux Containers** mode.

---

## Quickstart: Running the Application

### 1. Install Node Dependencies
From the repository root, install workspace dependencies:
```powershell
npm install
```

### 2. Launch the Application Stack
Start all 7 services in the background using Docker Compose:
```powershell
docker compose up --build -d
```
> [!NOTE]
> The initial build compiles Java 25 services (`security-core` and `gateway`), installs Python/Node dependencies, and compiles the Next.js dashboard. Thanks to Docker BuildKit caching, subsequent builds take only a few seconds.

### 3. Verify Container Health
Check that all 7 containers are up and healthy:
```powershell
docker compose ps
```
You should see all containers running:
- `securelayer-postgres` (healthy)
- `securelayer-redis` (healthy)
- `securelayer-security-core` (healthy / running)
- `securelayer-gateway` (running)
- `securelayer-demo-node-app` (running)
- `securelayer-demo-python-app` (running)
- `securelayer-dashboard` (running)

---

## Services & Port Mappings

Once running, the microservices expose the following endpoints on `localhost`:

| Service | Container Name | Port | Description |
|---|---|---|---|
| **Developer Dashboard** | `securelayer-dashboard` | [http://localhost:3000](http://localhost:3000) | Next.js visual security console & audit explorer |
| **Security Gateway** | `securelayer-gateway` | [http://localhost:8080](http://localhost:8080) | Stateless reverse proxy & policy enforcement point |
| **Security Core (REST)** | `securelayer-security-core` | [http://localhost:8090](http://localhost:8090) | Central control plane, CA, and policy engine |
| **Security Core (gRPC)** | `securelayer-security-core` | `localhost:9090` | Binary high-speed DataPlane & ControlPlane RPC |
| **Demo Banking API** | `securelayer-demo-node-app` | [http://localhost:3001](http://localhost:3001) | Protected Node.js upstream business service |
| **Demo Python App** | `securelayer-demo-python-app` | [http://localhost:3002](http://localhost:3002) | Cross-language Python verification service |
| **PostgreSQL 18** | `securelayer-postgres` | `localhost:5432` | Relational audit ledger & seed database |
| **Redis 8** | `securelayer-redis` | `localhost:6379` | Sub-millisecond session & CRL cache |

---

## Automated Testing Suite

SecureLayer provides four levels of automated testing:

### A. End-to-End Integration Test (`npm run test:e2e`)
Runs the comprehensive 14-step integration test validating the entire zero-trust lifecycle:
```powershell
npm run test:e2e
```
**What this validates:**
1. Developer application registration (`banking-app`).
2. Security policy compilation and activation.
3. Asymmetric device keypair generation & X.509 certificate issuance.
4. **Active device access** allowed through the gateway (`HTTP 200`).
5. **Pending device access** blocked fail-closed (`HTTP 403`).
6. **Suspended device access** blocked fail-closed (`HTTP 403`).
7. **Message tampering detection** via SHA-256 digest (`HTTP 400 REQUEST_INTEGRITY_FAILED`).
8. **Ed25519 digital signature** creation and verification (Non-repudiation).
9. **Tampered transaction signature failure** verification.
10. **Cross-SDK AES-256-GCM** encryption and decryption roundtrip (Node.js, Python, Java).
11. **Tamper-evident audit trail** persistence in the ledger.

---

### B. Running Container Demo Verifier (`verify-docker-demo.ps1`)
Runs automated probes directly against the live Docker containers:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-docker-demo.ps1
```
**Expected Output:**
```text
===============================================================================
       SECURELAYER LOCAL DOCKER DEMONSTRATION VERIFIER
===============================================================================

[1/4] Probing Service Health Endpoints...
  ✓ Demo Banking API is healthy (http://localhost:3001/health)
  ✓ Demo Python App is healthy (http://localhost:3002/health)
  ✓ Security Gateway is healthy (http://localhost:8080/actuator/health)

[2/4] Triggering Protected Banking Scenario...
  ✓ Banking Scenario Completed: SecureLayer Banking Demonstration
    - Step 1: Access with ACTIVE Device A -> ALLOWED
    - Step 2: Access with PENDING Device B -> DENIED
    - Step 3: Payload tampering detection -> REJECTED (HTTP 400 REQUEST_INTEGRITY_FAILED)
    - Step 4: Ed25519 transaction digital signature -> VALID
    - Step 5: AES-256-GCM confidentiality encryption/decryption -> CONFIRMED

[3/4] Triggering Cross-Language Python Verification...
  ✓ Python SDK Suite: SecureLayer Python SDK Security Verification
    - Device Key Generation (Ed25519): PASSED
    - Transaction Non-Repudiation (Ed25519): PASSED
    - Payload Integrity (SHA-256): PASSED
    - Confidentiality (AES-256-GCM Authenticated Encryption): PASSED

[4/4] Environment Summary:
  • Developer Dashboard: http://localhost:3000
  • Gateway Proxy:       http://localhost:8080
  • Security Core REST:  http://localhost:8090
  • Banking Core:        http://localhost:3001
  • Python Verifier:     http://localhost:3002
===============================================================================
```

---

### C. Node.js SDK Unit Tests
Tests the TypeScript SDK cryptographic primitives and HTTP middlewares:
```powershell
npm --workspace @securelayer/sdk-node test
```
*Executes all 9 unit test suites (AES-256-GCM, Ed25519, SHA-256, clock skew tolerance, and request interceptors).*

---

### D. Python SDK Cryptographic Tests
Tests Python's `cryptography` library integration:
```powershell
$env:PYTHONPATH="sdk-python/src"; python -m unittest discover -s sdk-python/tests
```
*Validates SHA-256 hashing, AES-256-GCM authenticated cipher roundtrip, and Ed25519 signing/verification.*

---

## Interactive Manual Testing & Demonstration

Follow these steps to manually test and inspect each zero-trust objective:

### 1. Web Dashboard Exploration
Open **[http://localhost:3000](http://localhost:3000)** in your browser:
- **Overview (`/overview`):** View real-time platform metrics, active devices, and gateway health.
- **Applications (`/applications`):** Inspect registered clients (`Core Retail Banking Portal`).
- **Devices (`/devices`):** View registered devices:
  - `dev-a-active-1001` (`ACTIVE` state)
  - `dev-b-pending-2002` (`PENDING` state)
  - `dev-c-suspended-3003` (`SUSPENDED` state)
- **Policies (`/policies`):** Review the active JSON zero-trust rulebook.
- **Audit Logs (`/audit-logs`):** Inspect the tamper-evident security event ledger with SHA-256 cryptographic hashes.

---

### 2. Service Health Checks
Verify microservice health using `curl` or PowerShell:
```powershell
# Gateway Health
curl http://localhost:8080/actuator/health

# Security Core Health
curl http://localhost:8090/actuator/health

# Upstream Banking API Health
curl http://localhost:3001/health

# Upstream Python Verifier Health
curl http://localhost:3002/health
```

---

### 3. Device Policy Enforcement (Fail-Closed DENY)

The Security Gateway requires registered device identity and application credentials.

#### Test 3.1: Access without Credentials (Default Fail-Closed DENY)
Call the protected gateway without device headers:
```powershell
curl -i http://localhost:8080/banking/accounts
```
**Response:** `HTTP/1.1 401 Unauthorized` or `HTTP/1.1 403 Forbidden` (rejected before reaching the banking app).

#### Test 3.2: Access with Active Device (ALLOWED)
Trigger the banking scenario endpoint to simulate an authorized request with `ACTIVE` device credentials:
```powershell
Invoke-RestMethod -Uri "http://localhost:3001/demo/scenario" -Method Post | ConvertTo-Json -Depth 4
```
**Result:** Step 1 executes successfully with `ALLOWED`.

#### Test 3.3: Access with Pending or Suspended Device (DENIED)
In the same scenario output, observe Steps 2 and 3:
- Device B in `PENDING` state is rejected with `DENIED`.
- Device C in `SUSPENDED` state is rejected with `DENIED`.

---

### 4. Payload Tampering & Integrity Verification

SecureLayer enforces message integrity using the `X-Message-Sha256` header. If a message body is altered in transit by even a single byte, the Gateway immediately aborts processing.

In Step 3 of the banking demo:
- **Original payload:** `{"transferId":"TX-1001","amount":500}` with valid SHA-256 digest header.
- **Tampered payload:** `{"transferId":"TX-1001","amount":999999}` (attacker altered amount).
- **Result:** Gateway responds with `HTTP 400 Bad Request` and error code `REQUEST_INTEGRITY_FAILED`.

---

### 5. Digital Signatures & Non-Repudiation (Ed25519)

Test Ed25519 transaction signing directly in the Python container:
```powershell
Invoke-RestMethod -Uri "http://localhost:3002/demo/run" -Method Post | ConvertTo-Json -Depth 4
```
**What happens under the hood:**
1. A fresh Ed25519 keypair is generated.
2. A financial transaction `{"transferId": "TX-PY-9921", "amount": 15000}` is signed with the private key.
3. Verification against the public key succeeds (`PASSED`).
4. The transaction amount is tampered to `999999`.
5. Verification immediately fails (`tamperedRejected: true`).

---

### 6. Authenticated Encryption (AES-256-GCM)

Cross-language confidentiality is tested across Node.js, Python, and Java:
- 256-bit symmetric keys.
- Unique 96-bit (12-byte) initialization vectors (nonces) generated per message from system CSPRNGs.
- 128-bit authentication tags to prevent chosen-ciphertext attacks.
- Plaintext is recovered bit-for-bit across all three languages without leakage.

---

### 7. Querying the Cryptographic Audit Ledger in PostgreSQL

Every authorization, registration, signature, and denial is immutably logged. Query the database container directly:

```powershell
docker exec -it securelayer-postgres psql -U securelayer -d securelayer -c "SELECT id, action, subject, resource, outcome, created_at FROM audit_events ORDER BY created_at DESC LIMIT 10;"
```

To view the cryptographic SHA-256 event hashes:
```powershell
docker exec -it securelayer-postgres psql -U securelayer -d securelayer -c "SELECT subject, action, encode(event_hash, 'hex') AS event_sha256 FROM audit_events ORDER BY created_at DESC LIMIT 5;"
```

---

## Operational & Troubleshooting Guide

### Viewing Container Logs
To inspect live logs from any service:
```powershell
# Security Core (Control Plane)
docker logs -f securelayer-security-core

# Gateway Reverse Proxy
docker logs -f securelayer-gateway

# Banking API
docker logs -f securelayer-demo-node-app

# Python App
docker logs -f securelayer-demo-python-app
```

### Stopping the Application
To stop all containers without losing data:
```powershell
docker compose stop
```

To resume the containers:
```powershell
docker compose start
```

### Full Teardown & Reset
To stop containers, remove the network, and delete database volumes for a clean slate:
```powershell
docker compose down -v
```
To restart from scratch with clean seed data:
```powershell
docker compose up --build -d
```

### Common Issues & Solutions

1. **Docker Desktop is not running:**
   - *Error:* `failed to connect to the docker API at ...`
   - *Solution:* Launch Docker Desktop from the Start Menu and wait until the status indicator turns green before running `docker compose up`.

2. **Port Conflict on 3000, 5432, 6379, 8080, or 8090:**
   - *Error:* `Bind for 0.0.0.0:<port> failed: port is already allocated`
   - *Solution:* Check if local PostgreSQL, Redis, or Node servers are already running on those ports (`Get-Process -Id (Get-NetTCPConnection -LocalPort <port>).OwningProcess`) and stop them before launching Compose.

3. **PowerShell Script Execution Policy Error:**
   - *Error:* `... cannot be loaded because running scripts is disabled on this system`
   - *Solution:* Run PowerShell with `-ExecutionPolicy Bypass`:
     ```powershell
     powershell -ExecutionPolicy Bypass -File scripts/verify-docker-demo.ps1
     ```

---

## Documentation Index

For in-depth architectural and theoretical details, refer to the project's documentation suite:

| Document | Description |
|---|---|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Control Plane vs. Data Plane decoupling, topology, and scalability |
| **[SECURITY.md](SECURITY.md)** | Analysis of the 4 security objectives, algorithms, CSPRNGs, and threat boundaries |
| **[DEMO.md](DEMO.md)** | 10–15 minute interactive presentation script for evaluators and architects |
| **[DEPLOYMENT.md](DEPLOYMENT.md)** | Production hardening, Kubernetes manifests, and cloud KMS/HSM integration |
| **[THREAT-MODEL.md](THREAT-MODEL.md)** | STRIDE analysis, attack surface definitions, and mitigations |
| **[PROTOCOL.md](PROTOCOL.md)** | Wire protocol specification, HTTP header structures, and gRPC definitions |
| **[DEVELOPER-GUIDE.md](DEVELOPER-GUIDE.md)** | Guide to integrating Node.js, Python, and Java SDKs into client apps |
| **[API.md](API.md)** | Complete REST and gRPC API reference across all services |
| **[docs/SECURELAYER_DOCS.md](docs/SECURELAYER_DOCS.md)** | SecureLayer platform documentation and developer guide |
| **[docs/securelayer-docs.html](docs/securelayer-docs.html)** | Interactive single-page documentation with cyan and blue UI |

---

## Academic & Prototype Statement

SecureLayer was developed as an advanced academic research project and reference implementation for zero-trust data plane architectures and device-bound identity.

- **No Custom Cryptography:** All cryptographic primitives rely directly on vetted platform security providers: OpenSSL (via Node.js `crypto` and Python `cryptography`) and Bouncy Castle / SunJCE (Java 25).
- **Production Transition Guidance:** In enterprise deployments, symmetric data keys and CA root keys must be backed by a FIPS 140-2 Level 3 Hardware Security Module (HSM) or Cloud KMS (AWS KMS, Google Cloud KMS, HashiCorp Vault), rather than development secrets. See [DEPLOYMENT.md](DEPLOYMENT.md) for details.
