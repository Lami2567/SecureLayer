# SecureLayer Deployment & Production Operations Guide

## 1. Local Development Deployment (Docker Compose)

The fastest method to deploy SecureLayer is using the bundled multi-service `docker-compose.yml`.

### Prerequisites
- Docker Engine $\ge$ 26.0
- Docker Compose $\ge$ 2.24
- Allocated memory: 4 GB minimum

### Startup
```bash
docker compose up --build -d
```

### Checking Container Health
```bash
docker compose ps
```

All seven containers should report healthy/running:
- `securelayer-postgres`
- `securelayer-redis`
- `securelayer-security-core`
- `securelayer-gateway`
- `securelayer-dashboard`
- `securelayer-demo-node-app`
- `securelayer-demo-python-app`

---

## 2. Production Kubernetes Blueprint

In production cloud environments (AWS EKS, Google GKE, Azure AKS), SecureLayer is structured as:
1. **Stateless Gateway Deployment:** Scaled horizontally with a Horizontal Pod Autoscaler (HPA) targeting CPU and request latency.
2. **Control Plane StatefulSet / Deployment:** Connected to managed PostgreSQL (Amazon RDS / Google Cloud SQL) and managed Redis (ElastiCache / Memorystore).

```
                      INTERNET / INGRESS
                              │
                      [ AWS ALB / Ingress ]
                              │
          ┌───────────────────┴───────────────────┐
          │ (HPA: 5 - 50 Replicas)                │
          ▼                                       ▼
  ┌───────────────┐                       ┌───────────────┐
  │ Gateway Pod 1 │                       │ Gateway Pod N │
  └───────┬───────┘                       └───────┬───────┘
          │                                       │
          └───────────────────┬───────────────────┘
                              │
                              ▼
                  [ Internal Network Load Balancer ]
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
          ▼                                       ▼
  ┌───────────────────────┐               ┌───────────────────────┐
  │  security-core Pod 1  │               │  security-core Pod 2  │
  └───────────┬───────────┘               └───────────┬───────────┘
              │                                       │
              └───────────────────┬───────────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
  ┌───────────────────────────────┐               ┌───────────────┐
  │ Amazon RDS PostgreSQL Multi-AZ│               │ Redis Cluster │
  └───────────────────────────────┘               └───────────────┘
```

---

## 3. Production Hardening: KMS & HSM Transition

To transition this reference prototype into high-assurance enterprise production:

### 3.1. Hardware Security Modules (HSMs) for Certificate Authority
- **The Problem:** In containerized deployments, CA private keys residing on disk or in environment variables are vulnerable to memory dump or container breakout attacks.
- **Production Solution:**
  - Delegate X.509 certificate signing to a PKCS#11-compliant **Hardware Security Module (HSM)** (e.g. AWS CloudHSM, YubiHSM, or Thales Luna).
  - The Root CA key is generated inside the tamper-resistant hardware and marked non-exportable.
  - Signing requests are transmitted via PKCS#11 API calls.

### 3.2. Cloud KMS for Envelope Encryption
- **The Problem:** Static master keys (`SECURELAYER_KEY_ENCRYPTION_MASTER_KEY`) require secure distribution and manual rotation.
- **Production Solution:**
  - Integrate **AWS KMS** (`aws:kms:arn`) or **Google Cloud KMS**.
  - Symmetric data encryption uses KMS `GenerateDataKey` APIs.
  - The plaintext Data Encryption Key (DEK) is used strictly in RAM for AES-256-GCM and immediately scrubbed; only the encrypted DEK (eDEK) is stored alongside the ciphertext.

### 3.3. Mutual TLS (mTLS) Ingress
- Terminate mutual TLS directly at the Gateway's Netty/Jetty listener.
- Configure `client-auth=REQUIRE` with client CA truststore containing SecureLayer's intermediate CA cert.
- The TLS stack performs cryptographic proof-of-possession and certificate chain validation at the TCP/TLS layer before parsing any HTTP payload bytes.
