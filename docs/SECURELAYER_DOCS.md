# SecureLayer Docs: The Simple Zero-Trust Platform Guide

> **Zero-Code Security for Developers:**  
> You **do not** need to write complex cryptographic algorithms, calculate SHA-256 hashes by hand, or manage encryption keys in your application. SecureLayer's Gateway handles all zero-trust protection automatically.

---

## ❮ Quick Navigation
- [1. How SecureLayer Works in Plain English](#1-how-securelayer-works-in-plain-english)
- [2. Quickstart in 3 Simple Steps](#2-quickstart-in-3-simple-steps)
- [3. Why It's Simple (Before vs. After)](#3-why-its-simple-before-vs-after)
- [4. Simple 1-Line Code Integrations](#4-simple-1-line-code-integrations)
  - [Node.js / Express (1-Line Middleware)](#a-nodejs--express-1-line-middleware)
  - [Python (Simple Request Calling)](#b-python-client-calling)
  - [Java / Spring Boot (Filter Registration)](#c-java--spring-boot-filter-registration)
- [5. Visual Dashboard: Manage Devices with 1 Click](#5-visual-dashboard-manage-devices-with-1-click)
- [6. Services & Port Reference](#6-services--port-reference)
- [7. Self-Test Knowledge Check](#7-self-test-knowledge-check)

---

## 1. How SecureLayer Works in Plain English

Instead of writing complex security and authentication checks into every single backend route, you place the **SecureLayer Gateway (Port 8080)** in front of your microservices:

```
    ┌──────────────────────────┐             ┌──────────────────────────┐
    │       Client / App       │             │   Your Backend Service   │
    │  (Web, Mobile, External) │             │ (Node, Python, Java, Go) │
    └────────────┬─────────────┘             └────────────▲─────────────┘
                 │                                        │
                 │ 1. Regular HTTP Request                │ 3. Forward Only
                 │    (No crypto code needed)             │    If Verified
                 ▼                                        │
    ┌─────────────────────────────────────────────────────┴─────────────┐
    │                SECURELAYER GATEWAY (Port 8080)                     │
    │  ✓ Automatically checks if device is registered and approved      │
    │  ✓ Automatically checks if payload was tampered in transit        │
    │  ✓ Automatically records tamper-evident audit logs in PostgreSQL  │
    └───────────────────────────────────────────────────────────────────┘
```

If an attacker tampers with the message or connects from an unapproved device, **the Gateway stops them immediately**. Your backend service never even receives the bad request.

---

## 2. Quickstart in 3 Simple Steps

### Step 1: Start the Platform
From your project directory, run:
```powershell
docker compose up -d
```
All background services (Gateway, Security Core, PostgreSQL, Redis, and Dashboard) start in the background.

### Step 2: Route Requests Through the Gateway
Instead of calling your service port directly, send requests through the Gateway at:
```text
http://localhost:8080/your-service-path
```

### Step 3: That's It!
Your application is now enterprise-grade Zero-Trust protected without writing any cryptographic code!

---

## 3. Why It's Simple (Before vs. After)

| Without SecureLayer (Hard) | With SecureLayer (Simple) |
| :--- | :--- |
| Writing hundreds of lines of cryptographic math in each service | **Zero cryptographic code in your application** |
| Manually hashing request bodies and checking for tampering | **Gateway automatically verifies payload integrity** |
| Building custom device approval and X.509 PKI systems | **Gateway blocks unapproved devices fail-closed** |
| Writing manual audit log code across every endpoint | **Automatic immutable audit ledger in PostgreSQL** |

---

## 4. Simple 1-Line Code Integrations

If you are developing backend microservices or client apps, our polyglot SDKs handle everything in 1 line.

### A. Node.js / Express (1-Line Middleware)

Just add `secureLayerMiddleware()` to your Express app:

```javascript
import express from "express";
import { secureLayerMiddleware } from "@securelayer/sdk-node";

const app = express();

// 1 LINE TO SECURE YOUR APPLICATION:
app.use(secureLayerMiddleware());

// Your regular business logic — zero crypto code needed!
app.get("/banking/accounts", (req, res) => {
  res.json({
    accountNumber: "ACC-1001",
    balance: "$25,000.00",
    status: "Verified & Protected"
  });
});

app.listen(3001);
```

---

### B. Python Client (Calling Protected APIs)

```python
import requests

# Call through the gateway with your device ID:
response = requests.get(
    "http://localhost:8080/banking/accounts",
    headers={"X-SecureLayer-Device-Id": "dev-a-active-1001"}
)

print(response.json())
```

---

### C. Java / Spring Boot (Filter Registration)

```java
@Configuration
public class SecurityConfig {

    @Bean
    public FilterRegistrationBean<SecureLayerGatewayFilter> secureFilter(SecureLayerGatewayFilter filter) {
        // Automatically protects all /banking/* endpoints
        return new FilterRegistrationBean<>(filter);
    }
}
```

---

## 5. Visual Dashboard: Manage Devices with 1 Click

You don't need database queries or complicated terminal commands. Open the visual console in your browser:

**[http://localhost:3000](http://localhost:3000)**

- **Approve or Suspend Devices**: Click **Devices** to view enrolled devices. Click `Suspend` to instantly block a compromised device, or `Enable` to approve a pending device.
- **View Audit Logs**: Click **Audit Logs** to review who did what, when, and see cryptographic SHA-256 verification hashes.
- **Simulate Policy Decisions**: Test whether an action will be `ALLOWED` or `DENIED` using the visual policy editor.

---

## 6. Services & Port Reference

| Service | Port | What It Does |
| :--- | :--- | :--- |
| **Developer Dashboard** | `3000` | Open in browser (`http://localhost:3000`) for 1-click device management. |
| **Security Gateway** | `8080` | Route your API requests here (`http://localhost:8080`) for automatic zero-trust protection. |
| **Protected Banking API**| `3001` | Sample business service running behind the gateway. |
| **Python Demo Service** | `3002` | Sample cross-language verification service. |

---

## 7. Self-Test Knowledge Check

**Question: Do developers need to write cryptographic math to use SecureLayer?**
- [ ] A) Yes, developers must manually calculate AES nonces and write hash functions.
- [x] **B) No, SecureLayer's Gateway or 1-line middleware automatically handles all cryptography.** *(Correct!)*
- [ ] C) Yes, developers must maintain database tables for every request.
