# SecureLayer Gateway

The **SecureLayer Gateway** is a production-quality, stateless security reverse proxy and policy enforcement data plane designed to protect enterprise applications without modifying their business logic.

## Core Security Responsibilities

1. **Default DENY Policy Enforcement**: All incoming requests are blocked by default unless explicitly allowed by the central control plane policy engine.
2. **Request Integrity Verification**: Inspects the `X-Message-Sha256` header (or configured integrity header) and cryptographically checks the SHA-256 digest of the request body to prevent in-flight tampering.
3. **Device Identity & Certificate Validation**: Extracts and validates client X.509 device certificates (`X-SecureLayer-Client-Certificate` or mTLS client certificates) ensuring proof-of-possession and device status (ACTIVE vs. PENDING/SUSPENDED/REVOKED).
4. **Application Identity**: Validates the registering application's credentials and tenant context via `X-SecureLayer-Client-Id`.
5. **Non-Repudiation & Audit Trail**: Streams structured audit entries to the control plane for every evaluated policy, failed signature, and denied request.
6. **Stateless Horizontal Scaling**: No shared session state inside the gateway; multiple gateway instances can run behind standard L4/L7 load balancers with zero bottlenecking.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Client Application / SDK  |
                      |   (Node, Python, Java, etc) |
                      +--------------+--------------+
                                     |
                                     | HTTPS (TLS 1.3)
                                     v
                      +-----------------------------+
                      |    SecureLayer Gateway      |
                      |  (Stateless Reverse Proxy)  |
                      +--------------+--------------+
                                     |
        +----------------------------+----------------------------+
        |                                                         |
        v                                                         v
+-------------------------------+                         +---------------+
|     Security Core Control     |                         | Upstream App  |
|  Plane (gRPC / REST Policy,   |                         | (Protected    |
|   Cert Validation, Audits)    |                         |  Microservice)|
+-------------------------------+                         +---------------+
```

---

## Deployment Modes

### Mode 1: Standalone Stateless Reverse Proxy
The gateway runs as a standalone Spring Boot service forwarding validated requests to upstream destinations defined by `securelayer.gateway.upstream-url`.

Configuration in `application.yml`:
```yaml
securelayer:
  gateway:
    enabled: true
    tenant-id: "tenant-primary"
    policy-name: "banking-policy"
    upstream-url: "https://banking-service.internal:8443"
    require-request-integrity: true
    require-device-certificate: true
    request-integrity-header: "X-Message-Sha256"
    application-id-header: "X-SecureLayer-Client-Id"
    device-identifier-header: "X-SecureLayer-Device-Id"
    certificate-header: "X-SecureLayer-Client-Certificate"
  control-plane:
    base-url: "http://security-core:8080"
```

Endpoints exposed by the Gateway:
- Proxy Route: `ALL /api/**` (forwards to `upstream-url` when authorized)
- Liveness Probe: `GET /api/v1/health/live` (returns HTTP 200 `{"status": "UP"}`)
- Readiness Probe: `GET /api/v1/health/ready` (verifies downstream connectivity)

---

### Mode 2: Reusable Middleware Filter (`SecureLayerGatewayFilter`)
For applications desiring in-process protection without deploying a separate proxy hopper, include the gateway library and inject `SecureLayerGatewayFilter`:

```java
@Configuration
public class SecurityFilterConfiguration {

    @Bean
    public FilterRegistrationBean<SecureLayerGatewayFilter> secureLayerFilter(SecureLayerGatewayFilter filter) {
        FilterRegistrationBean<SecureLayerGatewayFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/banking/*", "/api/v1/secure/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registrationBean;
    }
}
```

The filter intercepts incoming HTTP requests, performs integrity checks, queries the control plane for policy evaluation, records structured security audit logs, and either aborts with HTTP 400/403 or continues through `filterChain.doFilter(request, response)`.

---

## Security Logs & Structured Observability

The gateway logs security events using SLF4J 2.0 key-value pairs and MDC correlation tracking:

- `gateway.request_received`: Subject, method, URI, client ID, device ID.
- `gateway.integrity_failed`: Reason and body digest mismatch details.
- `gateway.device_certificate_failed`: Validation failure reason.
- `gateway.policy_decision`: Policy name, version, decision (`ALLOW` or `DENY`), reason.
- `gateway.request_forwarded`: Upstream target URI and response status code.
- `gateway.request_denied`: HTTP status code and rejection code.

---

## Running Gateway Tests

```bash
# Run gateway unit and integration test suite
mvn test -pl gateway -am
```
