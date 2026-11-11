# SecureLayer Gateway

The SecureLayer gateway is a stateless enforcement point for existing HTTP applications. Put it in front of an upstream app and route protected traffic through the gateway. The upstream application does not need to rewrite business handlers to call SecureLayer directly.

## Request Flow

1. Authenticate the caller with OAuth/OIDC.
2. Verify request integrity using `X-Message-Sha256`.
3. Resolve application identity from `X-SecureLayer-Client-Id`.
4. Optionally validate device identity using mTLS client certificates or `X-SecureLayer-Client-Certificate`.
5. Evaluate the configured SecureLayer policy through the control-plane API.
6. Record an audit event.
7. Forward only explicitly allowed requests to `SECURELAYER_UPSTREAM_BASE_URL`.

If any step fails, the gateway denies the request. The default behavior is `DENY`.

## Horizontal Scaling

Gateway instances keep no session state. Run multiple instances behind a load balancer and point each instance at the same control plane and upstream application. Request replay, policy state, certificates, and audit storage remain control-plane responsibilities.

## Important Configuration

```text
SECURELAYER_CONTROL_PLANE_URL=http://localhost:8081
SECURELAYER_CONTROL_PLANE_TOKEN=...
SECURELAYER_TENANT_ID=...
SECURELAYER_POLICY_NAME=default
SECURELAYER_UPSTREAM_BASE_URL=http://localhost:3000
SECURELAYER_REQUIRE_REQUEST_INTEGRITY=true
SECURELAYER_REQUIRE_DEVICE_CERTIFICATE=false
```

Identity headers:

```text
X-Message-Sha256
X-SecureLayer-Client-Id
X-SecureLayer-Device-Id
X-SecureLayer-Client-Certificate
```

## Health Checks

- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`
- `GET /actuator/health` when Actuator is available

## Security Logs

The gateway emits structured key-value security events:

- `gateway.integrity_failed`
- `gateway.device_certificate_failed`
- `gateway.policy_decision`

Each event includes correlation id, subject, method, path, decision, policy metadata, and reason where applicable.
