# Device-Bound Identity

SecureLayer device trust is certificate-bound, not password-bound.

## Registration Flow

1. The device generates its own asymmetric key pair locally.
2. The device creates a PKCS#10 certificate signing request.
3. The device sends only the CSR to SecureLayer.
4. SecureLayer validates CSR proof of possession.
5. SecureLayer issues an X.509 device certificate.
6. SecureLayer stores the device identity, certificate fingerprint, public-key hash, certificate state, and audit events.

The device private key is never transmitted to the server.

## Device States

- `PENDING`: created but not active.
- `ACTIVE`: registered, enabled, and eligible for mTLS authentication.
- `SUSPENDED`: temporarily disabled.
- `REVOKED`: permanently revoked; active certificates are revoked too.

## Certificate Lifecycle

SecureLayer supports issuance, validation, expiration checks, revocation, and rotation. Rotation requires a CSR whose public key matches the registered device identity.

## Authentication

SDK and protected-application access should use mTLS where possible. A device is trusted only when all checks pass:

- device is registered for the tenant,
- device state is `ACTIVE`,
- device is enabled,
- presented certificate is bound to the device,
- certificate is not expired,
- certificate is not revoked,
- certificate public key matches the registered device public-key hash.

A username/password or device secret alone is not sufficient for protected application access.

## Policy Support

Protected applications can enforce "only registered devices may access" by using the device-aware authorization path. It combines normal policy evaluation with certificate-bound device validation.

## Audit Events

SecureLayer records audit events for device registration, certificate issuance, certificate validation/authentication, certificate rotation, certificate revocation, device suspend, device enable, and device revoke.
