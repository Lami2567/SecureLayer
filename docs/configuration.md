# Configuration

SecureLayer uses environment variables as the external configuration boundary.

Required production values:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `REDIS_HOST`
- `REDIS_PORT`
- `OIDC_ISSUER_URI`
- `OIDC_AUDIENCE`
- `TLS_KEYSTORE_PATH`
- `TLS_KEYSTORE_PASSWORD`

The gateway configuration lives in `gateway/src/main/resources/application.yml`.

