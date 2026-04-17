# auth-service

Phase 1 authentication service for ModIntel.

## Endpoints

- `GET /health`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `GET /api/v1/auth/sessions`
- `POST /api/v1/auth/sessions/revoke`
- `POST /api/v1/auth/sessions/revoke-all`

## Environment

- `AUTH_PORT` (default `8084`)
- `MONGO_URI` (default `mongodb://localhost:27017/modintel`)
- `MONGO_DB_NAME` (default `modintel`)
- `JWT_SECRET` (must be 32+ chars in production)
- `JWT_ACCESS_EXPIRY` (default `15m`)
- `JWT_REFRESH_EXPIRY` (default `168h`)
- `BCRYPT_COST` (default `12`)
- `RATE_LIMIT_AUTH` (default `5` per minute per IP)
- `AUTH_BOOTSTRAP_ADMIN_EMAIL` (optional)
- `AUTH_BOOTSTRAP_ADMIN_PASSWORD` (optional)
- `AUTH_BOOTSTRAP_ADMIN_ROLE` (default `admin`)
- `AUTH_BOOTSTRAP_ADMIN_NAME` (default `ModIntel`)
