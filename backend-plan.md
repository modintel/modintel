# Backend API Architecture Plan

## Project: ModIntel - Hybrid WAF Research System

**Document Version:** 1.0  
**Created:** 2026-04-16  
**Status:** Ready for Implementation

---

## Executive Summary

This document outlines the production-ready backend API architecture for ModIntel, a cybersecurity-focused web application combining WAF (Web Application Firewall) analytics with machine learning. The architecture emphasizes security, scalability, and clean separation of concerns.

**Core Philosophy:** Rules detect → ML judges → Humans verify edge cases.

---

## Architecture Overview

```
Client
   |
   v
Caddy Reverse Proxy (TLS, Routing)
   |
   v
Coraza WAF (OWASP CRS)
   |
   |----> WAF decision (rules triggered)
   |
Auth Service (Go:8084)  ---->  MongoDB
   |                              |
   |                              |
   v                              v
Review API (Go:8082) <---->  Users, Roles, Tokens
   |
   |----> Dashboard, Analytics, Review UI
   |
Log Collector (Go:8081) ---> Alerts Collection
   |
ML Inference (Py:8083) ----> Feature Extraction, Prediction
```

---

## Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Reverse Proxy | Caddy | 2.x |
| WAF Engine | Coraza + OWASP CRS | Latest |
| API Framework | Go (Gin) | 1.22+ |
| ML Service | Python (FastAPI) | 3.11+ |
| Database | MongoDB | 6.0+ |
| Authentication | JWT (golang-jwt/jwt/v5) | v5 |
| Password Hashing | bcrypt | Standard |
| Rate Limiting | In-memory + MongoDB | Custom |

---

## Service Architecture

### 1. Auth Service (New) - Port 8084
**Responsibilities:**
- User registration and login
- JWT token generation and validation
- Token refresh
- Password reset
- RBAC permission checking
- Session management

### 2. Review API (Enhanced) - Port 8082
**Responsibilities:**
- Dashboard data endpoints
- Alert review and classification
- Analytics and reporting
- System configuration
- Protected by auth middleware

### 3. Log Collector (Existing) - Port 8081
**Responsibilities:**
- Tail Coraza audit logs
- Normalize and enrich with ML
- Store in MongoDB
- Health checks

### 4. ML Inference Engine (Existing) - Port 8083
**Responsibilities:**
- Feature extraction
- Attack probability prediction
- SHAP-based explanations
- Model versioning

### 5. Caddy + Coraza (Existing) - Port 8080
**Responsibilities:**
- TLS termination
- Request routing
- WAF inspection
- Audit logging

---

## Authentication Architecture

### JWT Token Design

**Access Token:**
- Algorithm: HS256
- Expiration: 15 minutes
- Contains: user_id, email, role, iat, exp

**Refresh Token:**
- Expiration: 7 days
- Contains: user_id, type="refresh", jti (unique id), iat, exp
- Stored in MongoDB for revocation support

### Token Storage Strategy

| Token Type | Storage | Expiration | Rotation |
|------------|---------|------------|----------|
| Access Token | Client (httpOnly cookie) | 15 minutes | No |
| Refresh Token | MongoDB + Client | 7 days | Yes (reuse detection) |

---

## Role-Based Access Control (RBAC)

### Role Definitions

| Role | Description | Use Case |
|------|-------------|----------|
| `admin` | Full system access | System administrators |
| `analyst` | Review alerts, view analytics | Security analysts |
| `viewer` | Read-only access | Auditors, managers |

### Permission Matrix

| Endpoint | Method | Admin | Analyst | Viewer |
|----------|--------|-------|---------|--------|
| `/api/alerts` | GET | ✓ | ✓ | ✓ |
| `/api/alerts/{id}/review` | POST | ✓ | ✓ | ✗ |
| `/api/alerts/{id}` | PUT/DELETE | ✓ | ✓ | ✗ |
| `/api/users` | GET/POST | ✓ | ✗ | ✗ |
| `/api/users/{id}` | PUT/DELETE | ✓ | ✗ | ✗ |
| `/api/rules` | GET | ✓ | ✓ | ✓ |
| `/api/rules` | POST/PUT/DELETE | ✓ | ✗ | ✗ |
| `/api/system/config` | GET/PUT | ✓ | ✗ | ✗ |
| `/api/analytics` | GET | ✓ | ✓ | ✓ |

---

## API Structure

### Versioning
All endpoints prefixed with `/api/v1/`

### Module Organization

```
/api/v1/
├── auth/           # Authentication
│   ├── POST /login
│   ├── POST /logout
│   ├── POST /refresh
│   ├── POST /forgot-password
│   └── POST /reset-password
├── users/          # User Management
│   ├── GET /users
│   ├── GET /users/{id}
│   ├── POST /users
│   ├── PUT /users/{id}
│   └── DELETE /users/{id}
├── roles/          # RBAC Management
│   ├── GET /roles
│   └── GET /roles/{id}/permissions
├── alerts/         # Alert Management
│   ├── GET /alerts
│   ├── GET /alerts/{id}
│   ├── POST /alerts/{id}/review
│   └── GET /alerts/stats
├── analytics/      # Analytics & Reporting
│   ├── GET /analytics/traffic
│   ├── GET /analytics/trends
│   └── GET /analytics/metrics
└── system/         # System Operations
    ├── GET /system/health
    ├── GET /system/config
    └── PUT /system/config
```

---

## Security Best Practices

### 1. Input Validation
- JSON schema validation for all requests
- Strict type checking
- SQL/NoSQL injection prevention
- XSS protection

### 2. Rate Limiting
- Per-IP: 100 requests/minute (general)
- Per-user: 1000 requests/hour (authenticated)
- Auth endpoints: 5 attempts/minute (strict)
- Storage: In-memory cache with MongoDB persistence

### 3. Secure Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS)
- Content-Security-Policy

### 4. Error Handling
- Generic error messages to clients
- Detailed logs for debugging (server-side only)
- No stack traces in responses
- Structured error format:
  ```json
  {
    "success": false,
    "error": "Invalid credentials",
    "code": "AUTH_001"
  }
  ```

---

## WAF Integration

### Request Flow

```
Client Request
    ↓
Caddy (TLS termination)
    ↓
Coraza WAF (Request inspection)
    ├─> Blocked → Return 403
    └─> Allowed → Continue
    ↓
Feature Extractor
    ↓
ML Inference (if anomaly detected)
    ├─> High probability → Block
    ├─> Low probability → Allow
    └─> Uncertain → Send to Review
    ↓
Backend API (with auth check)
    ↓
Response
```

### Audit Logging
All requests logged with:
- Timestamp
- Client IP
- User ID (if authenticated)
- Endpoint
- Method
- Status code
- Response time
- WAF rule IDs triggered
- ML prediction (if applicable)

---

## Database Schema

### Collections

**users:**
```json
{
  "_id": "ObjectId",
  "email": "string (unique)",
  "password_hash": "string (bcrypt)",
  "role": "string (admin|analyst|viewer)",
  "first_name": "string",
  "last_name": "string",
  "is_active": "boolean",
  "email_verified": "boolean",
  "last_login": "datetime",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

**refresh_tokens:**
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId (ref)",
  "token_hash": "string",
  "jti": "string (unique)",
  "expires_at": "datetime",
  "created_at": "datetime",
  "revoked": "boolean",
  "revoked_at": "datetime"
}
```

**password_reset_tokens:**
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId (ref)",
  "token_hash": "string",
  "expires_at": "datetime",
  "used": "boolean",
  "created_at": "datetime"
}
```

**alerts** (existing, enhanced):
```json
{
  "_id": "ObjectId",
  "timestamp": "datetime",
  "client_ip": "string",
  "uri": "string",
  "method": "string",
  "headers": "object",
  "triggered_rules": "array[string]",
  "anomaly_score": "number",
  "ai_status": "string",
  "ai_score": "number",
  "ai_priority": "string",
  "reviewed_by": "ObjectId (ref)",
  "reviewed_at": "datetime",
  "review_decision": "string (true_positive|false_positive|investigating)"
}
```

---

## Middleware Stack

### 1. Logger Middleware
- Request ID generation
- Request/response logging
- Execution time tracking

### 2. Recovery Middleware
- Panic recovery
- Graceful error responses

### 3. CORS Middleware
- Configured for dashboard origin
- Credentials support

### 4. Security Headers Middleware
- Add security headers to all responses

### 5. Rate Limiting Middleware
- IP-based limiting
- User-based limiting (if authenticated)
- Skip for health checks

### 6. Authentication Middleware
- JWT validation
- Token extraction from header/cookie
- User context injection

### 7. Authorization Middleware (RBAC)
- Role checking
- Permission validation
- Resource access control

### 8. Validation Middleware
- JSON schema validation
- Input sanitization

---

## Performance & Scalability

### Stateless Design
- No server-side sessions
- All state in JWT or database
- Horizontal scaling ready

### Caching Strategy
- In-memory rate limit counters
- MongoDB query optimization with indexes
- Response caching for analytics (future)

### Database Indexes
```javascript
// users collection
db.users.createIndex({ "email": 1 }, { unique: true })
db.users.createIndex({ "role": 1 })

// refresh_tokens collection
db.refresh_tokens.createIndex({ "token_hash": 1 })
db.refresh_tokens.createIndex({ "user_id": 1 })
db.refresh_tokens.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })

// alerts collection
db.alerts.createIndex({ "timestamp": -1 })
db.alerts.createIndex({ "client_ip": 1 })
db.alerts.createIndex({ "ai_priority": 1 })
db.alerts.createIndex({ "reviewed_by": 1 })
```

---

## Implementation Phases

### Phase 1: Core Authentication (Week 1)
**Priority: Security Critical**

1. **Create auth-service structure**
   - Service scaffolding
   - MongoDB connection
   - Basic middleware setup

2. **Implement user model**
   - User struct with validation
   - Password hashing (bcrypt)
   - Repository pattern

3. **Implement JWT middleware**
   - Token generation
   - Token validation
   - Token extraction

4. **Create auth endpoints**
   - POST /api/v1/auth/login
   - POST /api/v1/auth/logout
   - POST /api/v1/auth/refresh
   - GET /api/v1/auth/me

5. **Setup token storage**
   - Refresh token collection
   - Token revocation logic
   - Cleanup of expired tokens

**Deliverables:**
- Working auth service
- JWT authentication flow
- Token refresh mechanism

---

### Phase 2: RBAC & Security Hardening (Week 2)
**Priority: Security Hardening**

1. **Implement RBAC system**
   - Role definitions
   - Permission middleware
   - Role-based access control

2. **Create user management endpoints**
   - CRUD operations for users
   - Role assignment
   - User activation/deactivation

3. **Add rate limiting**
   - In-memory rate limiter
   - Per-IP limits
   - Per-user limits
   - MongoDB persistence

4. **Implement input validation**
   - JSON schema validation
   - Request sanitization
   - Type checking

5. **Add security headers**
   - Security headers middleware
   - CORS configuration
   - Secure cookie settings

**Deliverables:**
- RBAC working
- Rate limiting active
- Input validation on all endpoints

---

### Phase 3: Password Management (Week 3)
**Priority: Security Hardening**

1. **Implement password reset flow**
   - Forgot password endpoint
   - Reset token generation
   - Email template (placeholder)
   - Reset password endpoint

2. **Add password security**
   - Password strength validation
   - Password history (optional)
   - Account lockout after failed attempts

3. **Implement session management**
   - List active sessions
   - Revoke specific sessions
   - Revoke all sessions (logout everywhere)

**Deliverables:**
- Password reset working
- Session management complete

---

### Phase 4: Review API Integration (Week 4)
**Priority: Architecture Completion**

1. **Enhance review-api with auth**
   - Integrate JWT middleware
   - Add RBAC middleware
   - Protect all endpoints

2. **Migrate existing data**
   - Create default admin user
   - Update alert collection schema
   - Backfill reviewed_by fields

3. **Add user context to logging**
   - Track which user reviewed alerts
   - Audit log for user actions
   - Analytics by user role

4. **Create dashboard serving**
   - Serve HTML from Go (not static)
   - Inject auth token into page
   - Protect dashboard routes

**Deliverables:**
- Review API protected
- Dashboard integrated with auth
- Data migration complete

---

### Phase 5: Testing & Documentation (Week 5)
**Priority: Quality Assurance**

1. **Unit tests**
   - Auth middleware tests
   - JWT validation tests
   - RBAC tests
   - Rate limiting tests

2. **Integration tests**
   - End-to-end auth flow
   - API endpoint tests
   - Security tests

3. **Documentation**
   - API endpoint documentation
   - Authentication guide
   - Deployment guide

**Deliverables:**
- Test coverage > 80%
- Documentation complete

---

## Sensitive Endpoint Protection

### Critical Endpoints

| Endpoint | Risk Level | Protection |
|----------|------------|------------|
| POST /auth/login | High | Rate limit: 5/min, IP tracking |
| POST /auth/forgot-password | High | Rate limit: 3/hour, email validation |
| POST /auth/reset-password | High | Token validation, one-time use |
| POST /users | Critical | Admin only, audit log |
| PUT /users/{id} | Critical | Self or admin, audit log |
| DELETE /users/{id} | Critical | Admin only, soft delete |
| PUT /system/config | Critical | Admin only, change notification |

### Security Measures
- All critical endpoints require authentication
- Admin endpoints require admin role
- Audit logs for all critical operations
- Rate limiting with progressive delays
- IP-based suspicious activity detection

---

## Example Requests/Responses

### Login
**Request:**
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "analyst@modintel.io",
  "password": "SecurePass123!"
}
```

**Success Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: refresh_token=eyJhbGciOiJIUzI1NiIs...; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
Content-Type: application/json

{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": "507f1f77bcf86cd799439011",
      "email": "analyst@modintel.io",
      "role": "analyst",
      "first_name": "John",
      "last_name": "Doe"
    }
  }
}
```

**Error Response:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "success": false,
  "error": "Invalid credentials",
  "code": "AUTH_001"
}
```

### Get Alerts (Protected)
**Request:**
```http
GET /api/v1/alerts?page=1&limit=50&priority=P1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Success Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "507f1f77bcf86cd799439012",
        "timestamp": "2026-04-16T10:30:00Z",
        "client_ip": "192.168.1.100",
        "uri": "/api/search?q=test",
        "method": "GET",
        "ai_score": 0.85,
        "ai_priority": "P1",
        "reviewed": false
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 1250,
      "total_pages": 25
    }
  }
}
```

### Access Denied (RBAC)
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "success": false,
  "error": "Insufficient permissions",
  "code": "AUTH_003",
  "required_role": "admin"
}
```

---

## Environment Variables

### Auth Service
```bash
# Server
AUTH_PORT=8084
AUTH_HOST=0.0.0.0

# Database
MONGO_URI=mongodb://localhost:27017/modintel
MONGO_DB_NAME=modintel

# JWT
JWT_SECRET=your-super-secret-key-min-32-characters
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h  # 7 days

# Security
BCRYPT_COST=12
MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCKOUT_DURATION=15m

# Rate Limiting
RATE_LIMIT_IP=100  # requests per minute
RATE_LIMIT_USER=1000  # requests per hour
RATE_LIMIT_AUTH=5  # attempts per minute
```

### Review API (Enhanced)
```bash
# Server
REVIEW_API_PORT=8082
REVIEW_API_HOST=0.0.0.0

# Database
MONGO_URI=mongodb://localhost:27017/modintel

# Auth (connection to auth-service)
JWT_SECRET=your-super-secret-key-min-32-characters
AUTH_SERVICE_URL=http://auth-service:8084

# CORS
ALLOWED_ORIGINS=http://localhost:8080
```

---

## Deployment Checklist

### Pre-deployment
- [ ] Generate strong JWT_SECRET (32+ chars)
- [ ] Configure MongoDB indexes
- [ ] Set up TLS certificates
- [ ] Configure firewall rules

### Deployment
- [ ] Deploy auth-service
- [ ] Deploy enhanced review-api
- [ ] Update Caddy configuration
- [ ] Create default admin user

### Post-deployment
- [ ] Verify all health checks pass
- [ ] Test authentication flow
- [ ] Test RBAC permissions
- [ ] Verify rate limiting
- [ ] Check audit logs
- [ ] Run security scan

---

## Future Enhancements (Post-MVP)

### Phase 6: Advanced Features
- OAuth2/OIDC integration
- Multi-factor authentication (MFA)
- API key management for service-to-service
- Advanced analytics dashboard
- Real-time notifications
- Webhook support

### Phase 7: Enterprise Features
- LDAP/AD integration
- SAML SSO
- Audit trail export
- Compliance reporting
- Data retention policies
- Backup/restore procedures

---

## Success Metrics

### Security
- Zero authentication bypass vulnerabilities
- 100% RBAC enforcement on protected endpoints
- <0.1% false positive rate for rate limiting

### Performance
- Auth middleware latency < 5ms
- Login response time < 200ms
- API response time < 100ms (p95)

### Reliability
- 99.9% uptime for auth service
- Zero data loss during migration
- Graceful degradation on dependencies

---

## Conclusion

This architecture provides a secure, scalable foundation for the ModIntel platform. The phased approach allows incremental delivery while maintaining security standards. Each phase builds on the previous, ensuring a robust authentication and authorization system before adding complexity.

**Next Steps:**
1. Review and approve this plan
2. Begin Phase 1 implementation
3. Set up development environment
4. Create feature branches for each phase

---

**Document Owner:** Backend Team  
**Reviewers:** Security Team, DevOps Team  
**Approval Date:** TBD
