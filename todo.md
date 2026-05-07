# ModIntel — Tasks

> **Project tracking for upcoming features and tasks.**

---
## Task -1 — Rule Management System
> Move rule ownership from Go hardcode to MongoDB backend, seed OWASP CRS
> rules (~600) + custom rules (26) from config files, enable toggle + override
> sync, two-section dashboard UI (CRS + custom).

---

## Task 0 — User Invite & 2FA
> Self-registration, email-based invites, password reset, TOTP two-factor
> authentication, SMTP configuration, and onboarding flow.

---

## Task 1 — Layer 2 ML-Based Blocking

> Composite scoring for miss-detector alerts. If Coraza misses an attack but
> regex signatures catch it, we score it and decide: log, monitor, or block.

---

## Task 2 — Miss Model Training Pipeline (Layer 2)

> Train the model that powers `/predict-miss` — the ONNX model that detects
> attacks Coraza misses. No Coraza features, no anomaly scores. Pure raw HTTP
> request data (method, URI, headers, body) → 135 features → predict.

---

## Task 3 — Update SDS Document

> Bring `docs/SDS.pdf` in line with the current system. The document still
> describes the old ModSecurity-centric architecture and needs updating across
> every section.

---

## Task 4 — Comprehensive System Testing
> Unit, integration, e2e, and acceptance tests across the full stack. Metrics
> for Layer 1 (Coraza WAF) vs Layer 2 (ML miss model) vs combined, benchmarked
> against a Coraza-only baseline.

---
---
***
***

# Task -1 - Rule Management Architecture

## Goal
Move rule ownership from Go hardcode to MongoDB backend, enable CRS rule toggling, and provide a unified rule management interface with separate sections for OWASP CRS and Custom rules.

---

## Current State

| Aspect | Current | Target |
|--------|---------|--------|
| Custom rules | 26 rules hardcoded in `handler.go` | Seeded from `custom_rules.conf` into MongoDB |
| CRS rules | Not exposed, not toggleable | Parsed from CRS files, seeded into MongoDB, toggleable |
| Rule state | In-memory Go slice + DB overrides | DB-first with startup seeding |
| UI | Single list of 26 custom rules | Two sections: CRS Rules + Custom Rules |
| Overrides | Only custom rule IDs | Any rule ID (CRS or custom) |

---

## 1. Data Model

### MongoDB `waf_rules` Collection

```json
{
  "id": "942100",
  "type": "crs",
  "category": "SQLi",
  "description": "SQL Injection Attack Detected via libinjection",
  "severity": "CRITICAL",
  "phase": 2,
  "paranoia_level": 1,
  "source": "owasp-crs",
  "enabled": true,
  "created_at": "2026-04-22T00:00:00Z",
  "updated_at": "2026-04-22T00:00:00Z"
}
```

Fields:
- `id` — Coraza rule ID (unique index)
- `type` — `crs` | `custom`
- `category` — SQLi, XSS, LFI, RCE, Protocol, etc.
- `description` — Human-readable rule purpose
- `severity` — CRITICAL | HIGH | MEDIUM | LOW (CRS) or custom mapping
- `phase` — 1 | 2 | 3 | 4 | 5
- `paranoia_level` — 1-4 (CRS only, null for custom)
- `source` — `owasp-crs` | `modintel-custom`
- `enabled` — Current toggle state
- `created_at` / `updated_at` — Timestamps

### Indexes
- Unique: `{ id: 1 }`
- Query: `{ type: 1, category: 1 }`
- Query: `{ enabled: 1 }`

---

## 2. Seeding Strategy

### 2.1 CRS Rules (~600 detection rules)

**Source:** Parse Coraza CRS rule files at review-api startup.

**Which rules to seed:**
Only rules with explicit `id:` that are independently toggleable. Skip:
- Chain rules (child rules without standalone IDs)
- Skip/chain markers
- Initialization rules (901xxx)
- Blocking evaluation rules (949xxx/959xxx)

**Parsing logic:**
```go
// Pseudocode for CRS parser
for each .conf file in /opt/coraza/owasp-crs/rules/:
    for each SecRule directive:
        if line contains "id:" AND standalone rule (not chain child):
            extract id, msg, severity, phase, tag
            map tags to category
            insert into MongoDB if not exists (preserve enabled state)
```

**Category mapping from CRS tags:**
| CRS Tag Prefix | Category |
|---------------|----------|
| `attack-sqli` | SQLi |
| `attack-xss` | XSS |
| `attack-lfi` | LFI |
| `attack-rfi` | RFI |
| `attack-rce` | RCE |
| `attack-execution` | RCE |
| `attack-injection-php` | PHP |
| `attack-protocol` | Protocol |
| `attack-generic` | Generic |
| `attack-session` | Session Fixation |
| `attack-java` | Java |
| `attack-scanner` | Scanner Detection |
| `attack-multipart` | Multipart |
| `leakage-*` | Data Leakage |
| `web-shells` | Web Shells |

### 2.2 Custom Rules (26 rules)

**Source:** Parse `custom_rules.conf` OR keep current Go seed data.

**Approach:** Parse `custom_rules.conf` on startup:
```go
for each SecRule in custom_rules.conf:
    extract id, msg, tag, phase
    insert into MongoDB with type=custom if not exists
```

This removes the need for the Go `defaultWAFRules` slice entirely.

### 2.3 Seed Safety

- **Idempotent:** On each startup, scan for missing rules and insert them. Never overwrite existing `enabled` state.
- **Soft delete:** If a rule file is removed, mark rules as `archived: true` instead of deleting (preserves audit trail).
- **Version tracking:** Store `crs_version` in a metadata collection for traceability.

---

## 3. API Changes

### 3.1 Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/rules?type=crs` | List CRS rules (paginated) |
| GET | `/api/rules?type=custom` | List custom rules (paginated) |
| GET | `/api/rules?category=SQLi` | Filter by category |
| GET | `/api/rules?search=sqli` | Search in description/ID |
| PUT | `/api/rules/:id` | Toggle enable/disable |
| POST | `/api/rules` | Create custom rule |
| PUT | `/api/rules/:id` | Update custom rule metadata |
| DELETE | `/api/rules/:id` | Archive custom rule |

### 3.2 Validation

- CRS rules: Allow toggle only (`enabled`). Reject metadata edits.
- Custom rules: Allow full CRUD.
- Rule ID format: Validate against `^[0-9]{6}$` (6 digits).
- Unknown IDs: Return 404.

### 3.3 Override Sync

`syncManagedWAFOverrides()` already works for any rule ID. No changes needed to the override generation logic — it already queries all `enabled: false` rules.

---

## 4. Frontend Changes

### 4.1 Layout: Two Sections

```
┌─────────────────────────────────────────────┐
│  Rules Management                           │
├─────────────────────────────────────────────┤
│                                             │
│  OWASP CRS Rules          [Search...] [Cat▼]│
│  ┌───────────────────────────────────────┐  │
│  │ ID    Category  Description    Status │  │
│  │ 942100 SQLi     SQL Injection  [On/Off]│ │
│  │ 941100 XSS      XSS via lib... [On/Off]│ │
│  │ ...                                  │  │
│  │ [Prev] [1 2 3 ... 45] [Next]        │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  Custom Rules                               │
│  ┌───────────────────────────────────────┐  │
│  │ ID    Category  Description    Status │  │
│  │ 990001 LFI      etc/passwd     [On/Off]│ │
│  │ ...                                  │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  [Create Custom Rule]  [Restart WAF]        │
└─────────────────────────────────────────────┘
```

### 4.2 CRS Section Features

- **Pagination:** 50 rules per page (cursor-based on `_id` or offset)
- **Category filter:** Dropdown with all CRS categories
- **Paranoia level filter:** Show only rules at selected PL
- **Search:** Filter by rule ID or description
- **Bulk toggle:** Enable/disable all rules in a category (with confirmation)
- **Read-only indicator:** CRS rules show a lock icon; metadata is not editable

### 4.3 Custom Section Features

- All existing functionality preserved
- "Write Custom Rule" left panel already exists
- Full CRUD enabled

### 4.4 WAF Restart Indicator

- Show pending restart flag when ANY rule (CRS or custom) is toggled
- Restart applies to all overrides

---

## 5. Migration Plan

### Phase 1: Seed Mechanism
1. Create `db/rules_seed.go` with CRS parser + custom rule parser
2. Call seed function in `main.go` before starting HTTP server
3. Seed runs once per startup; idempotent

### Phase 2: API Refactor
1. Update `GetRules` to query MongoDB only (remove `defaultWAFRules`)
2. Add `type`, `category`, `search` query params
3. Add pagination (cursor-based for CRS, offset for custom)
4. Validate CRS vs custom permissions

### Phase 3: Frontend Refactor
1. Split rules table into two sections
2. Add pagination controls
3. Add category/paranoia filters for CRS
4. Style CRS rules with read-only indicators

### Phase 4: Cleanup
1. Remove `defaultWAFRules` hardcoded slice from `handler.go`
2. Remove `ruleNotes` hardcoded map from `rules.js` (read from API)
3. Verify override sync still works for CRS + custom IDs

### Phase 5: Testing
1. Seed test: verify all CRS rules inserted with correct metadata
2. Toggle test: disable a CRS rule, verify `SecRuleRemoveById` generated
3. Toggle test: re-enable, verify line removed from overrides
4. Custom rule CRUD: create, update, archive
5. Frontend: pagination, filtering, search
6. WAF restart: verify CRS rule disable takes effect after restart

---

## 6. Docker Compose Changes

```yaml
review-api:
    volumes:
      # Existing mounts
      - /var/run/docker.sock:/var/run/docker.sock
      - ./proxy-waf/overrides:/waf-overrides
      # NEW: Mount CRS rules for parsing
      - modintel_crs_rules:/opt/coraza/owasp-crs/rules:ro
```

Alternative: Copy CRS rules into review-api image at build time (more self-contained, less runtime dependency).

---

## 7. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Disabling CRS chain parent breaks child rules | High | Only seed standalone rules; skip chain children |
| 900+ rules crash dashboard | Medium | Pagination (50/page); virtual scrolling |
| CRS version mismatch | Low | Store `crs_version` in metadata; seed on startup detects changes |
| User disables too many CRS rules | High | Warning banner on bulk disable; audit log |
| Seed overwrites manual toggles on restart | Critical | Upsert with `$setOnInsert` for `enabled` field |

---

## 8. Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/review-api/db/rules_seed.go` | Create | CRS + custom rule parser and seeder |
| `services/review-api/db/rules.go` | Create | Rule CRUD operations |
| `services/review-api/api/handler.go` | Modify | Remove hardcode; add query params |
| `services/review-api/main.go` | Modify | Call seed function on startup |
| `dashboard/js/rules.js` | Modify | Two-section layout, pagination, filters |
| `dashboard/rules.html` | Modify | Updated structure for CRS + custom sections |
| `dashboard/css/rules.css` | Modify | Styles for pagination, filters, read-only indicators |
| `docker-compose.yml` | Modify | Mount CRS rules volume (optional) |
| `services/review-api/Dockerfile` | Modify | Optionally copy CRS seed data |

---

## 9. Success Criteria

- [ ] All CRS rules (~600) appear in dashboard with correct metadata
- [ ] Custom rules (26) appear in separate section
- [ ] Toggle works for both CRS and custom rules
- [ ] Override file contains correct `SecRuleRemoveById` for disabled rules
- [ ] WAF restart applies CRS + custom overrides
- [ ] Pagination loads <500ms for 50 CRS rules
- [ ] Search/filter works across both sections
- [ ] No hardcoded rule metadata remains in frontend
- [ ] No hardcoded rule list remains in Go backend
- [ ] Seed is idempotent — toggles survive restart

---

## 10. Decisions Made

| Decision | Value |
|----------|-------|
| Restore to PL default | No |
| Expose PL as first-class | No |
| Rule hit counts | No |
| Custom rules versioning | Yes - draft state |
| Scoped exclusions | Yes |
| Reset hit counts on upgrade | No - preserve

---

## 11. Future: Scoped Exclusions

*This feature is NOT in the initial implementation but is a major pain point for production WAFs.*

### The Problem

Current plan only toggles rules *globally*. But in production:
- Legitimate file uploads trigger LFI rules
- Rich text editors trigger XSS rules
- API parameters legitimately contain special characters

### Solution: Exclusions

Create separate collection `waf_rule_exclusions`:

```json
{
  "_id": "objectid",
  "rule_id": "942100",
  "scope": "endpoint",
  "match": "/api/upload",
  "param": "file_content",
  "method": "POST",
  "description": "Allow file uploads",
  "enabled": true,
  "created_by": "admin@modintel.local",
  "created_at": "2026-05-05T10:00:00Z"
}
```

### Coraza Implementation Challenge

Coraza doesn't natively support per-endpoint exclusions. Options:

**Option A: Pre-phase skip rules**
```caddyfile
SecRule REQUEST_URI "@beginsWith /api/upload" \
  "id:999001,phase:1,pass,setvar:tx.skip_rule_942100=1"

SecRule &TX:SKIP_RULE_942100 "@eq 1" \
  "phase:2,skipAfter:END_SQLI_CHECK"
```

**Option B: Separate backend route** - bypass WAF entirely for specific URIs.

**Option C: ML-based auto-exclusions** - train model to auto-learn FPs.

---

## 12. Future: Rule Hit Counts (Analytics)

Track how often each rule triggers.

### Implementation

1. Log-collector extracts `rule_details[].rule_id` from alerts
2. Aggregate counter per rule in `waf_rule_stats`:
```json
{
  "rule_id": "942100",
  "trigger_count": 15432,
  "last_triggered": "2026-05-05T10:00:00Z"
}
```

### API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/rules/stats` | Get hit counts for all rules |

---

## 13. Future: IP Reputation

Block known bad IPs before WAF evaluation.

### External Feeds

| Source | Format | Update |
|--------|--------|--------|
| abuse.ch Feodo | CSV | Daily |
| AWS Threatlist | JSON | Hourly |
| FireHOL | IPset | Daily |

### MongoDB

```json
{
  "ip": "192.168.1.100",
  "source": "abuse-ch-feodo",
  "reason": "Botnet C&C",
  "expires_at": "2026-05-12T00:00:00Z"
}
```

---

## 14. Future: Rate Limiting

Block bots behaving differently than humans.

### Config Settings

Add to `waf_config`:
- `rate_limit_requests_per_minute`: 60
- `rate_limit_requests_per_hour`: 1000


# Task 0 — User Invite & 2FA

# User Invite & 2FA Plan

## 1. First-Admin Registration Flow

### Current state
- Admin is bootstrapped via `AUTH_BOOTSTRAP_ADMIN_*` environment variables
- No self-registration endpoint exists

### Target
- The first person to access `/setup` (or first `POST /api/v1/auth/register`) becomes admin
- Subsequent registrations without an invite are rejected

### Implementation

#### 1a. Registration endpoint
`POST /api/v1/auth/register`

Request body:
```json
{
  "email": "admin@example.com",
  "password": "securepassword",
  "first_name": "Admin",
  "last_name": "User"
}
```

Password requirements:
- Minimum 10 characters
- Must contain at least: 1 uppercase, 1 lowercase, 1 number, 1 special character
- Reject common passwords (e.g., "password123", "admin123")

Logic:
```go
func (h *Handler) register(c *gin.Context) {
    // Validate password requirements
    if !isValidPassword(password) {
        return 400 "Password must be at least 10 characters and contain uppercase, lowercase, number, and special character"
    }
    if isCommonPassword(password) {
        return 400 "Password is too common, choose a stronger password"
    }
    
    count, _ := h.users.CountDocuments(ctx, bson.M{})
    
    if count == 0 {
        // First user → admin
        role = "admin"
        emailVerified = false // will verify via 2FA setup
    } else {
        // Not first user → reject (must use invite)
        return 403 "Registration closed. Ask an admin to invite you."
    }
    
    // Create user, set is_active=true, require_2fa_setup=true
    // Return success, redirect to 2FA setup
}
```

#### 1b. Bootstrap fallback with user check
Keep the existing `AUTH_BOOTSTRAP_ADMIN_*` env vars as a fallback for headless deployments. If set:
- Check if users already exist in the database
- If users exist → SKIP bootstrap (do not overwrite or create new admin)
- If no users exist → create the bootstrap admin
- Log a warning if bootstrap is skipped due to existing users

This preserves backward compatibility for Docker deployments and prevents accidental admin creation.

#### 1c. `/setup` page
A dedicated onboarding page served only when no users exist. 
- If users already exist → redirect to login
- Serve `/setup` only when `GET /api/v1/auth/status` returns `{"has_users": false}`

---

## 2. Invite Flow

### 2a. Role restriction
Remove `admin` from the role dropdown in `settings.html`. Admin role can only be acquired via:
- First-user registration
- Bootstrap env vars
- Direct MongoDB update (emergency)

Updated dropdown:
```html
<select id="invite-role" class="invite-role">
    <option value="analyst" selected>Analyst</option>
    <option value="viewer">Viewer</option>
</select>
```

### 2b. Invite endpoint with rate limiting (updated)
`POST /api/v1/users/invite` (admin only)

Request body:
```json
{
  "email": "invitee@gmail.com",
  "role": "analyst"
}
```

Rate limiting:
- Maximum 10 invites per hour per admin
- Return 429 "Rate limit exceeded. Try again later."

What changes:
- Generate a time-limited invite token (24h expiry)
- Store invite in a new `invitations` collection:
  ```json
  {
    "_id": ObjectId,
    "email": "invitee@gmail.com",
    "role": "analyst",
    "invited_by": "admin@modintel.local",
    "token": "crypto-random-hex-64",
    "status": "pending",
    "expires_at": ISODate("+24h"),
    "created_at": ISODate()
  }
  ```
- Send email FROM admin's email TO invitee's email with a link: `https://modintel.local/accept-invite?token=<token>`
- Return `{"success": true, "message": "Invitation sent to invitee@gmail.com"}`

### 2c. Accept-invite endpoint
`POST /api/v1/auth/accept-invite`

Request body:
```json
{
  "token": "crypto-random-hex-64",
  "password": "chosen-password",
  "first_name": "Jane",
  "last_name": "Doe"
}
```

Password requirements same as registration.

Logic:
- Look up token in `invitations` collection
- Validate: exists, status=pending, not expired
- Create user in `users` collection with the assigned role
- Auto-verify email (email_verified = true) since invitee clicked the link
- Mark invite status as "accepted"
- Return success, redirect to 2FA setup

### 2d. Accept-invite page
`/accept-invite` — a minimal page with a password form. Reads `?token=` from URL. On submit, calls `POST /api/v1/auth/accept-invite`.

---

## 3. Password Reset Flow (NEW)

### 3a. Request reset
`POST /api/v1/auth/reset-password/request`

Request body:
```json
{
  "email": "user@example.com"
}
```

Logic:
- Look up user by email
- If exists → generate reset token (1h expiry)
- Store in `password_resets` collection:
  ```json
  {
    "user_id": ObjectId,
    "token": "crypto-random-hex-64",
    "expires_at": ISODate("+1h"),
    "used": false
  }
  ```
- Send email with reset link
- Return success (don't reveal if email exists or not - prevents enumeration)

### 3b. Complete reset
`POST /api/v1/auth/reset-password/complete`

Request body:
```json
{
  "token": "crypto-random-hex-64",
  "new_password": "newsecurepassword"
}
```

Logic:
- Validate token exists, not expired, not used
- Validate new password requirements
- Update user password hash
- Mark token as used
- Invalidate all existing refresh tokens for user
- Return success

### 3c. Reset page
`/reset-password` — form to enter new password after clicking link in email.

---

## 4. Email Sending (SMTP)

### 4a. Why admin's email as sender
Since this is a self-hosted app, the admin configures their own SMTP credentials (Gmail, SendGrid, Mailgun, etc.) during first-time setup. Emails are sent from that address, so invitees see the admin's email as the sender.

### 4b. SMTP configuration
Store in a new `settings` collection in MongoDB, or as part of the admin user profile:

```json
{
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_username": "admin@gmail.com",
  "smtp_password": "app-password",
  "smtp_from": "admin@gmail.com",
  "smtp_from_name": "ModIntel Security"
}
```

Admin configures this via Settings → Email Configuration. The password is encrypted at rest.

### 4c. SMTP endpoint
`PUT /api/v1/settings/smtp` (admin only)

An `email` package in the auth-service handles sending via Go's `net/smtp` or a library like `gomail`.

### 4d. Invite email template
```
Subject: You've been invited to ModIntel

From: Admin Name <admin@gmail.com>
To: invitee@gmail.com

Hi,

Admin Name has invited you to join ModIntel as an Analyst.

Click here to accept: https://modintel.local/accept-invite?token=abc123

This link expires in 24 hours.
```

---

## 5. Two-Factor Authentication (2FA)

### 5a. TOTP-based (Time-based One-Time Password)
Use TOTP (RFC 6238) — the same algorithm used by Google Authenticator, Authy, 1Password, etc. No SMS costs, works offline, industry standard.

### 5b. User model additions
Add to `User` struct:
```go
type User struct {
    // ... existing fields
    TOTPSecret        string `bson:"totp_secret,omitempty" json:"-"`
    TOTPEnabled       bool   `bson:"totp_enabled" json:"totp_enabled"`
    TOTPVerifiedAt    *time.Time `bson:"totp_verified_at,omitempty" json:"totp_verified_at,omitempty"`
}
```

### 5c. 2FA setup flow (mandatory for admin, optional for others)
1. After registration/invite-accept: redirect to `/setup-2fa`
2. Generate TOTP secret, store in DB (not yet enabled)
3. Show QR code + manual setup key
4. User scans with authenticator app, enters the 6-digit code
5. Verify code against secret → set `totp_enabled: true`, `totp_verified_at: now()`
6. Issue access + refresh tokens

### 5d. 2FA enforcement
- **Admin**: 2FA is mandatory. Login returns `{"require_2fa": true}` if not yet set up. Must complete setup before accessing any protected route.
- **Analyst/Viewer**: 2FA is optional. If enabled, required for login.

### 5e. 2FA endpoints
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/auth/2fa/status` | Returns whether 2FA is required/setup for current user |
| `POST` | `/api/v1/auth/2fa/setup` | Generates TOTP secret, returns QR code URI and manual key |
| `POST` | `/api/v1/auth/2fa/verify` | Verifies a TOTP code to complete setup |
| `POST` | `/api/v1/auth/2fa/login` | During login: submits TOTP code to get access token |
| `POST` | `/api/v1/auth/2fa/disable` | Disables 2FA (admin only, requires password re-entry) |

### 5f. Secure intermediate 2FA token
The `2fa_token` (intermediate JWT) must be secured:
- Short expiry: 5 minutes maximum
- Include user_id and purpose claim
- Cannot be used for refresh token rotation
- Invalidate after successful 2FA verification or expiry

```go
// 2FA token claims
type TwoFactorClaims struct {
    UserID    string `json:"sub"`
    Purpose   string `json:"purpose"` // "2fa_login"
    Type      string `json:"type"`    // "intermediate"
    jwt.RegisteredClaims
}
```

### 5g. Login flow with 2FA
1. `POST /login` with email + password
2. If `totp_enabled == false` and role is not admin → issue tokens directly
3. If `totp_enabled == true` or role is admin → 
   - Generate 2FA token with 5-min expiry
   - Return `{"require_2fa": true, "2fa_token": "intermediate-jwt"}`
4. Client prompts for 6-digit code
5. `POST /api/v1/auth/2fa/login` with `2fa_token` + TOTP code
6. Server validates:
   - 2FA token not expired
   - TOTP code valid
7. Issue full access + refresh tokens
8. Invalidate the 2FA token immediately

### 5h. Recovery codes
Generate 8 recovery codes (one-time use) during 2FA setup. Store **hashed** in DB:
- `POST /api/v1/auth/2fa/recover` — enter a recovery code to bypass 2FA (consumes the code)
- Admin can regenerate recovery codes (invalidates old ones)

---

## 6. Settings Page Updates

### 6a. Invite section
- Remove "Admin" from role dropdown → only "Analyst" and "Viewer"
- After successful invite, modal shows: "Invitation sent to invitee@gmail.com. They have 24 hours to accept."

### 6b. Email configuration section (new)
- SMTP host, port, username, password, from name fields
- "Test Email" button sends a test to the admin's own address
- Only visible/adjustable by admin

### 6c. 2FA section (new)
- Show 2FA status (Enabled/Disabled)
- "Set Up 2FA" button → shows QR code + setup key in modal
- "Disable 2FA" button (admin only, with password confirmation)
- "Regenerate Recovery Codes" button

### 6d. Password reset section (new)
- "Forgot Password?" link on login page
- "Request Password Reset" form

---

## 7. Implementation Order

| Phase | Task | Files |
|-------|------|-------|
| 1 | Add TOTP fields to User model | `models/user.go` |
| 2 | Add TOTP utility package (generate, verify, QR) | `auth/totp.go` |
| 3 | Add invitations collection + model | `models/invitation.go` |
| 4 | Add password_resets collection + model | `models/password_reset.go` |
| 5 | Add password validation utilities | `auth/password.go` |
| 6 | SMTP config struct + email package | `email/smtp.go` |
| 7 | First-admin registration endpoint | `api/handler.go` |
| 8 | Updated invite endpoint (token + email + rate limit) | `api/handler.go` |
| 9 | Accept-invite endpoint + page | `api/handler.go`, `dashboard/accept-invite.html` |
| 10 | Password reset endpoints | `api/handler.go`, `dashboard/reset-password.html` |
| 11 | 2FA setup/verify/login endpoints | `api/handler.go` |
| 12 | Remove admin from invite dropdown | `dashboard/settings.html` |
| 13 | SMTP settings endpoint | `api/handler.go` |
| 14 | 2FA settings/setup UI | `dashboard/settings.html`, `dashboard/js/settings.js` |
| 15 | Email config settings UI | `dashboard/settings.html`, `dashboard/js/settings.js` |
| 16 | `/setup` onboarding page | `dashboard/setup.html`, `dashboard/css/setup.css` |
| 17 | Accept-invite frontend page | `dashboard/accept-invite.html`, `dashboard/js/accept-invite.js` |
| 18 | Forgot password page | `dashboard/forgot-password.html`, `dashboard/js/forgot-password.js` |

---

# Task 1 — Layer 2 ML-Based Blocking

## Architecture Overview

```
Request → WAF (misses) → Backend
                            │
                       access.log
                            │
                    Log Collector
                      ├── regex match hit
                      ├── rate_score (per-IP freq + burst)
                      ├── rep_score (internal + external feeds)
                      └── POST /eval-miss ──► Inference Engine
                                                 │
                            ◄── { ml, rate, rep, composite, decision }
                            │
                    if composite >= 50%:
                      → upsert alert to dashboard (already done)
                    if composite >= 85%:
                      → add IP to in-memory blocklist
                      → write to blocked_ips.txt in proxy-waf/overrides/
                      → Coraza @ipMatchFromFile blocks subsequent requests
```

---

## Phase 1 — Rate Tracking (Log Collector)

**Goal:** Per-IP request frequency + burst detection from Caddy access logs.

**Files:** `services/log-collector/main.go`

**Changes:**

1. New in-memory struct in log-collector:
   - `IPRateTracker` — sliding window counters per IP: request timestamps (60s window)
   - `frequency_score` = (requests_in_window / max_expected) capped at 1.0
   - `burst_score` = detect if current rate exceeds rolling avg by 3σ → 0.0–1.0
   - `rate_score` = 0.6 × frequency + 0.4 × burst

2. Wire into miss-detection pipeline (Caddy access log parsing):
   - After regex match, look up `rate_score` for the source IP
   - Include `rate_score` in the payload sent to inference engine

**Rate scoring formula:**
```
frequency_score = min(requests_in_60s / 120, 1.0)   // 120 req/min = 1.0
burst_score     = sigmoid((current_rate - baseline) / baseline - 2)  // 3σ above baseline → ~0.9
rate_score      = 0.6 × frequency_score + 0.4 × burst_score
```

---

## Phase 2 — Reputation Scoring (Log Collector)

**Goal:** Score IPs based on internal alert history + external threat feeds.

**Files:** `services/log-collector/main.go`, `services/log-collector/db/mongo.go`

### 2a — Internal Reputation (MongoDB)

- Query `alerts` collection for IPs with `human_label: "true_positive"`
- `internal_score` = (tp_count_30d / total_requests_30d_from_ip) capped at 1.0
- Cache in-memory, refresh every 60s

### 2b — External Threat Feeds

- Three sources layered:
  - **AlienVault OTX** — poll `https://otx.alienvault.com/api/v1/indicators/ip/{ip}/general`
  - **abuse.ch SSLBL** — download `https://sslbl.abuse.ch/blacklist/sslipblacklist.txt`
  - **abuse.ch URLhaus** — download `https://urlhaus.abuse.ch/downloads/hostfile/`
- Poll bulk feeds every 5 min, cache in-memory
- `external_score` = 1.0 if in any feed, else 0.0

### 2c — Combined Reputation

```
rep_score = 0.7 × internal_score + 0.3 × external_score
```

- Include `rep_score` in payload sent to inference engine alongside `rate_score`

---

## Phase 3 — Composite Scoring Endpoint (Inference Engine)

**Goal:** New endpoint `/eval-miss` that computes the full composite and returns a decision.

**Files:** `services/inference-engine/main.py`

### Request Schema (POST /eval-miss)

```json
{
  "features": { ... },
  "rate_score": 0.45,
  "rep_score": 0.70
}
```

### Processing

1. Run existing ML prediction (same as `/predict-miss`) → `ml_score` (0–1)
2. Compute composite:

```
composite = (ml_score × 0.6) + (rate_score × 0.2) + (rep_score × 0.2)
```

3. Decision:

| Composite Range | Decision | Action |
|-----------------|----------|--------|
| < 0.50 | `allow` | No alert (below threshold, skip) |
| 0.50 – 0.84 | `monitor` | Alert logged to dashboard (existing behavior) |
| ≥ 0.85 | `block` | Alert logged + IP added to blocklist |

### Response Schema

```json
{
  "ml_score": 0.72,
  "rate_score": 0.45,
  "rep_score": 0.70,
  "composite": 0.662,
  "decision": "monitor",
  "breakdown": {
    "ml_contribution": 0.432,
    "rate_contribution": 0.090,
    "rep_contribution": 0.140
  }
}
```

---

## Phase 4 — Blocklist Management (Log Collector)

**Goal:** When composite ≥ 0.85, add IP to blocklist so Coraza blocks future requests.

**Files:** `services/log-collector/main.go`, `services/log-collector/api/handler.go`

### 4a — In-Memory Blocklist

- `sync.Map[ip → expiry_timestamp]` in log-collector
- Default TTL: 30 minutes (configurable, `BLOCKLIST_TTL` env var)
- Fast lookup via `IsBlocked(ip) bool` method

### 4b — File Sync

- Write blocked IPs to `proxy-waf/overrides/blocked_ips.txt` (one IP per line)
- Sync interval: every 10s (or immediately on new block event, whichever comes first)
- Remove expired IPs from both memory + file on each sync

**File format (blocked_ips.txt):**
```
10.0.0.1
10.0.0.2
```

### 4c — Docker Volume

- Add `./proxy-waf/overrides:/waf-overrides` mount to log-collector in docker-compose.yml
- Log-collector writes to `/waf-overrides/blocked_ips.txt`

### 4d — Admin API

```
GET /api/blocklist → list of currently blocked IPs + remaining TTL
DELETE /api/blocklist/{ip} → manually unblock an IP
```

---

## Phase 5 — WAF Enforcement (Coraza)

**Goal:** Coraza reads the blocklist file and denies matching IPs.

**Files:** `proxy-waf/custom_rules.conf`

### Rule Addition

At the end of `custom_rules.conf` (or as a new file in overrides):

```
# Block known malicious IPs (populated by log-collector)
SecRule REMOTE_ADDR "@ipMatchFromFile /etc/coraza/overrides/blocked_ips.txt" \
    "id:1000000,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Request from blocked malicious IP'"
```

This requires knowing the container-side path of the overrides mount. The current mount maps `./proxy-waf/overrides` into the WAF container — verify the container path (likely `/etc/coraza/overrides/` or `/project/proxy-waf/overrides/`).

---

## Phase 6 — Dashboard Visibility

**Goal:** Surface blocklist state on the dashboard.

**Files:** `dashboard/reports.html`, `dashboard/js/reports.js` (or a new blocklist page)

### Blocklist Status Card

- Count of currently blocked IPs
- "Recently Blocked" mini-table (timestamp, IP, score breakdown)
- Manual unblock button (DELETE to log-collector API)

### Alert Tagging

- Miss-detection alerts caused by composite ≥ 0.5 get an extra tag column: `ML BLOCKED` / `ML MONITORED`
- Add `ml_action: "block"|"monitor"` to alert document

---

## Phase 7 — Configuration & Environment

| Env Var | Default | Purpose |
|---------|---------|---------|
| `BLOCKLIST_TTL` | `30m` | How long an IP stays blocked |
| `BLOCKLIST_SYNC_INTERVAL` | `10s` | How often to sync to file |
| `MONITOR_THRESHOLD` | `0.50` | Composite threshold for logging |
| `BLOCK_THRESHOLD` | `0.85` | Composite threshold for blocking |
| `RATE_WINDOW_SECONDS` | `60` | Rate tracking sliding window |
| `REP_CACHE_TTL` | `60s` | Internal reputation cache refresh |
| `ALIENVAULT_API_KEY` | — | OTX API key (optional) |

---

## Implementation Order

| Step | What | Depends On |
|------|------|------------|
| 1 | Rate tracker in log-collector | — |
| 2 | Internal reputation (MongoDB queries in log-collector) | Step 1 |
| 3 | External feed polling in log-collector | Step 2 |
| 4 | `/eval-miss` endpoint in inference engine | — |
| 5 | Wire log-collector to call `/eval-miss` with rate + rep | Steps 3, 4 |
| 6 | In-memory blocklist + file sync in log-collector | Step 5 |
| 7 | Coraza `@ipMatchFromFile` rule + volume mount | Step 6 |
| 8 | Dashboard blocklist visibility | Step 6 |
| 9 | Env vars, config cleanup, documentation | All |

---

## Open Questions for Design Review

1. **Container path** for the overrides mount: what does Coraza see internally? (Run `docker inspect proxy-waf` to confirm `/etc/coraza/overrides/` vs something else)
2. **AlienVault OTX API key** — needs to be sourced and added to `.env`
3. **retroactive blocking** — should the log-collector blocklist IPs retroactively from past TP alerts (batch), or only from real-time miss-detections?

---

# Task 2 — Miss Model Training Pipeline (Layer 2)

> Train the model that powers `/predict-miss` — the ONNX model that detects
> attacks Coraza misses. No Coraza features, no anomaly scores. Pure raw HTTP
> request data (method, URI, headers, body) → 135 features → predict.

---

## Current Problems

| Problem | Impact |
|---------|--------|
| Current miss model (`modintel.onnx`) is pre-trained on static external data | Doesn't learn from YOUR traffic patterns |
| Reviewed alerts are mostly attacks → dataset is heavily imbalanced | Model biases toward attack, high FP on benign |
| No benign traffic sampling from the actual backend | Model doesn't learn real normal patterns |
| 4 fixed model configs, no tuning | Suboptimal performance per dataset |
| Single train/val/test split (no CV) | Metrics can be noisy/lucky split |
| No augmentation for rare attack families | Minority attack types get poor recall |

---

## Key Constraint — No Coraza Dependence

The miss model must work **independently** of Coraza:

| Do NOT use | Use Instead |
|------------|-------------|
| `anomaly_score` | Raw URI, method, headers |
| `triggered_rules[]` | Raw body bytes |
| Coraza audit log format | Caddy access log (raw HTTP) |
| WAFFeatureExtractor (22+ features) | MissONNXInference (135 raw HTTP features) |

Training data stores raw HTTP fields from the Caddy access log — same format
the log-collector already parses in its miss-detection pipeline.

---

## Dataset Schema — Stripped & Clean

No Coraza fields, no AI enrichment fields, no metadata noise. Just raw HTTP
request data + a binary label.

### Fields Kept (raw HTTP only)

| Field | Type | Source |
|-------|------|--------|
| `method` | string | Caddy log |
| `uri` | string | Caddy log |
| `body` | string | Caddy log (base64 or truncated) |
| `headers` | map[string]string | Caddy log |
| `body_length` | int | computed |
| `header_count` | int | computed |
| `query_params` | map[string]string | parsed from URI |
| `content_type` | string | from headers |
| `client_ip` | string | Caddy log |
| `timestamp` | string | Caddy log |
| `label` | string | `"attack"` or `"benign"` |

### Fields Stripped (not in training dataset)

| Field | Reason |
|-------|--------|
| `triggered_rules` | Coraza-specific, useless for miss model |
| `anomaly_score` | Coraza-specific |
| `rule_details` | Coraza-specific |
| `raw_log` | Coraza-specific, bloated |
| `http_status` | Response status, not request feature |
| `ai_score`, `ai_confidence`, etc. | Inference output, not input feature |
| `ai_priority`, `ai_explanation` | Inference output |
| `human_label` | Mapped to `label` instead |
| `reviewed_by`, `reviewed_at` | Operational metadata |
| `source`, `status` | Internal pipeline tracking |
| `request_fingerprint` | Internal dedup |
| `matched_signatures` | Rule artifact, not a feature |

### Label Mapping

| Source Data | Mapped To | Condition |
|-------------|-----------|-----------|
| Reviewed TP miss-detection | `label: "attack"` | `source = "ml_miss_detector"` AND `human_label = "true_positive"` |
| Reviewed FP miss-detection | `label: "benign"` | `source = "ml_miss_detector"` AND `human_label = "false_positive"` |
| Live benign recording | `label: "benign"` | No sig match, no Coraza flag |

Both FP misses AND recorded live traffic become `"benign"` — they represent
normal traffic the model should not flag.

---

## Architecture — Dataset Lifecycle

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        DATASET STATE MACHINE                              │
│                                                                           │
│  User reviews miss-detection alerts → exports all labeled TP ✅ + FP ❌   │
│         │                                                                 │
│         ▼                                                                 │
│  ┌──────────────────────┐                                                 │
│  │  ATTACK + BENIGN     │                                                 │
│  │  FROM REVIEW         │   TP misses → label "attack"                    │
│  │                      │   FP misses → label "benign"                    │
│  └──┬────────┬──────────┘                                                 │
│     │        │                                                            │
│     ▼        ▼                                                            │
│  attack     benign                                                        │
│  count      count_from_review                                             │
│     │        │                                                            │
│     └───┬────┘                                                            │
│         ▼                                                                 │
│  remaining_benign_needed = attacks × (0.4/0.6) - benign_from_review       │
│         │                                                                 │
│         ▼ (if remaining_benign_needed > 0)                               │
│  ┌────────────────┐   Log-collector starts passive recording:            │
│  │  RECORDING     │   ✓ No signature match                               │
│  │  BENIGN        │   ✓ No Coraza flag                                  │
│  └──────┬─────────┘   ✓ Raw HTTP from WAF access log                    │
│         │                                                                 │
│         ▼ (when buffer >= remaining_needed)                              │
│  ┌────────────────┐                                                       │
│  │  READY TO      │   Dataset = attacks ⚔️ + all benign 🙝               │
│  │  TRAIN         │   ↓ raw HTTP fields + label → Parquet                │
│  └────────────────┘   Training UI enables "Start Training" button       │
└───────────────────────────────────────────────────────────────────────────┘

Training produces:
  ├── modintel.onnx         → new ONNX model for /predict-miss
  ├── modintel.pt           → PyTorch checkpoint
  └── feature_extractor.joblib → fitted MissONNX feature extractor
```

---

## Phase 1 — Benign Traffic Recording

**Goal:** Passively record normal traffic from live WAF logs when the system
needs benign samples to balance a pending dataset.

**Files:** `services/log-collector/main.go`, `services/training-api/main.py`,
`ml-pipeline/dataset_builder.py`

### Logic

The log-collector already tails the Caddy access log. It's already applying
regex signatures and checking Coraza flags. The ask is:

**For every request that passes both checks** (no signature match, no Coraza
flag), tag it as a benign candidate. If a benign recording job is active,
persist it.

### Decision Tree

```
For each Caddy access log line:
  ├── regex signature matched?          → YES → skip (potential attack)
  ├── Coraza anomaly score > 0?        → YES → skip (WAF had doubts)
  ├── URI in exclude list?              → YES → skip (/admin, /api/system/*)
  ├── HTTP status != 200?               → YES → skip (error, not "normal")
  │
  └── ALL CLEAR → benign candidate
        ├── Is there an active benign recording job?
        │     YES → append to job buffer
        │     NO  → discard (no one needs it yet)
        └── Check: has buffer hit the target count?
              YES → mark recording job complete, dataset is ready
```

### Recording Job State

Managed in MongoDB `datasets` collection — a dataset document gets lifecycle
fields:

```json
{
  "name": "waf_dataset_v4",
  "status": "recording_benign",
  "type": "training",
  "attack_samples": 9000,
  "benign_needed": 6000,
  "benign_collected": 3400,
  "attack_exported_at": "2026-05-06T10:00:00Z",
  "benign_collection_started_at": "2026-05-06T10:00:05Z",
  "benign_sources": ["waf_access_log"]
}
```

States: `attacks_exported` → `recording_benign` → `ready` → `training` → `done`

### Trigger — User Exports Reviewed Attacks

When the analyst clicks "Cut Dataset" on the review page, the system
**strips and maps** as it exports:

```
1. Query MongoDB for:
   ├── source = "ml_miss_detector" (only miss-detection alerts)
   └── human_label exists (reviewed at least once)

2. For each alert:
   ├── strip: triggered_rules, anomaly_score, rule_details, raw_log
   ├── strip: ai_score, ai_confidence, ai_priority, ai_explanation, etc.
   ├── strip: reviewed_by, reviewed_at, status, source, request_fingerprint
   └── map label:
         human_label = "true_positive"  →  label = "attack"
         human_label = "false_positive" →  label = "benign"

3. Save to data/processed/attack_samples_v{N}.jsonl (raw HTTP fields + label only)

4. Count:
   ├── attack_count = samples with label="attack"
   └── benign_from_review = samples with label="benign"

5. Calculate remaining benign_needed:
   └── max(0, attack_count × (0.4/0.6) - benign_from_review)

6. If remaining_benign_needed > 0:
   ├── create dataset record with status "recording_benign"
   ├── target = remaining_benign_needed
   └── log-collector starts passive recording (Phase 1)

7. If remaining_benign_needed <= 0:
   ├── mark status "ready" immediately
   └── dataset is balanced from review labels alone
```

MongoDB alerts are **never modified** by this process — they keep all Coraza
and AI fields for operational traceability. The clean copy lives in the
exported JSONL / Parquet.

### What Benign Recording Stores

Store raw HTTP data — same format the miss model consumes (no Coraza fields):

| Field | Source |
|-------|--------|
| `method` | Caddy log |
| `uri` | Caddy log |
| `body` | Caddy log (base64 or truncated) |
| `headers` | Caddy log |
| `body_length` | computed |
| `header_count` | computed |
| `query_params` | parsed from URI |
| `content_type` | from headers |
| `client_ip` | Caddy log |
| `timestamp` | Caddy log |
| `label` | `"benign"` |

### Storage

Benign samples are stored in-memory in the log-collector initially (ring
buffer, max ~10k), then flushed to a JSONL file in
`data/processed/benign_buffer.jsonl` periodically. The dataset builder picks
them up from there.

### Dashboard Feedback

While `recording_benign`:
- Datasets page shows a progress bar: `3,400 / 6,000 benign samples collected`
- Estimated time remaining based on current traffic rate

---

## Phase 2 — Attack Family Balancing

**Goal:** Ensure minority attack types aren't drowned out by majority ones.

**Files:** `ml-pipeline/dataset_builder.py`

### Per-Family Sampling

```
For each attack family:
  family_count = count of reviewed TP alerts for this family
  target_per_family = max(min_floor, total_attacks / num_families)

  If family_count >= target:
    → Random subsample to target (preserve variety)
  If family_count < target AND > 0:
    → Keep all, apply augmentation (Phase 3)
  If family_count == 0:
    → Fall back to static attack dataset for this family
```

### Default Configuration

| Parameter | Value | Why |
|-----------|-------|-----|
| `attack_ratio` | 0.60 | 60% attacks, 40% benign |
| `min_samples_per_family` | 50 | Ensures each family has enough for training |
| `max_samples_per_family` | 3000 | Prevents SQLi/XSS from drowning out others |
| `augment_until` | 50 | Augment families with <50 samples up to 50 |

---

## Phase 3 — Attack Augmentation

**Goal:** Increase variety for families with few real samples.

**Files:** `ml-pipeline/dataset_builder.py` — new augmentation module

### Lightweight Mutations (no GANs, no LLMs)

For each attack payload, randomly apply 1–3 of these:

| Mutation | Applies To | Effect |
|----------|-----------|--------|
| Case shuffle | SQLi, XSS | `SELECT` ↔ `select` ↔ `Select` |
| Whitespace insertion | All | `union select` ↔ `union%0a%09select` |
| URL-encode some chars | All | `'` ↔ `%27`, `<` ↔ `%3C` |
| Comment injection | SQLi | `SELECT` ↔ `SE/**/LECT` |
| Add benign prefix/suffix | All | `/?q=<script>` ↔ `/?search=hello&q=<script>` |
| Double encoding | LFI, Path | `../` ↔ `%252e%252e%252f` |

Each mutated sample is treated as a separate training example. The original is always kept.

### Guardrails

- Max 5 mutated copies per original payload (avoid overfitting on synthetic data)
- Track `augmented: true` in dataset metadata
- Never augment benign samples (only attacks)

---

## Phase 4 — Bayesian Hyperparameter Tuning

**Goal:** Replace 4 fixed model configs with Optuna-driven search.

**Files:** `ml-pipeline/train_model.py` — major rewrite of model training section

### Optuna Integration

```
study = optuna.create_study(
    direction="maximize",
    sampler=optuna.samplers.TPESampler(),   // Tree-structured Parzen Estimator
    pruner=optuna.pruners.MedianPruner()    // Early-stop bad trials
)
study.optimize(objective, n_trials=10)
```

The `objective` function for each trial:
1. Sample hyperparameters from the search space
2. Train model on 4 of 5 stratified folds
3. Evaluate on held-out fold
4. Return composite score: `F1×0.4 + (1-ECE)×0.3 + AUROC×0.2 + (1-FPR)×0.1`
5. After all trials: train best config on full training set, evaluate on test set

### Search Spaces

**XGBoost (10 trials):**

| Param | Range | Scale |
|-------|-------|-------|
| `n_estimators` | 100–500 | linear |
| `max_depth` | 3–12 | linear |
| `learning_rate` | 0.01–0.3 | log |
| `subsample` | 0.6–1.0 | linear |
| `colsample_bytree` | 0.6–1.0 | linear |
| `min_child_weight` | 1–10 | linear |
| `reg_alpha` | 1e-8–10 | log |
| `reg_lambda` | 1e-8–10 | log |
| `scale_pos_weight` | 1–10 (or computed) | linear |

**LightGBM (10 trials):**

| Param | Range | Scale |
|-------|-------|-------|
| `n_estimators` | 100–500 | linear |
| `max_depth` | 3–15 | linear |
| `learning_rate` | 0.01–0.3 | log |
| `num_leaves` | 15–127 | linear |
| `subsample` | 0.6–1.0 | linear |
| `colsample_bytree` | 0.6–1.0 | linear |
| `min_child_samples` | 5–50 | linear |
| `reg_alpha` | 1e-8–10 | log |
| `reg_lambda` | 1e-8–10 | log |
| `class_weight` | "balanced" or None | choice |

**Random Forest (10 trials):**

| Param | Range | Scale |
|-------|-------|-------|
| `n_estimators` | 100–500 | linear |
| `max_depth` | 5–30 (or None) | linear |
| `min_samples_split` | 2–20 | linear |
| `min_samples_leaf` | 1–10 | linear |
| `max_features` | "sqrt", "log2", 0.3–0.8 | choice + linear |
| `class_weight` | "balanced", "balanced_subsample", None | choice |

**Logistic Regression (10 trials):**

| Param | Range | Scale |
|-------|-------|-------|
| `C` | 1e-4–100 | log |
| `penalty` | "l1", "l2", "elasticnet" | choice |
| `solver` | "saga" | fixed |
| `l1_ratio` | 0–1 (only if elasticnet) | linear |
| `class_weight` | "balanced" or None | choice |

### Cross-Validation Strategy

- **5-fold stratified** (maintains attack/benign ratio per fold)
- Each fold: train on 4/5, validate on 1/5
- Final evaluation: train on all 5 folds combined, test on held-out 20% test split
- Metrics reported as: `mean ± std` across folds

---

## Phase 5 — Calibration & Model Selection

**Files:** `ml-pipeline/train_model.py`

### Calibration Flow (per optimized model)

```
For each model returned by Optuna:
  ├── Platt (sigmoid) calibration on validation set → ECE_sigmoid
  └── Isotonic calibration on validation set → ECE_isotonic
  
  Selected calibrator = argmin(ECE_sigmoid, ECE_isotonic)
  ↳ Both saved as calibrator_*.joblib for later comparison
```

### Model Selection

```
For each model type (XGBoost, LightGBM, RF, LR):
  ├── Get best trial from Optuna
  └── train on full train set → evaluate on test set

Composite scores:
  ├── winner = argmax(composite_score) across all 4 model types
  └── winner saved as models/v{N}/ with all calibrator variants

If winner's composite < previous active model's composite + margin:
  → Warn but still save (manual approval gate)
```

### Minimum Improvement Gate

```
improvement = new_composite - previous_composite
if improvement < 0.01:
  → Training succeeds but model is NOT auto-activated
  → Dashboard shows: "New model v{N} (no significant improvement over v{prev})"
  → Analyst can manually activate if desired
```

---

## Phase 6 — Training API Changes

**Files:** `services/training-api/main.py`

### New Endpoint Parameters

```
POST /api/training/start
{
  "dataset": "waf_dataset_v4",
  "model_type": "auto",          // auto = try all 4 with tuning
  "val_split": 0.2,
  "tuning_trials": 50,           // Optuna trials per model type
  "attack_ratio": 0.6,
  "tuning_trials": 10,
  "balance_strategy": "attack_weighted",
  "min_family_samples": 50
}
```

### Job Status Enrichment

Current: `{job_id, status, progress, model_version}`

New:
```json
{
  "job_id": "abc123",
  "status": "tuning_xgboost",    // granular phase tracking
  "progress": 0.45,              // 0.0–1.0
  "model_version": null,
  "tuning_results": {
    "best_trial": { "params": {...}, "score": 0.992 },
    "trials_completed": 22
  },
  "dataset_summary": {
    "total": 15000,
    "attack_ratio": 0.60,
    "families": {...}
  }
}
```

---

## Phase 7 — Evaluation Report Enhancements

**Files:** `ml-pipeline/evaluate_model.py`

### New Sections in HTML Report

| Section | What It Shows |
|---------|---------------|
| **Tuning History** | Trial → composite score scatter plot, top-10 parameter table |
| **Cross-Validation** | Fold-by-fold metrics table (+ mean ± std) |
| **Per-Family Confusion** | Heatmap of FP/FN per attack family |
| **Calibration Comparison** | Reliability diagram with both Platt + Isotonic curves |
| **Cost Analysis** | Estimated FP/FN cost at different thresholds (simulated) |
| **Data Composition** | Attack/benign split bar chart, family distribution pie |

---

## Implementation Order

| Step | What | Files | Depends On |
|------|------|-------|------------|
| 1 | Benign candidate tagging in log-collector (passive, always-on) | `services/log-collector/main.go` | — |
| 2 | Dataset lifecycle state machine (MongoDB status field + transitions) | `services/training-api/main.py` | — |
| 3 | Benign recording job — log-collector reads active jobs, starts buffering | `services/log-collector/main.go`, `services/training-api/main.py` | Steps 1, 2 |
| 4 | Dataset cut triggers benign calculation + spawns recording job | `services/training-api/main.py` | Step 3 |
| 5 | Dataset builder merges attacks + recorded benign → balanced Parquet | `ml-pipeline/dataset_builder.py` | Step 4 |
| 6 | Attack family grouping + balanced sampling | `ml-pipeline/dataset_builder.py` | Step 5 |
| 7 | Attack augmentation (lightweight mutations) | `ml-pipeline/dataset_builder.py` (new module) | Step 6 |
| 8 | Optuna integration (search spaces + objective) | `ml-pipeline/train_model.py` | Step 7 |
| 9 | Stratified k-fold cross-validation | `ml-pipeline/train_model.py` | Step 8 |
| 10 | Calibration selection (Platt vs Isotonic) | `ml-pipeline/train_model.py` | Step 9 |
| 11 | Model selection with improvement gate | `ml-pipeline/train_model.py` | Step 10 |
| 12 | Training API new params + job status | `services/training-api/main.py` | Step 11 |
| 13 | Evaluation report enhancements | `ml-pipeline/evaluate_model.py` | Step 11 |
| 14 | Dashboard: dataset progress bar + ready-to-train indicator | `dashboard/datasets.html`, `dashboard/js/datasets.js`, `dashboard/training.html`, `dashboard/js/training.js` | Step 4 |
| 15 | End-to-end testing with attack_suite | — | All |

---

## Open Questions

1. **Optuna storage** — in-memory per job (ephemeral) or persistent SQLite? SQLite keeps trial history across restarts for reproducibility.
2. **Cost-sensitive evaluation weights** — what's the assumed cost ratio of FN vs FP? Default: FN costs 10× more than FP in WAF context.
3. **Benign buffer durability** — if log-collector restarts mid-recording, should the buffer survive? Write to JSONL on disk every N samples, reload on startup.
4. **Minimum attack threshold** — how many reviewed TP alerts should trigger the benign recording? 100? 500? (Affects Phase 1 trigger).

---

# Task 3 — Update SDS Document

> Bring `docs/SDS.pdf` in line with the current system. Every section of the
> SDS references the old ModSecurity-centric design and needs updating.

---

## Sections to Update

### Section 1 — Introduction

| Current (SDS) | Needs To Say |
|---------------|--------------|
| "Modular extension to ModSecurity" | ModIntel is a standalone hybrid WAF platform built on Coraza, not ModSecurity |
| "Intercepts CRS audit logs" | Two-layer architecture: Layer 1 (Coraza WAF) + Layer 2 (ML miss-detection) |
| "Decision-support layer" | No longer advisory-only — Layer 2 can actively block via composite scoring |
| 4 subsystems (Parsing, Intelligence, Explainability, Presentation) | 3 layers (Deterministic WAF, ML Detection, Platform Services) |
| "Fail-Safe Stability: failure in Python ML Service does not crash Web Server" | Now 10 Docker containers with health aggregator, SSE monitoring |

### Section 2 — System Design Model

**2.1 Subsystem Decomposition:**

Add new subsystems:
- Miss Detection Subsystem (regex + `/predict-miss` ONNX)
- Composite Scoring Subsystem (`/eval-miss`: `0.6×ml + 0.2×rate + 0.2×rep`)
- Blocklist Management Subsystem (in-memory + `@ipMatchFromFile` + file sync)
- Dataset Lifecycle Management Subsystem (state machine: `attacks_exported` → `recording_benign` → `ready`)
- Benign Traffic Recording Subsystem (passive recording from live Caddy logs)
- Rate Tracking Subsystem (per-IP sliding window freq + burst detection)
- Reputation Scoring Subsystem (internal MongoDB TP history + external feed polling)

Rename/merge:
- "Integration Layer" → now Log Collector (dual-pipeline: Coraza audit + Caddy access)
- "Feature Extraction Module" → split into WAFFeatureExtractor (22 features) + MissONNXInference (135 raw HTTP features)
- "Alert Prioritization and Policy Engine" → now Composite Scorer + Blocklist Manager

**2.2 Hardware/Software Mapping:**

Replace the 3-node deployment diagram with the actual 10-container Docker Compose setup:

| Container | Language | Port |
|-----------|----------|------|
| mongodb | Mongo 7 | 27018:27017 |
| proxy-waf-custom | Caddy | 8080, 3000 |
| proxy-waf | Caddy+Coraza | internal |
| juice-shop | Node.js | internal |
| log-collector | Go | 8081 |
| inference-engine | Python | 8083 |
| review-api | Go | 8082 |
| health-aggregator | Go | 8090 |
| training-api | Python | 8085 |
| auth-service | Go | 8084 |

Also add named volumes: `modintel_mongo_data`, `modintel_waf-logs`, `modintel_caddy_logs`, plus the new blocklist volume for `proxy-waf/overrides/`.

**2.3 Access Control:**

The current roles are close (Security Analyst, System Administrator, Developer). Update to match actual RBAC:
- Re-label: `viewer` (read-only), `analyst` (review + datasets), `admin` (full control)
- Add: analyst can now cut/export datasets and trigger training
- Add: admin can manage blocklist (unblock IPs, view blocked list)
- Add: admin can manage user invites
- Remove "Cannot deploy, retrain, or replace ML models" restriction — analysts CAN now (that's the whole point of the training UI)

### Section 3 — Object Model

**3.1 Class Diagram:**

Add these new classes with their relationships:

| New Class | Parent / Association | Key Difference from Current |
|-----------|---------------------|----------------------------|
| `CaddyLogParser` | → LogCollector | Parses raw HTTP (method, URI, headers, body), not Coraza audit format |
| `MissONNXInference` | → InferenceEngine | 135 raw HTTP features, no Coraza fields |
| `CorazaLogParser` | → LogCollector | Rename from ModSecurityAuditLogParser, now handles Coraza JSON format |
| `CompositeScorer` | → InferenceEngine | New: `evaluate(ml, rate, rep) → decision{allow, monitor, block}` |
| `BlocklistManager` | → LogCollector | `addIP()`, `removeIP()`, `syncToFile()`, `isBlocked()`. In-memory set + `@ipMatchFromFile` sync |
| `RateTracker` | → LogCollector | Sliding window per-IP: `frequency_score + burst_score` |
| `ReputationScorer` | → LogCollector | `internal_score` (MongoDB TP history) + `external_score` (AlienVault + abuse.ch feeds) |
| `DatasetBuilder` | → TrainingAPI | State machine: `attacks_exported → recording_benign → ready → training → done` |
| `BenignRecorder` | → LogCollector | Passive recording from live traffic when a dataset job is active |
| `WAFFeatureExtractor` | → InferenceEngine | Rename from `FeatureExtractor`, 22+ features including rule/anomaly groups |

Remove/replace:
- `ModSecurityAuditLogParser` → replaced by `CorazaLogParser` + `CaddyLogParser`
- `AlertPrioritizer` → replaced by `CompositeScorer` (richer scoring, not just priority)
- `ExplanationGenerator` → keep but merge into `InferenceEngine` as part of `/predict` response

Update:
- `MLClassifier.threshold` → now a configurable tri-threshold: `monitor_threshold: 0.50`, `block_threshold: 0.85`
- `ModelTrainer` → add `optimizeHyperparams(searchSpace, nTrials)`, `calibrate(method)`, `augmentAttack()`, `stratifiedKFold()`, attribute `tuningTrials: Integer` (default 10)

**3.2 Sequence Diagrams:**

Add 3 new diagrams:

1. **Miss Detection Flow:**
   ```
   Caddy Access Log → Log Collector
     → regex match (SQLi/XSS/CMDi)
     → POST /predict-miss (MissONNXInference)
     → upsert alert (source: ml_miss_detector)
     → SSE broadcast to dashboard
   ```

2. **Composite Scoring & Blocking Flow:**
   ```
   Miss alert → Log Collector
     → lookup rate_score (RateTracker)
     → lookup rep_score (ReputationScorer)
     → POST /eval-miss (Inference Engine)
     → composite = 0.6×ml + 0.2×rate + 0.2×rep
     → if ≥ 0.85: add IP to BlocklistManager
     → sync to blocked_ips.txt
     → Coraza @ipMatchFromFile blocks next request
   ```

3. **Dataset Building Flow:**
   ```
   Analyst clicks "Cut Dataset"
     → TrainingAPI exports reviewed TP/FP → strips Coraza fields → maps labels
     → calculates benign_needed = attacks × (0.4/0.6) - benign_from_review
     → creates dataset record (status: recording_benign)
     → LogCollector starts BenignRecorder for live traffic
     → when buffer hits target → status flips to ready
     → DatasetBuilder merges → Parquet
     → TrainingUI enables "Start Training"
   ```

Update existing diagrams:
- **ML-Assisted Request Classification**: Change ModSecurity → Coraza WAF, add Layer 2 miss-detection path
- **Offline Model Training**: Change to show Optuna tuning (10 trials), stratified CV, calibration selection, balanced dataset from reviews + recorded benign
- **Model Deployment and Rollback**: Add retraining trigger (cut dataset → record benign → train → activate)

**3.3 State Chart:**

Current: `Generated → Classified → Reviewed → Resolved`

Add two more state machines:
- **Dataset Lifecycle**: `attacks_exported → recording_benign → ready → training → done`
- **Blocked IP Lifecycle**: `monitoring → blocked (30 min TTL) → expired`

### Section 4 — Detailed Design

**4.1 ModSecurityAuditLogParser → split into CorazaLogParser + CaddyLogParser:**

`CorazaLogParser` (replaces ModSecurityAuditLogParser):
- Rename class, update `logSource` to Coraza JSON audit log path
- Operations: `parseCorazaEntry()`, `getTriggeredRules()`, `getAnomalyScore()`, `extractRequestMetadata()`

`CaddyLogParser` (new):
- `logSource: String` (path to `waf-access.json`)
- Operations: `parseCaddyEntry()`, `extractRawHTTP()` → returns method, URI, body, headers only

**4.2 FeatureExtractor → split:**

`WAFFeatureExtractor` (22+ features, for `/predict`):
- `ruleEncoder: Dictionary`, `maxFeatures: Integer`
- Operations: `extract()`, `encodeRules()`, `normalizeScore()`

`MissONNXInference` (new, for `/predict-miss`):
- `onnxModel: ONNXModel`, `featureCount: 135`
- Operations: `loadONNX(path)`, `predictRawHTTP(method, uri, headers, body) → attackProbability`

**4.3 MLClassifier → update:**

Add threshold tri-state: `monitorThreshold: 0.50`, `blockThreshold: 0.85`
Operation `classify()` → now returns `{ label, confidence, decision: allow|monitor|block }`

**4.4 AlertPrioritizer → replace with CompositeScorer (new):**

| Attribute | Type | Description |
|-----------|------|-------------|
| `mlWeight` | Float | Weight for ML score (0.6) |
| `rateWeight` | Float | Weight for rate score (0.2) |
| `repWeight` | Float | Weight for reputation score (0.2) |
| `monitorThreshold` | Float | Composite ≥ this → log (0.50) |
| `blockThreshold` | Float | Composite ≥ this → block (0.85) |

| Operation | Return | Description |
|-----------|--------|-------------|
| `evaluate(ml, rate, rep)` | `{composite, decision, breakdown}` | Compute composite, return decision with per-component breakdown |
| `computeBreakdown(ml, rate, rep)` | Dictionary | Return component contributions for dashboard display |

**4.5 ModelTrainer → update:**

Update:
- Add `tuningTrials: Integer` (default 10)
- Add `searchSpaces: Dictionary` (per-model hyperparameter ranges)
- Update `trainAndEvaluate()` to use Optuna + stratified k-fold CV
- Add `optimizeHyperparams()` — runs Bayesian search with TPE sampler
- Add `calibrate(method)` — tries Platt + Isotonic, picks best ECE
- Add `augmentAttack(payload)` — lightweight mutations on minority attack families
- Add `buildBalancedDataset(attacks, benign)` — 60/40 split with family balancing
- Update `computeMetrics()` → add per-family metrics, cost analysis

**4.6 DashboardController → update:**

Add:
- `blocklistView: List` — current blocked IPs
- `datasetProgress: Float` — 0.0–1.0 for benign recording progress
- `renderBlocklist()` — display blocked IPs with TTL
- `renderDatasetProgress()` — progress bar for benign recording
- `unblockIP(ip)` — remove IP from blocklist

### New Sections to Add

Add detailed design tables for these new classes (not currently in the SDS):

| New Class | Attributes | Operations |
|-----------|------------|------------|
| `RateTracker` | `windowSize: 60s`, `ipCounters: Map<IP, SlidingWindow>` | `recordRequest(ip)`, `getFrequency(ip) → 0-1`, `getBurst(ip) → 0-1`, `getRateScore(ip) → 0-1` |
| `ReputationScorer` | `internalCache: Map<IP, score>`, `externalFeeds: [AlienVault, abuse.ch]` | `queryInternal(ip) → score`, `pollFeeds()`, `getScore(ip) → 0-1` |
| `BlocklistManager` | `blockedIPs: Map<IP, expiry>`, `syncInterval: 10s` | `addIP(ip, ttl)`, `removeIP(ip)`, `isBlocked(ip) → bool`, `syncToFile()`, `listBlocked() → [IP+TTL]` |
| `DatasetBuilder` | `dataset: MongoDB record`, `benignBuffer: JSONL file` | `exportReviewed(only_misses) → str`, `calculateBenignNeeded() → int`, `buildParquet()`, `getState() → enum` |
| `BenignRecorder` | `activeJob: Dataset | null`, `buffer: RingBuffer<HTTPRecord>` | `startJob(dataset)`, `recordCandidate(request)`, `bufferSize()`, `flushToDisk()` |

### Data Flows (new section needed in SDS)

The SDS currently has no data flow section. Add the following flows (matching status.md Section 8):

1. Attack Detection Pipeline (Layer 1 + Layer 2)
2. Composite Scoring & Blocking Flow (new)
3. Benign Recording Flow (new)
4. Dataset Building Lifecycle Flow (new)
5. AI Enrichment Pipeline (existing but needs updating)
6. Analyst Review Flow (existing, minor updates for dataset cut trigger)

### References

Add:
- Optuna documentation (hyperparameter optimization framework)
- Coraza WAF documentation (replaces ModSecurity Handbook reference)
- ONNX Runtime documentation (miss model inference)
- Caddy Server documentation (reverse proxy config)

---

## Summary of All Changes

| SDS Section | Type of Change |
|-------------|---------------|
| 1. Introduction | Rewrite — new architecture, 3 layers, active blocking |
| 2.1 Subsystem Decomposition | Major overhaul — 10 new/renamed subsystems |
| 2.2 Hardware/Software Mapping | Rewrite — 10 Docker containers |
| 2.3 Access Control | Update — reflect actual RBAC (+dataset/training perms) |
| 3.1 Class Diagram | Overhaul — 8 new classes, 3 removed, 3 renamed |
| 3.2 Sequence Diagrams | Add 3 new, update 3 existing |
| 3.3 State Chart | Add 2 new state machines (dataset, blocklist) |
| 4.1 ModSecurityAuditLogParser → split | Rename + split |
| 4.2 FeatureExtractor → split | Rename + split |
| 4.3 MLClassifier | Update — tri-threshold, composite decision |
| 4.4 AlertPrioritizer → CompositeScorer | Replace entirely |
| 4.5 ExplanationGenerator | Merge into InferenceEngine |
| 4.6 ModelTrainer | Major update — Optuna, CV, calibration, augmentation, balancing |
| 4.7 DashboardController | Update — blocklist view, dataset progress |
| New: RateTracker | Add detailed design table |
| New: ReputationScorer | Add detailed design table |
| New: BlocklistManager | Add detailed design table |
| New: DatasetBuilder | Add detailed design table |
| New: BenignRecorder | Add detailed design table |
| New: Data Flows section | Add 6 data flow diagrams |
| References | Update — add Optuna, Coraza, ONNX, Caddy |

---

# Task 4 — Comprehensive System Testing

> Unit, integration, e2e, and acceptance tests across the full stack. Metrics
> for Layer 1 (Coraza WAF) vs Layer 2 (ML miss model) vs combined, benchmarked
> against a Coraza-only baseline.

---

## Testing Pyramid

| Level | What | Who Runs | Frequency |
|-------|------|----------|-----------|
| **Unit** | Individual functions, classes, methods | CI | On push |
| **Model** | ML metrics: accuracy, precision, recall, F1, AUROC, ECE, FPR, FNR | CI + nightly | Per training run + nightly |
| **Integration** | Service interactions: log-collector → inference-engine → MongoDB → SSE | CI | Per PR |
| **E2E** | Full pipeline: attack → WAF → log → ML → dashboard → review | Scheduled | Nightly |
| **Acceptance** | Requirements verification against SRS | Manual | Per release |
| **Benchmark** | Layer 1 vs Layer 2 vs Coraza-only — head-to-head | Manual | Per model deploy |

---

## Phase 1 — Unit Tests

### 1a — Log Collector (Go)

| Package | Priority | What to Test |
|---------|----------|-------------|
| `parsers/coraza.go` | High | Parse Coraza JSON audit log: extract URI, method, IP, triggered rules, anomaly score, HTTP status. Edge cases: malformed JSON, missing fields, empty body, long body truncation |
| `parsers/caddy.go` | High | Parse Caddy access log: extract method, URI, status, body, headers. Edge cases: missing body, no captured_body, query-only GET, multipart forms |
| `signatures/prefilter.go` | High | Regex matching against known SQLi/XSS/CMDi payloads (each of the ~720 signature patterns). False-positive check on benign payloads. Performance: time per evaluation |
| `main.go` | Medium | `uniqueAlertKey()` determinism, `uniqueMissKey()` determinism, `isAlreadyEnriched()` logic, `isInternalIP()` accuracy (Docker 172.x, localhost) |
| `api/handler.go` | Medium | `/health`, `/api/logs`, `/api/stats`, `/api/waf_traffic`. Response format, status codes |

### 1b — Inference Engine (Python)

| Test | Priority | What to Test |
|------|----------|-------------|
| `test_feature_extractor.py` | High | WAFFeatureExtractor: fit + transform on sample alerts, feature count (22+), schema parity validation, missing field handling |
| `test_miss_onnx.py` | High | MissONNXInference: load ONNX model, predict on sample HTTP requests, fallback to heuristic when ONNX fails, feature count = 135 |
| `test_main_predict.py` | High | `/predict`: valid request → response schema, missing fields → 422, malformed → 400 |
| `test_main_predict_miss.py` | High | `/predict-miss`: ONNX path, force fallback → heuristic path, response schema |
| `test_main_batch.py` | Medium | `/predict/batch`: multiple inputs → array output, empty array |
| `test_main_health.py` | Medium | `/health`, `/metrics`, `/model-info`: expected fields, uptime, prediction count |

### 1c — Training API (Python)

| Test | Priority | What to Test |
|------|----------|-------------|
| `test_main_training.py` | High | `/api/training/start` validation, `/api/training/status`, `/api/training/history` format |
| `test_audit_client.py` | Low | HTTP audit event POST to review-api, retry on failure |

### 1d — ML Pipeline (Python)

| Test | Priority | What to Test |
|------|----------|-------------|
| `test_feature_extractor_pipeline.py` | High | WAFFeatureExtractor training-parity with inference-engine version |
| `test_train_model.py` | High | Metrics computation correctness (accuracy, precision, recall, F1, AUROC, ECE, Brier) |
| `test_build_dataset.py` | High | Parquet load/save, column schema, label encoding |

### 1e — Review API (Go)

| Test | Priority | What to Test |
|------|----------|-------------|
| `api/auth_middleware_test.go` | High | Already exists — keep passing |
| `api/pagination_test.go` | Medium | Cursor encoding/decoding, empty results, offset boundary conditions |
| `api/audit_log_test.go` | Medium | Audit event creation, filtering, CSV export format |

### 1f — Auth Service (Go)

Already has: `handler_test.go`, `session_handlers_test.go`, `sessions_test.go`, `jwt_test.go`, `password_test.go`, `auth_rate_limit_test.go`. No new tests needed.

---

## Phase 2 — Model Tests (ML Metrics)

### 2a — Metrics Suite

Run on every training run + nightly. Script: `ml-pipeline/test_models.py`

| Metric | What It Measures | Target (v3 baseline) |
|--------|-----------------|---------------------|
| **Accuracy** | Overall correct predictions | 99.9% |
| **Precision** | TP / (TP + FP) | 99.87% |
| **Recall** | TP / (TP + FN) | 97.94% |
| **F1 Score** | Harmonic mean of precision + recall | 98.90% |
| **AUROC** | Discrimination ability across thresholds | 99.98% |
| **PR-AUC** | Precision-Recall curve area | >0.99 |
| **FPR** | False positive rate | 0.036% |
| **FNR** | False negative rate | 2.06% |
| **ECE** | Expected Calibration Error | 0.00013 |
| **Brier Score** | Mean squared prediction error | 0.0031 |
| **Composite** | `F1×0.4 + (1-ECE)×0.3 + AUROC×0.2 + (1-FPR)×0.1` | 0.9955 |

All metrics reported for Coraza-only, miss model only, and combined.

### 2b — Confusion Matrix

```
                      ┌─────────────┬─────────────┐
                      │ Predicted   │ Predicted   │
                      │ Attack      │ Benign      │
──────────────┬───────┼─────────────┼─────────────┤
Actual Attack │  TP   │   True      │   False     │
              │       │   Positive  │   Negative  │
──────────────┼───────┼─────────────┼─────────────┤
Actual Benign │  FP   │   False     │   True      │
              │       │   Positive  │   Negative  │
──────────────┴───────┴─────────────┴─────────────┘
```

Generate one matrix for each: Coraza-only, miss model only, combined.

### 2c — Calibration

- Reliability diagram (predicted probability vs observed frequency, 10 bins)
- ECE + MCE (Maximum Calibration Error)
- Platt vs Isotonic comparison on held-out validation

### 2d — Threshold Sweep

Sweep block threshold from 0.50 to 0.95 in 0.05 increments:
- For each: precision, recall, F1, FPR, FNR
- Identify threshold that maximizes `F1 - FPR`
- Recommend optimal threshold with FN-cost = 10× FP-cost

---

## Phase 3 — Integration Tests

### 3a — Service Contracts

| From | To | Test |
|------|----|------|
| log-collector | inference-engine | Send Coraza audit event → receive `/predict` response |
| log-collector | inference-engine | Send Caddy miss event → receive `/predict-miss` response |
| log-collector | MongoDB | Upsert alert → verify document with correct fields |
| review-api | MongoDB | Query alerts, rules, datasets, audit logs |
| review-api | Docker socket | Restart WAF → container actually restarts |
| training-api | review-api | Audit event → appears in audit log query |
| training-api | Docker socket | Activate model → inference restarts |
| auth-service | MongoDB | Login → user found, refresh stored, tokens valid |
| auth-service | review-api | JWT from auth → authenticated request succeeds |
| SSE | dashboard | Alert inserted → dashboard receives SSE event |
| health-aggregator | all services | Probe each → correct status returned |

### 3b — Alert Lifecycle

```
1. Send attack → WAF blocks (403) → audit log written
2. Log-collector reads → POST /predict
3. Inference returns AI enrichment → MongoDB upsert
4. Dashboard receives SSE "alert" event
5. Analyst reviews → sets human_label = "true_positive"
6. Verify MongoDB has ai_score, ai_priority, human_label, reviewed_by, reviewed_at
```

### 3c — Miss Detection Lifecycle

```
1. Send attack that bypasses Coraza (obfuscated SQLi)
2. Caddy access log written (status 200)
3. Log-collector reads → regex matches → POST /predict-miss
4. Alert created with source = "ml_miss_detector"
5. Dashboard receives SSE event
6. Analyst reviews → labels TP
```

---

## Phase 4 — End-to-End Tests

### 4a — Attack Simulation Suite

Update `scripts/attack_suite.ps1`:

| Category | Payloads | Expected Layer 1 | Expected Layer 2 |
|----------|----------|-----------------|------------------|
| SQLi | `' OR 1=1--`, `UNION SELECT`, time-based | Block (403) | Alert (if bypasses) |
| SQLi (obfuscated) | Hex-encoded, comment-injected, case-mangled | Might pass | Should detect |
| XSS | `<script>`, `<img onerror=>`, `javascript:` | Block (403) | Alert |
| XSS (DOM) | `onmouseover=`, `document.cookie` | Might pass | Should detect |
| LFI | `../../../etc/passwd`, `....//....//` | Block (403) | Alert |
| CMDi | Backticks, `\|`, `$(cat)` | Block (403) | Alert |
| NoSQLi | `$ne`, `$gt`, `$regex` in JSON body | Might pass | Should detect |
| SSTI | `{{7*7}}`, `${7*7}`, `{{config}}` | Might pass | Should detect |
| SSRF | `http://169.254.169.254/`, `gopher://` | Block (403) | Alert |
| Log4Shell | `${jndi:ldap://}` in headers | Block (403) | Alert |
| CRLF | `%0d%0a` in headers | Block (403) | Alert |
| XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Block (403) | Alert |
| Benign | GET `/`, POST `/login`, GET `/api/products` | Allow (200) | No alert |
| Benign edge | Long URIs, binary bodies, emoji, multipart | Allow (200) | No alert |

### 4b — Measure Per Run

For each attack execution:
- Blocked by Coraza (status = 403)
- Allowed by Coraza but caught by ML (miss alert created)
- Total blocked
- Blind spots (passed both)
- False positives (benign flagged by either)

Run data logged to `data/test/results/{run_id}.json`

### 4c — Baseline: Coraza-Only

Run full attack suite **with ML disabled** (inference stopped, log-collector not enriching):

| Metric | Value |
|--------|-------|
| Attacks detected | Count |
| Attacks missed | Count |
| Detection rate | % |
| Benign FPs | Count |
| FP rate | % |

### 4d — Combined: Coraza + Miss Model

Run full attack suite **with both layers active**:

| Metric | Value |
|--------|-------|
| Attacks detected (Coraza) | Count |
| Attacks detected (ML miss) | Count |
| Total attacks caught | Count |
| Missed by both | Count |
| Total detection rate | % |
| Benign FPs (Coraza) | Count |
| Benign FPs (ML miss) | Count |
| Total FP rate | % |

### 4e — Head-to-Head Comparison

| Metric | Coraza-Only | + Miss Model | Improvement |
|--------|------------|-------------|-------------|
| Detection rate | % | % | +/- % |
| Missed attacks | N | N | +/- N |
| False positives | N | N | +/- N |
| FP rate | % | % | +/- % |
| Precision | % | % | +/- % |
| Recall | % | % | +/- % |
| F1 | % | % | +/- % |

### 4f — Performance Benchmarks

| Test | Metric | Acceptable | Target |
|------|--------|-----------|--------|
| Request latency (Layer 1) | p50 / p95 / p99 | <50ms / <200ms / <500ms | <20ms / <100ms / <300ms |
| Log → alert delay (Layer 2) | p50 / p95 | <5s / <30s | <2s / <10s |
| Inference throughput | Req/sec | >100 | >500 |

---

## Phase 5 — Acceptance Tests

### 5a — Requirements Traceability

Map each SRS requirement to test cases (update as tests are written):

| Req | Description | Test Cases | Status |
|-----|------------|-----------|--------|
| FR-1 | WAF blocks attacks via CRS rules | E2E: each attack → 403 | ❌ |
| FR-2 | ML enriches CRS alerts | Integration: alert → `/predict` → ai_score | ❌ |
| FR-3 | Analyst reviews and labels alerts | E2E: review → TP/FP → MongoDB | ❌ |
| FR-4 | Miss detection catches CRS bypasses | E2E: obfuscated attack → miss alert | ❌ |
| FR-5 | Dashboard receives real-time events | Integration: SSE → browser | ❌ |
| FR-6 | Role-based access control | Unit: admin/analyst/viewer perms | ❌ |
| FR-7 | Audit logging of actions | Integration: action → audit_logs | ❌ |
| FR-8 | System health monitoring | Integration: health-aggregator probes | ❌ |

### 5b — UAT Scenarios

| Scenario | Steps | Expected |
|----------|-------|----------|
| Analyst reviews alert | Login as analyst → /review → label TP | Status changed, SSE fires |
| Viewer tries to review | Login as viewer → /review | Buttons hidden/disabled |
| System survives ML outage | Stop inference-engine | Coraza still blocks, dashboard shows degraded |
| Training completes | Dataset ready → start → wait | Artifacts saved, history updated |

---

## Phase 6 — Documentation

### 6a — Test Report

Generate after each run. Script: `scripts/generate_test_report.ps1`

```
# ModIntel Test Report — {date}

Unit: {pass}/{total} | Integration: {pass}/{total}
E2E: {pass}/{total} | Model composite: {score}
Improvement over Coraza-only: {+X%}

## Combined Performance
Detection rate: {value} (vs {baseline})
FP rate: {value} (vs {baseline})
F1: {value} (vs {baseline})

## Failed Tests
- {test}: {reason}
```

### 6b — Acceptance Sign-Off

| Item | Signed Off | Date |
|------|-----------|------|
| All SRS functional requirements tested | _ | _ |
| Coraza-only baseline established | _ | _ |
| Combined performance documented | _ | _ |
| Regression baseline established | _ | _ |
| Benchmarks met | _ | _ |

### 6c — Test Infrastructure

| Artifact | Location | Purpose |
|----------|----------|---------|
| Test dataset (60/40 balanced) | `data/test/waf_test_dataset.parquet` | Reproducible model eval |
| Attack payload catalog | `data/test/attack_payloads.jsonl` | 500+ labeled samples, all categories |
| Benign request catalog | `data/test/benign_requests.jsonl` | 1000+ real benign requests |
| Coraza-only baseline | `data/test/baseline_coraza_only.json` | Benchmark reference |
| Test reports archive | `data/test/reports/` | Track metrics over time |

---

## Implementation Order

| Step | What | Est. |
|------|------|------|
| 1 | Write missing unit tests: review api endpoints, parsers, inference engine, training API | 2 days |
| 2 | Write pipeline tests: feature extractor parity, metrics computation | 1 day |
| 3 | Build attack payload catalog (500+ samples across all categories) | 1 day |
| 4 | Write integration tests: alert lifecycle, miss detection | 1 day |
| 5 | Run Coraza-only baseline (ML disabled) | 0.5 day |
| 6 | Run combined benchmark (both layers) | 0.5 day |
| 7 | Generate head-to-head comparison | 0.5 day |
| 8 | Write acceptance tests + traceability matrix | 0.5 day |
| 9 | Build test report script + CI integration | 1 day |
| 10 | Documentation: report template, sign-off checklist | 0.5 day |

**Total: ~8.5 days**

---

## Success Criteria

| Criterion | Threshold |
|-----------|-----------|
| Unit test pass rate | 100% |
| Integration test pass rate | 100% |
| E2E test pass rate | 100% |
| Acceptance test pass rate | 100% |
| Model F1 vs v3 baseline | Maintained or improved |
| Combined detection rate vs Coraza-only | ≥ 2% absolute |
| Combined FP rate vs Coraza-only | Not increased |
| p50 inference latency | ≤ 20ms |
| p50 log → alert delay | ≤ 2s |
| All SRS reqs traceable to a test | 100% |

---

*Last updated: 2026-05-06*
