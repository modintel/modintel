# ModIntel Plan

## 1. Pagination

### What
Breaking large dataset responses into smaller chunks using the pagination method best suited for each data type:
- **Cursor-based** for realtime, append-only data (logs, alerts) — stable across inserts/deletes
- **Offset-based** for static or rarely-changing data (rules) — supports random page access

### Why Cursor-Based for Logs/Alerts
- **New entries shift offsets**: If logs arrive between requests, `?page=2` returns different results or skips/duplicates entries
- **Cursor stability**: A cursor (e.g., MongoDB `_id`) points to a fixed position; new inserts don't affect pages already served
- **Performance**: Cursor-based queries use indexed `_id` scans (`_id > cursor`) instead of `Skip()`, which scans and discards rows

### Why Offset-Based for Rules
- Rules rarely change; offset shifting is not a concern
- Users expect to jump to arbitrary page numbers (e.g., "page 3 of 8")
- Offset pagination provides `total` and `total_pages` for standard page navigation UI

### Current State
No pagination exists; endpoints likely return full arrays.

### Implementation Steps

#### 1.1 Define Pagination Utilities
Create `api/pagination.go` in review-api:

```
// Cursor-based (logs, alerts)
filter = bson.D{{"_id", bson.D{{"$gt", cursorID}}}}
collection.Find(ctx, filter).Limit(limit)

// Offset-based (rules)
page_offset = (page - 1) * limit
collection.Find(ctx, filter).Skip(page_offset).Limit(limit)
```

Cursor-based response envelope:
```json
{
  "data": [...],
  "pagination": {
    "next_cursor": "6601a2f3e4b0...",
    "limit": 20,
    "has_next": true
  }
}
```

Offset-based response envelope:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 312,
    "total_pages": 7,
    "has_next": true,
    "has_prev": false
  }
}
```

#### 1.2 Update Endpoints
Paginate these existing endpoints with the appropriate method:
- `GET /api/alerts` → `GET /api/alerts?cursor=<id>&limit=20` (cursor-based)
- `GET /api/logs` → `GET /api/logs?cursor=<id>&limit=50` (cursor-based)
- `GET /api/rules` → `GET /api/rules?page=1&limit=50` (offset-based)

Initial request uses no cursor/offset to get first page:
- `GET /api/alerts?limit=20` → returns first 20 + `next_cursor`
- `GET /api/logs?limit=50` → returns first 50 + `next_cursor`
- `GET /api/rules?page=1&limit=50` → returns first 50

#### 1.3 Frontend Updates
- Logs/Alerts: render "Load more" / "Next" using `next_cursor`; no page numbers
- Rules: render standard page number navigation with "Previous" / "Next" and page indicators
- Store cursor or page in URL query params for shareability
- Pair cursor pagination on the "live" view with SSE or WebSocket for realtime new entries

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/pagination.go` | New file - cursor + offset pagination helpers |
| `services/review-api/api/handler.go` | Add cursor/limit and page/limit params to queries |
| `services/review-api/main.go` | Register pagination middleware |
| `dashboard/js/*.js` | Add pagination UI components (cursor-based + offset-based) |

### Testing
1. Request `/api/alerts?limit=5` → verify 5 items returned with `next_cursor`
2. Request `/api/alerts?cursor=<next_cursor>&limit=5` → verify next 5 items, no duplicates from prior page
3. Insert new alert between requests → verify existing cursor still returns stable results
4. Request `/api/rules?page=1&limit=5` → verify offset-based response with `total` and `total_pages`
5. Request `/api/alerts?limit=1000` → verify capped at reasonable max (e.g., 100)
6. Dashboard pagination controls work correctly for both cursor and offset modes

---

## 2. Async Logging

### What
Use a bounded async logging pipeline with batching, retries, and clear durability tiers. This reduces request-path I/O while preserving security-critical events during failures.

### Why for ModIntel
- **Review-API Access Logs**: Every API request currently writes to MongoDB synchronously
- **Log-Collector**: Already tails Coraza logs; batching writes prevents write amplification
- **Performance Gain**: Lower p95/p99 latency by removing blocking DB writes from request path
- **MongoDB Load**: Batching reduces connection overhead and write operations
- **Reliability Under Failure**: Explicit backpressure and retry behavior prevents silent log loss

### Current State
- Review-api writes to MongoDB on every request synchronously
- Log-collector writes enriched logs immediately after parsing

### Implementation Steps

#### 2.1 Define Durability Tiers (Policy First)
Classify logs before implementation:
- **Tier A (critical security/audit events)**: synchronous write path (or write-ahead durable spool) required
- **Tier B (high-volume operational logs)**: async buffered + batched write path

This avoids losing high-value evidence during crashes or DB outages.

#### 2.2 Review-API: Buffered Logger
Create `api/async_logger.go` in review-api:

```
type AsyncLogger struct {
    buffer        chan LogEntry
    batchSize     int
    flushInterval time.Duration
    collection    *mongo.Collection
    maxRetries    int
    retryBackoff  time.Duration
    overflowMode  string // drop_newest | drop_oldest | block | spill_to_disk
}

- `Log(entry)` is non-blocking for Tier B logs
- If buffer is full, apply configured `overflowMode` and increment drop/overflow metrics
- Batch collector flushes when `batchSize` reached OR `flushInterval` elapsed
- Flush errors trigger retry with exponential backoff; on final failure move batch to spool/dead-letter queue
- Graceful shutdown drains buffer with timeout and flushes remaining entries
```

#### 2.3 Log-Collector: Batch Inserts + Failure Handling
Update MongoDB write logic in log-collector:

```
- Accumulate parsed logs in slice
- Flush to MongoDB when slice reaches 100 items OR 5 seconds elapsed
- Use unordered bulk writes for performance (document that insertion order is not guaranteed)
- On write failure: retry with backoff; if still failing, write to local spool for replay
```

#### 2.4 Replay Worker for Spool/Dead-Letter
Add a background replay worker:
```
- Reads failed batches from spool/dead-letter storage
- Re-attempts insert with rate limits
- Emits success/failure metrics
- Retains failed artifacts for forensic recovery window
```

#### 2.5 Observability and SLO Signals
Expose metrics and logs for operations:
```
async_log_buffer_depth
async_log_dropped_total
async_log_flush_total
async_log_flush_failed_total
async_log_flush_latency_ms
async_log_retry_total
async_log_spool_size_bytes
```

#### 2.6 Configuration
Add to `.env`:
```
ASYNC_LOG_BUFFER_SIZE=1000
ASYNC_LOG_BATCH_SIZE=100
ASYNC_LOG_FLUSH_INTERVAL=5s
ASYNC_LOG_MAX_RETRIES=5
ASYNC_LOG_RETRY_BACKOFF=250ms
ASYNC_LOG_OVERFLOW_MODE=drop_newest
ASYNC_LOG_SHUTDOWN_TIMEOUT=10s
ASYNC_LOG_ENABLE_SPOOL=true
ASYNC_LOG_SPOOL_PATH=/var/lib/modintel/async-log-spool
```

Set sane caps in code:
```
limit ASYNC_LOG_BUFFER_SIZE to max allowed value
limit ASYNC_LOG_BATCH_SIZE to max allowed value
reject invalid overflow mode values
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/async_logger.go` | New file - async logging logic |
| `services/review-api/api/handler.go` | Route Tier A vs Tier B logging paths |
| `services/review-api/main.go` | Initialize AsyncLogger on startup |
| `services/log-collector/main.go` | Add batch insert + retry/spool logic |
| `services/review-api/api/log_replay.go` | New file - spool replay worker |
| `services/review-api/metrics/*.go` | Add async logging metrics |
| `.env` | Add async config variables |

### Testing
1. Send 100 API requests rapidly → verify writes are batched, not one write/request
2. Fill buffer intentionally → verify configured `overflowMode` behavior and metrics
3. Simulate MongoDB outage → verify retries happen, failed batches are spooled
4. Recover MongoDB → verify replay worker drains spool and restores backlog
5. Simulate process crash → verify Tier A durability requirements are met
6. Trigger graceful shutdown under load → verify drain+flush within shutdown timeout
7. Validate memory remains bounded under sustained high ingress
8. Validate p95/p99 API latency improves versus synchronous baseline

---

## 3. Redis Caching

### What
Use Redis as a resilient cache layer with explicit consistency policies, stampede protection, and fail-open behavior. Keep database/API correctness as source of truth while reducing repeated MongoDB queries and ML recomputation.

### Why for ModIntel
- **ML Inference Results**: Same request patterns (same URI, parameters) may recur; caching ML scores avoids redundant inference
- **WAF Rule Metadata**: Rule descriptions, categories rarely change; cache for instant lookups
- **Dashboard Aggregations**: Attack statistics, top blocked IPs computed periodically and cached
- **Session Data**: Dashboard user sessions can be Redis-backed for horizontal scaling
- **Resilience**: Redis outage should degrade gracefully, not break request handling

### Current State
Every request hits MongoDB directly; ML inference runs on every request.

### Implementation Steps

#### 3.1 Add Redis Dependency
```
go get github.com/redis/go-redis/v9
```

#### 3.2 Define Caching Policy Per Data Type
Use explicit policy by endpoint/domain:
```
- ML inference: cache-aside + short TTL + optional stale-while-revalidate
- Rules metadata: cache-aside + event-driven invalidation on rule updates
- Dashboard stats: cache-aside + single-flight recompute + stale-while-revalidate
- Sessions (if enabled): Redis as primary session store with strict TTL and revoke support
```

Fail-open rule:
```
If Redis is unavailable, continue serving from MongoDB/ML path.
Cache errors must not fail user/API requests.
```

#### 3.3 Define Cache Keys
```
ml:inference:{hash(features)} → ML score (TTL: 5min)
rules:all → Rule list JSON (TTL: 1hr)
stats:daily:{date} → Daily attack statistics (TTL: 10min)
session:{token} → User session data (TTL: 30min)
```

Key safety rules:
```
- Canonicalize input before hashing for ml:inference keys (stable field order, normalized numeric precision)
- Avoid raw PII/secrets in keys
- Prefix keys by environment (dev/stage/prod) to avoid cross-env collisions
- Keep values small; compress large JSON payloads if needed
```

#### 3.4 Implement Cache Service
Create `services/cache/redis.go`:
```
type RedisCache struct {
    client *redis.Client
}

func (c *RedisCache) Get(key string) ([]byte, error)
func (c *RedisCache) Set(key string, value []byte, ttl time.Duration) error
func (c *RedisCache) Delete(key string) error
func (c *RedisCache) DeletePattern(pattern string) error
func (c *RedisCache) GetOrCompute(key string, ttl time.Duration, fn func() ([]byte, error)) ([]byte, error)
```

Implementation notes:
```
- Add context deadlines for all Redis operations
- Distinguish cache miss from Redis error
- Instrument hit/miss/error and latency metrics
- Add optional local in-process single-flight to coalesce concurrent misses
```

#### 3.5 Add Stampede Protection and Freshness Controls
```
- Use single-flight for hot misses (one recompute, many waiters)
- Add TTL jitter (e.g., +/-10%) to avoid synchronized expirations
- Use stale-while-revalidate for stats/rules where acceptable
- Add max recompute concurrency guard for expensive ML paths
```

#### 3.6 Update Inference Endpoint
```
1. Hash incoming features
2. Check Redis for cached score
3. If HIT: return cached score immediately
4. If MISS: single-flight compute inference, cache result, return
5. If Redis error: continue with inference path; return result without failing request
```

#### 3.7 Update Dashboard Stats
```
1. Check Redis for cached stats
2. If HIT: return immediately
3. If MISS: single-flight query/compute, cache, return
4. If cache stale and SWR enabled: serve stale quickly and refresh in background
```

#### 3.8 Rules Cache Invalidation
```
- On rule create/update/delete, delete keys: rules:all and rules:* selectors
- Keep TTL as safety net, not primary invalidation mechanism
- Add admin endpoint/hook for manual cache purge during incident response
```

#### 3.9 Session Store Hardening (if Redis sessions used)
```
- Store minimal session payload only (no sensitive plaintext)
- Enforce short TTL + sliding renewal policy
- Rotate tokens and support explicit revoke on logout/password reset
- Separate key namespace for sessions
```

#### 3.10 Configuration
Add to `.env`:
```
REDIS_URL=redis://redis:6379
REDIS_POOL_SIZE=100
REDIS_MIN_IDLE_CONNS=10
REDIS_DIAL_TIMEOUT=2s
REDIS_READ_TIMEOUT=500ms
REDIS_WRITE_TIMEOUT=500ms
REDIS_ENABLE_TLS=false

CACHE_ML_TTL=5m
CACHE_RULES_TTL=1h
CACHE_STATS_TTL=10m
CACHE_TTL_JITTER_PCT=10
CACHE_ENABLE_SWR=true
CACHE_FAIL_OPEN=true
CACHE_SINGLEFLIGHT_ENABLED=true
```

Set sane caps in code:
```
- Clamp TTLs to min/max allowed ranges
- Reject invalid jitter percentage
- Enforce max value size before cache set
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/go.mod` | Add `go-redis/v9` |
| `services/review-api/services/cache/redis.go` | New file - Redis client wrapper |
| `services/review-api/services/cache/inference.go` | New file - ML cache logic |
| `services/review-api/services/cache/singleflight.go` | New file - miss coalescing helper |
| `services/review-api/api/handler.go` | Add caching to relevant handlers |
| `services/review-api/main.go` | Initialize Redis connection |
| `services/review-api/metrics/*.go` | Add cache hit/miss/error and latency metrics |
| `docker-compose.yml` | Add Redis service |
| `.env` | Add Redis URL |

### Testing
1. Send identical inference request twice -> second request should be faster (cache hit)
2. Simulate concurrent identical misses -> verify single-flight runs only one backend compute
3. Wait for TTL expiry -> verify miss then recache behavior
4. Force Redis outage -> verify API remains functional via fail-open path
5. Update/delete rules -> verify immediate invalidation and fresh read on next request
6. Validate hit rate and fallback/error metrics in normal and failure scenarios
7. Check Redis memory and key cardinality remain bounded under sustained load
8. Security test: ensure session keys/payloads do not leak sensitive data

---

## 4. Connection Pooling

### What
Tune and manage MongoDB and Redis connection pools as first-class runtime controls with timeouts, saturation policies, and observability. Goal is predictable latency under burst traffic without exhausting backend connection limits.

### Why for ModIntel
- **MongoDB Connections**: Both review-api and log-collector connect to MongoDB; connection overhead is significant under load
- **Traffic Spikes**: WAF attacks generate bursts of logs; connection pooling handles spikes without connection exhaustion
- **Random Failures**: Without pooling, random "connection refused" errors occur when DB limits are hit
- **Resource Efficiency**: Fewer TCP handshakes, less memory fragmentation
- **Stability Under Degradation**: Explicit pool/timeouts prevent cascading failures when DB/Redis slows down

### Current State
- Review-api uses `mongo.Connect()` - likely creates pool but may not configure limits
- Log-collector creates new connections on reconnection

### Implementation Steps

#### 4.1 Define Pooling and Timeout Policy
Set baseline policy before code changes:
```
- One shared long-lived client per process per backend (MongoDB/Redis)
- No per-request connect/disconnect
- Strict operation deadlines for all DB/cache calls
- Bounded wait queues and fail-fast behavior under saturation
```

#### 4.2 Review-API: Configure MongoDB Pool
Update `main.go`:
```go
clientOpts := options.Client().
    ApplyURI(mongoURI).
    SetMaxPoolSize(100).
    SetMinPoolSize(10).
    SetMaxConnIdleTime(30 * time.Second).
    SetServerSelectionTimeout(3 * time.Second).
    SetConnectTimeout(3 * time.Second).
    SetSocketTimeout(10 * time.Second).
    SetWaitQueueTimeout(2 * time.Second)

client, err := mongo.Connect(ctx, clientOpts)
```

Operational notes:
```
- Keep one global `*mongo.Client` and reuse collection handles
- Wrap each query/insert with context timeout
- Fail fast when wait queue timeout is exceeded; return controlled error
```

#### 4.3 Log-Collector: Configure MongoDB Pool
Use same strategy with tuned values for ingest profile:
```
- Higher max pool may be needed for burst ingest
- Keep min pool modest to avoid idle resource waste
- Reconnect loops must not recreate clients repeatedly
```

#### 4.4 Review-API: Configure Redis Pool (if caching implemented)
```go
redisOpts := &redis.Options{
    Addr:         redisAddr,
    PoolSize:     100,
    MinIdleConns: 10,
    DialTimeout:  2 * time.Second,
    ReadTimeout:  500 * time.Millisecond,
    WriteTimeout: 500 * time.Millisecond,
    PoolTimeout:  1 * time.Second,
    MaxConnAge:   5 * time.Minute,
}
```

#### 4.5 Saturation and Backpressure Behavior
Define explicit behavior when pools are exhausted:
```
- API read paths: fail fast with retriable 503/controlled error (do not hang)
- Async writers: enqueue to bounded buffer/spool and retry based on policy
- Never allow unbounded goroutine buildup waiting on connections
```

#### 4.6 Connection Health Checks
Use startup and periodic health checks:
```go
// Startup readiness
err = client.Ping(ctx, nil)

// Liveness/readiness probes should validate backend connectivity with timeout
```

#### 4.7 Graceful Shutdown
```go
defer func() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    client.Disconnect(ctx)
}()
```

Shutdown notes:
```
- Stop accepting new requests before disconnect
- Drain async workers, then close DB/cache clients
- Emit shutdown metrics/logs for unfinished work
```

#### 4.8 Configuration
Add to `.env`:
```
MONGO_MAX_POOL_SIZE=100
MONGO_MIN_POOL_SIZE=10
MONGO_MAX_CONN_IDLE_TIME=30s
MONGO_CONNECT_TIMEOUT=3s
MONGO_SERVER_SELECTION_TIMEOUT=3s
MONGO_SOCKET_TIMEOUT=10s
MONGO_WAIT_QUEUE_TIMEOUT=2s

REDIS_POOL_SIZE=100
REDIS_MIN_IDLE_CONNS=10
REDIS_DIAL_TIMEOUT=2s
REDIS_READ_TIMEOUT=500ms
REDIS_WRITE_TIMEOUT=500ms
REDIS_POOL_TIMEOUT=1s
REDIS_MAX_CONN_AGE=5m
```

Set sane caps in code:
```
- Clamp pool sizes to safe min/max ranges
- Reject negative/zero timeout values
- Log effective runtime pool settings at startup
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/main.go` | Configure MongoDB and Redis pool options |
| `services/review-api/db/mongo.go` | Add pool + timeout configuration |
| `services/review-api/cache/redis.go` | Add Redis pool and timeout configuration |
| `services/log-collector/main.go` | Configure MongoDB pool options for ingest profile |
| `services/log-collector/db/mongo.go` | Add pool + timeout configuration |
| `services/review-api/metrics/*.go` | Add pool saturation/latency/error metrics |
| `.env` | Add pool and timeout config variables |

### Testing
1. Load test with steady and burst traffic -> verify connections stay within configured limits
2. Concurrent requests -> verify connection reuse and reduced connect churn
3. Saturation test -> verify fail-fast behavior when wait queue/pool timeouts are exceeded
4. Inject MongoDB latency/outage -> verify controlled errors, no request hangs, and recovery after backend returns
5. Inject Redis latency/outage -> verify cache timeouts and graceful fallback behavior
6. Long idle period -> verify idle connections trimmed and min pool behavior is as configured
7. Shutdown under load -> verify workers drain and all clients disconnect cleanly
8. Verify pool/timeout metrics and alerts trigger at expected thresholds

---

## Implementation Order

| Priority | Task | Section | Rationale |
|----------|------|---------|-----------|
| 1 | Connection Pooling | §4 | Foundation - improves everything, low risk |
| 2 | Pagination | §1 | High user impact, straightforward implementation |
| 3 | Redis Caching | §3 | Significant performance gain for ML and stats |
| 4 | Async Logging | §2 | Backend optimization, improves write throughput |
| 5 | Access Control Hardening | §5 | Security-critical; blocks staging/UAT rollout if missing |
| 6 | Error Handling and Crash Recovery | §6 | Reliability baseline; stabilizes all prior work |
| 7 | Rule Refactor and Custom Rules | §7 | Data ownership fix; unblocks custom rule authoring |
| 8 | WebSocket Real-Time Alerts | §8 | Replaces polling with sub-second push delivery |

---

## Branch Strategy

- Branch from: `modintel-base`
- Feature branch: `feat/scalability-practices`

Implement in order above. Each practice should be a separate commit with tests passing before moving to next.

---

## Success Metrics

| Section | Practice | Metric | Target |
|---------|----------|--------|--------|
| §1 | Pagination | Dashboard load time with 10K alerts | < 500ms |
| §1 | Pagination | Cursor stability under concurrent inserts | No duplicates or skipped entries |
| §2 | Async Logging | Review-api p99 latency (vs sync baseline) | < 50ms |
| §2 | Async Logging | Log loss on crash within flush interval | 0 Tier A events; ≤ flush_interval of Tier B |
| §3 | Redis Caching | Cache hit rate | > 80% |
| §3 | Redis Caching | API availability during Redis outage | 100% (fail-open) |
| §4 | Connection Pooling | Connection errors under load | 0 |
| §4 | Connection Pooling | Request hang on pool saturation | 0 (fail-fast instead) |
| §5 | Access Control | Unauthenticated page access (direct URL) | 0 |
| §5 | Access Control | Auth-service outage behavior | Fail-closed, no bypass |
| §6 | Error Handling | Leaked internal details in API responses | 0 |
| §6 | Error Handling | Service recovery after dependency outage | < circuit-breaker open timeout |
| §7 | Rule Refactor | Frontend hardcoded rule metadata remaining | 0 |
| §7 | Rule Refactor | Custom rule create/persist/toggle | End-to-end functional |
| §7 | Rule Refactor | Managed overrides after rule mutations | Correct and deterministic |
| §8 | Real-Time Alerts | Alert delivery latency (insert -> dashboard render, p95) | < 1s |
| §8 | Real-Time Alerts | Dashboard reconnect recovery after review-api restart | < 10s |
| §8 | Real-Time Alerts | Polling fallback availability after WS failure | 100% |

---

## 5. Dashboard Access Control Hardening (Auth/RBAC Gaps)

### Goal
Enforce authentication and authorization as a full-stack control (frontend UX + server/proxy enforcement) with deny-by-default behavior, secure token handling, and auditable decisions.

### Current Gaps
- Route protection is mostly client-side (`requireAuth()`), so static page URLs are not server-denied.
- No frontend role-based page guards (admin/analyst/viewer page-level access matrix not enforced in UI routing).
- Sign-in has demo fallback auth path when auth-service is unavailable.
- Frontend token storage uses `localStorage` (higher XSS exposure risk than httpOnly cookies).
- Auth semantics are not explicit (`401` vs `403` behavior inconsistent across UI/API).
- No guaranteed bootstrap gate to prevent protected-content flash before auth check completes.
- Missing centralized audit trail for authorization denials and privilege changes.

### Implementation Steps

#### 5.1 Define Access Model (Deny by Default)
Create a centralized access matrix:
```
- Roles: admin, analyst, viewer
- Resources: dashboard pages + API capability groups
- Decision: default deny unless explicit allow
```

Requirements:
```
- UI checks improve UX only; backend API RBAC remains source of truth
- Any mismatch between UI role and API role resolves to API role
- Add versioned policy file for traceability
```

#### 5.2 Remove Insecure Auth Paths
```
- Remove demo fallback login flow and hardcoded credentials from signin flow
- Fail closed if auth-service is unavailable (show service-unavailable page)
- Disallow local bypass modes in staging/UAT and production-like builds
```

#### 5.3 Secure Token Storage and Session Flow
Adopt cookie-based session/JWT transport:
```
- httpOnly + Secure + SameSite cookies
- Short access-token/session TTL with refresh rotation
- Explicit revoke on logout, password reset, and admin session revoke
- CSRF protection for state-changing requests (token or same-site strategy)
```

#### 5.4 Frontend Guard and Bootstrap Gate
Implement a centralized route guard in `dashboard/js/auth.js`:
```
1. App bootstrap calls `/api/whoami`
2. Block protected page render until auth state resolves
3. If unauthenticated -> redirect to `/signin`
4. If authenticated but unauthorized -> render `/403`
5. If token expired/invalid -> clear auth state and redirect cleanly
```

#### 5.5 Server-Side Route Protection (Caddy + API)
```
- Caddy enforces unauthenticated dashboard route redirects to `/signin`
- Backend APIs enforce RBAC on every protected endpoint
- Never trust client role claims without server verification
- Return standardized status codes: 401 unauthenticated, 403 unauthorized
```

#### 5.6 Unauthorized and Error UX
```
- Add dedicated 403 page with least-privilege messaging
- Avoid leaking internal authorization details to users
- Keep navigation safe (no open redirect vectors in return URLs)
```

#### 5.7 Auditing and Observability
Add security telemetry:
```
auth_login_success_total
auth_login_failure_total
authz_denied_total{resource,action,role}
auth_token_expired_total
auth_session_revoked_total
```

Audit events:
```
- login/logout, token refresh, role change, authz deny, suspicious replay/tamper attempts
```

#### 5.8 Configuration
Add to `.env`:
```
AUTH_COOKIE_SECURE=true
AUTH_COOKIE_HTTPONLY=true
AUTH_COOKIE_SAMESITE=Lax
AUTH_ACCESS_TTL=15m
AUTH_REFRESH_TTL=7d
AUTH_FAIL_CLOSED=true
AUTH_ENFORCE_RBAC=true
AUTH_ENABLE_AUDIT_LOG=true
```

### Affected Files
| File | Changes |
|------|---------|
| `dashboard/js/signin.js` | Remove demo fallback and hardcoded dev credentials |
| `dashboard/js/auth.js` | Add centralized bootstrap guard and role checks |
| `dashboard/js/router.js` | Enforce deny-by-default page access mapping |
| `dashboard/403.html` | New file - explicit unauthorized page |
| `dashboard/*.html` | Apply centralized guard consistently |
| `proxy-waf/Caddyfile` | Enforce route-level redirects for unauthenticated access |
| `services/review-api/api/middleware/auth.go` | Standardize 401/403 handling and RBAC checks |
| `services/review-api/api/handler.go` | Enforce per-endpoint RBAC scopes |
| `docs/AUTHENTICATION_GUIDE.md` | Document authn/authz model, token flow, and failure modes |
| `.env` | Add auth hardening config values |

### Verification
1. Unauthenticated request to `/events`, `/monitor`, `/settings` redirects to `/signin`.
2. Authenticated viewer access to admin pages renders `/403` and no privileged content is shown.
3. API request without auth returns `401`; API request with insufficient role returns `403`.
4. Expired/invalid/tampered token clears session and redirects cleanly without render flash.
5. Auth-service outage in staging/UAT results in fail-closed behavior (no silent bypass).
6. Logout/password reset/session revoke invalidates active session immediately.
7. Attempted open-redirect return URLs are rejected/sanitized.
8. Audit logs and auth/authz metrics capture login, deny, revoke, and token-expiry events.
---

## 6. Graceful Error Handling and Crash Recovery

### What
Implement a unified reliability model across Go and Python services: sanitized client errors, structured diagnostics, bounded retries, circuit breaking, and crash-safe shutdown/recovery. Focus on fail-safe behavior without leaking internal details.

### Why for ModIntel
- **Security**: Prevents exposure of internal details (e.g., stack traces, DB errors) in API responses.
- **Reliability**: Handles transient failures (network issues, DB timeouts) with retries and fallbacks.
- **Maintainability**: Structured logging aids debugging; consistent patterns reduce bugs.
- **User Experience**: Generic error messages for clients; graceful degradation during failures.
- **Operational Control**: Standardized recovery behavior avoids cascading failures during backend incidents.

### Current State
- Basic error handling exists but inconsistent (e.g., some APIs return full exceptions).
- Logging is minimal; no structured format or centralized aggregation.
- No retries or circuit breakers for external calls.
- ML pipelines lack fallbacks; services may crash without recovery.

### Implementation Steps

#### 6.1 Define Error Taxonomy and API Contract
Create shared error classes and response schema:
```
- Client errors: validation/auth/authz/not found/rate limit
- Transient server errors: timeout, dependency unavailable, deadlock, network reset
- Fatal/internal errors: unexpected panic/exception
```

Standard response envelope:
```json
{
  "error": {
    "code": "internal_error",
    "message": "Internal server error",
    "request_id": "req-abc123"
  }
}
```

Rules:
```
- Never return stack traces, raw DB errors, or dependency internals to clients
- Always attach request ID/correlation ID in response and logs
- Enforce consistent status mapping (400/401/403/404/409/429/500/502/503/504)
```

#### 6.2 Go Service Hardening (review-api, log-collector)
```
- Use typed/sentinel errors with wrapping (`fmt.Errorf("...: %w", err)`)
- Add panic recovery middleware that logs stack internally and returns sanitized 500
- Enforce operation timeouts with context on DB/cache/network calls
- Use early returns and explicit error translation at API boundary
```

#### 6.3 Python Service Hardening (inference-engine, ml-pipeline)
```
- Use specific exceptions (no bare `except`)
- Convert internal exceptions to sanitized API/domain errors
- Add timeout controls for model load/inference/external I/O
- Add guarded fallback model/path with explicit confidence marker
```

#### 6.4 Structured Logging and Correlation
```
- Standardize JSON logs across services
- Required fields: ts, level, service, env, request_id, trace_id, user_id (if available), error_code
- Log full internal error context only on server side
- Redact secrets/PII in logs
```

#### 6.5 Retry, Backoff, and Idempotency Rules
Apply retries only to retriable failures:
```
- Retry on timeout/connection reset/5xx from dependencies
- Do not retry on validation/auth/authz/not-found/conflict errors
- Use exponential backoff + jitter + max attempts
- Require idempotency key or idempotent operation for write retries
```

#### 6.6 Circuit Breakers and Degradation Paths
```
- Add circuit breakers per dependency (MongoDB, Redis, model backend)
- Open circuit after threshold; half-open probe for recovery
- Degraded mode: serve reduced features where safe (never bypass auth/RBAC)
- Surface dependency health in readiness endpoint
```

#### 6.7 Crash Recovery and Shutdown Discipline
```
- Graceful shutdown order: stop intake -> drain workers -> flush buffers/spool -> close connections
- Persist in-flight critical artifacts (spool/checkpoints) before exit
- Add startup recovery to replay spool/checkpoints after crash
```

#### 6.8 Configuration
Add to `.env`:
```
ERROR_INCLUDE_REQUEST_ID=true
ERROR_SANITIZE_ENABLED=true
LOG_FORMAT=json
LOG_REDACT_SECRETS=true

RETRY_MAX_ATTEMPTS=5
RETRY_BASE_BACKOFF=100ms
RETRY_MAX_BACKOFF=5s
RETRY_JITTER=true

CIRCUIT_BREAKER_ENABLED=true
CIRCUIT_BREAKER_FAILURE_THRESHOLD=10
CIRCUIT_BREAKER_OPEN_TIMEOUT=30s

REQUEST_TIMEOUT=10s
SHUTDOWN_GRACE_PERIOD=15s
```

Set sane caps in code:
```
- Cap max retry attempts and backoff upper bound
- Reject unsafe timeout values
- Disable debug/stacktrace response mode in production
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/handler.go` | Standardize error translation and response envelope |
| `services/review-api/api/middleware/recovery.go` | New file - panic recovery middleware |
| `services/log-collector/main.go` | Add timeout/retry/circuit-breaker integration |
| `services/inference-engine/main.py` | Sanitize exceptions, add fallback paths, structured logging |
| `services/inference-engine/error_types.py` | New file - domain exception mapping |
| `ml-pipeline/train_model.py` | Add checkpoint-safe error handling and recovery hooks |
| `services/review-api/go.mod` | Add resilience/logging dependencies |
| `services/inference-engine/requirements.txt` | Add retry/circuit-breaker libraries as needed |
| `docs/ERROR_HANDLING_GUIDE.md` | New file - shared error and recovery contract |
| `.env` | Add reliability and recovery config values |

### Testing
1. Simulate dependency failure (Mongo/Redis down) -> verify sanitized 5xx with request ID and internal diagnostic logs
2. Simulate validation/auth errors -> verify correct non-5xx codes and no retries
3. Retry tests -> verify backoff + jitter + max-attempt behavior on transient failures
4. Circuit-breaker tests -> verify open/half-open/close transitions and degraded behavior
5. Panic/exception injection -> verify process survives request path and returns sanitized 500
6. Crash/restart test -> verify spool/checkpoint replay and no critical data loss beyond policy
7. Logging verification -> ensure JSON fields present and secrets are redacted
8. Load test during partial outage -> verify latency/error budgets remain within targets

---

## 7. Rule Refactor and Custom Rule Implementation

### Goals
- Move rule metadata ownership from frontend hardcoded maps to backend data sources.
- Keep `GET /api/rules` as the single source of truth for Rules page rendering.
- Implement the left-panel `Write Custom Rule` flow end-to-end.
- Preserve current rule toggle behavior and managed override generation.

### Current Problems
- Rule metadata is split across layers (backend defaults + frontend `ruleNotes`).
- Frontend can drift from backend rule definitions over time.
- Custom rule form is present but not wired to persistence, validation, or deployment.
- No explicit versioning/approval lifecycle for newly authored custom rules.

### Target Architecture

#### Rule Data Ownership
- Backend owns all rule records and optional analyst metadata.
- Frontend only renders API responses; no embedded hardcoded catalog.
- Database stores both built-in rule metadata and user-authored custom rules.

#### Rule Types
- `builtin`: CRS/custom preloaded baseline rules managed by system.
- `custom`: user-created rules from UI form.

#### Rule States
- `enabled`/`disabled` for enforcement.
- `draft`/`active`/`archived` lifecycle for custom rules (optional but recommended).

### Data Model Plan (Mongo)
- Create a unified `waf_rules` schema with fields like:
  - identity: `id`, `type`, `source`
  - display: `category`, `description`
  - analyst docs: `purpose`, `triggers`, `impact`, `analyst_guidance`
  - execution: `enabled`, `syntax`, `phase`, `action`
  - audit: `created_at`, `updated_at`, `created_by`, `updated_by`
  - lifecycle: `status` (`draft|active|archived`)
- Add indexes:
  - unique on `id`
  - optional compound indexes for listing/filtering (`type`, `status`, `enabled`)

### API Refactor Plan

#### Read APIs
- Update `GET /api/rules` to return DB-backed rule catalog only.
- Add optional query params for filtering (`type`, `status`, `enabled`, `category`).
- Include analyst metadata fields in response so frontend can render details panel.

#### Write APIs
- Add `POST /api/rules` for creating custom rules.
- Add `PUT /api/rules/:id` for metadata/status updates.
- Add `PATCH /api/rules/:id/enabled` for enable/disable toggles.
- Add `DELETE /api/rules/:id` or archive endpoint for safe deactivation.

#### Validation
- Validate rule ID format and uniqueness.
- Validate syntax structure and required directives.
- Validate category against allowed set + allow custom categories.
- Reject unsafe or malformed payloads with sanitized errors.

### Migration Plan
- Step 1: Seed DB with current built-in rules from backend defaults.
- Step 2: Migrate frontend rule annotation content into DB analyst metadata fields (`purpose`, `triggers`, `impact`, `analyst_guidance`).
- Step 3: Switch `GET /api/rules` to DB-only path behind feature flag.
- Step 4: Remove backend hardcoded defaults after parity verification.
- Step 5: Remove frontend hardcoded `ruleNotes` permanently.

### Frontend Plan (Rules Page)

#### Data Loading
- Remove all hardcoded rule fallback behavior.
- Render only API response data for both list and details.
- Show explicit empty/error states from API outcomes.

#### Details Panel
- Populate rule detail expansion from API metadata fields.
- Gracefully handle missing analyst metadata with neutral placeholders.

#### Toggle Behavior
- Keep per-rule enable/disable actions via API.
- Keep pending restart indicator after state changes.

### "Write Custom Rule" Implementation Plan

#### Left Panel UI Improvements
- Redesign form layout for clarity and faster authoring (group fields by identity, metadata, syntax).
- Add explicit form inputs for backend first-class fields so frontend matches schema exactly.
- Add a dedicated "Trigger Conditions" area to capture what causes the rule to fire.
- Keep a fixed, predictable field order for authoring:
  - core: `rule-id`, `category`, `description`
  - behavior: `purpose`, `triggers`, `impact`, `analyst_guidance`
  - execution: `syntax`, `phase`, `action`, `enabled`, `status`
- Add helper text under each field and validation hints before submit.
- Add syntax textarea improvements:
  - monospace font
  - larger default height
  - optional expand/collapse
  - live character count
- Add rule template picker (SQLi/XSS/RCE/etc.) to prefill safe starter syntax.
- Add preview/summary panel before submission (ID, category, action, enabled state).
- Improve action area with clear primary/secondary hierarchy (`Add Rule`, `Clear`, optional `Save Draft`).
- Add success/error toast and inline error states aligned with existing modal patterns.
- Ensure mobile responsiveness and accessibility (labels, focus order, keyboard interactions, contrast).

#### Form Behavior
- Enforce required fields: `rule-id`, `category`, `description`, `rule-syntax`.
- Enforce required behavior fields for custom rules: `purpose`, `triggers`.
- Add client-side basic validation and clear inline errors.
- Disable submit during request; show progress and success/failure messages.

#### API Integration
- Wire `Add Rule` to `POST /api/rules`.
- Submit payload with `type=custom`, `status=draft` or `active` per design.
- Submit explicit backend fields (including `triggers`) as top-level typed properties, not only free-form extras.
- On success:
  - clear form
  - refresh rules table
  - set pending restart flag if rule is active/enabled

#### Endpoint Consistency
- `PUT /api/rules/:id` handles metadata/lifecycle edits.
- `PATCH /api/rules/:id/enabled` handles toggle-only state changes.
- Frontend uses toggle endpoint for list actions and update endpoint for editor form saves.

#### Extensible Field Model
- Prefer first-class schema fields for known rule metadata used by UI and analysts.
- If truly needed, keep optional `custom_fields` as secondary extension storage only.
- Ensure frontend always renders first-class fields directly (especially `triggers`).

#### Safety Controls
- Restrict custom rule creation/update to authorized roles.
- Add server-side syntax/lint validation before saving.
- Optionally require approval flow before activation in staging/UAT mode.

### WAF Sync Plan
- Extend managed overrides sync to include custom rule deployment state.
- Define output strategy:
  - disabled rules -> `SecRuleRemoveById`
  - active custom rules -> generated include file entries
- Keep generated files deterministic and auditable.
- Trigger sync on create/update/toggle/archive operations.

### Security and Compliance
- Keep CSP strict (`script-src 'self'`) and avoid inline scripts.
- Sanitize all API errors and rule content handling paths.
- Enforce RBAC for create/update/delete operations.
- Log audit events for rule changes with actor, before/after, and timestamp.

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/handler.go` | Add POST/PUT/PATCH/DELETE rule endpoints, update GET with filters |
| `services/review-api/api/middleware/auth.go` | RBAC checks on rule mutation endpoints |
| `services/review-api/db/rules.go` | New file - rule CRUD and query logic |
| `services/review-api/db/rules_seed.go` | New file - built-in rule seeding |
| `services/review-api/api/validation.go` | New file - rule ID, syntax, category validation |
| `dashboard/js/rules.js` | Remove hardcoded ruleNotes, render API data, wire custom rule form |
| `dashboard/js/rule-form.js` | New file - custom rule form behavior and validation |
| `dashboard/rules.html` | Update rule detail panel, add custom rule form UI |
| `dashboard/403.html` | Exists from §5 (no changes needed here) |
| `.env` | Add feature flags and rule config |

### Testing
1. Unit tests for validation, ID collisions, and lifecycle transitions.
2. Integration tests for `GET/POST/PUT/DELETE` rule APIs.
3. E2E tests for Rules page: load list, expand details, toggle status, create custom rule, restart-required visual state.
4. Regression tests for managed overrides file generation after rule mutations.
5. Verify no hardcoded rule metadata remains in frontend code.
6. RBAC enforcement: unauthorized role cannot create/update/delete rules.
7. Audit log captures rule change events with actor, before/after, and timestamp.

### Rollout Plan (Pre-Production)
- Phase 1: Introduce schema + seed + read path parity checks.
- Phase 2: Enable DB-backed details and remove frontend hardcoded metadata.
- Phase 3: Enable custom rule creation UI/API in controlled environment.
- Phase 4: Staging/UAT enablement with monitoring and rollback path.

### Acceptance Criteria
- Rules page shows only backend-provided data.
- No hardcoded rule metadata remains in frontend code.
- Custom rule form successfully creates and persists rules.
- Created rules appear in list immediately and can be toggled.
- Managed override artifacts remain correct after rule changes.
- Authz and audit controls are enforced for all rule mutations.

---

## 8. WebSocket Real-Time Alerts

### Goal
Replace HTTP polling for live alerts with a secure, resilient WebSocket pipeline delivering sub-second updates from Review-API to Dashboard, while preserving fallback behavior.



### Current State
- Dashboard currently polls every 5s (`dashboard/js/monitor.js`), no push channel exists.
- Review-API has no WebSocket endpoint or broadcast hub.
- MongoDB watch support depends on replica set configuration, which may not be guaranteed in all environments.

### Architecture Decision
- **Primary path**: MongoDB Change Stream -> Review-API WS Hub -> Dashboard clients.
- **Fallback path**: `POST /api/notify` from log-collector -> Review-API broadcast.
- **Client fallback**: if WS fails after bounded retries, temporarily revert to HTTP polling.

### Implementation Steps

#### 8.1 Backend - WebSocket Hub and Endpoints
- Add WebSocket dependency in `services/review-api/go.mod`.
- Create `services/review-api/api/ws_hub.go`:
  - client register/unregister
  - fan-out broadcast channel
  - bounded send queues + slow-consumer eviction
- Add `GET /api/ws` endpoint in review-api for upgrades.
- Add `POST /api/notify` endpoint for fallback notifications from log-collector.

#### 8.2 Auth and Security (Required)
- Require authentication on WS upgrade (token/cookie validation using existing auth middleware model).
- Enforce role checks for real-time stream access (`admin|analyst|viewer` as policy allows).
- Rate-limit WS connects/reconnect storms and validate origin.
- Use WSS in deployed environments behind Caddy.

#### 8.3 Data Source Strategy (Primary + Fallback)
- **Option A (preferred)**: MongoDB Change Stream watcher for `modintel.alerts` inserts.
- **Option B**: timestamp/cursor polling watcher when change streams unavailable.
- **Option C**: hybrid (A/B + `/api/notify`) for resilience.
- Startup behavior:
  - detect change stream capability
  - auto-select strategy
  - expose selected mode via health/metrics

#### 8.4 Log-Collector Notification Path
- After successful insert/upsert, enqueue non-blocking notify call to Review-API `/api/notify`.
- Keep notify fire-and-forget with timeout and retry budget (must not block ingestion loop).
- Include minimal payload (`alert_id`, `timestamp`) so Review-API fetches canonical document before broadcast.

#### 8.5 Frontend Migration (Dashboard)
- Replace primary polling loop with WebSocket client in `dashboard/js/monitor.js` (or `dashboard/js/index.js` as page ownership dictates).
- On WS message:
  - prepend alert row
  - update live counters
  - preserve current table state filters where applicable
- Add reconnection with exponential backoff + jitter.
- Add connection state indicator (`connected`, `reconnecting`, `disconnected`).
- Fallback to HTTP polling after N failed reconnect attempts; auto-return to WS on next successful handshake.

#### 8.6 Message Contract
Use versioned envelope:
```json
{
  "type": "new_alert",
  "version": 1,
  "data": {
    "id": "...",
    "timestamp": "...",
    "client_ip": "...",
    "uri": "...",
    "anomaly_score": 5,
    "triggered_rules": ["942100"],
    "ai_score": 0.87,
    "ai_confidence": 0.92,
    "ai_priority": "critical"
  }
}
```

Validation rules:
- Unknown `type` ignored safely by client.
- Backward-compatible additive fields only for `version=1`.

#### 8.7 Observability and Operations
Add metrics:
```
ws_connections_active
ws_broadcast_total
ws_broadcast_failed_total
ws_message_latency_ms
ws_reconnect_total
ws_fallback_polling_total
watcher_mode{change_stream|polling|hybrid}
```

Add structured logs for connect/disconnect/reconnect/fallback transitions.

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/go.mod` | Add WebSocket dependency |
| `services/review-api/api/ws_hub.go` | New file - hub, client lifecycle, broadcast logic |
| `services/review-api/api/watcher.go` | New file - change stream/polling watcher |
| `services/review-api/api/handler.go` | Add `/api/ws` and `/api/notify` endpoints |
| `services/review-api/main.go` | Initialize WS hub + watcher and register routes |
| `services/log-collector/main.go` | Add non-blocking notify path after insert |
| `dashboard/js/monitor.js` | Replace primary polling with WebSocket + reconnection/fallback logic |
| `dashboard/css/monitor.css` | Connection state indicator styles |
| `proxy-waf/Caddyfile` | Ensure WS upgrade headers and route support |

### Testing
1. Open dashboard -> verify WS connects and status shows connected.
2. Trigger attack/log insert -> verify alert rendered in <1s (p95).
3. Kill review-api -> verify client shows disconnected then reconnecting.
4. Restart review-api -> verify auto-reconnect and resumed live updates.
5. Disable change streams environment -> verify fallback watcher mode still delivers alerts.
6. Force WS handshake failures -> verify HTTP polling fallback activates and data still updates.
7. Open multiple tabs/clients -> verify fan-out consistency across clients.
8. Auth tests: unauthenticated WS upgrade rejected; authorized roles succeed.

### Acceptance Criteria
- Polling is no longer the primary live-alert mechanism.
- Sub-second live alert delivery is achieved under normal conditions.
- Automatic reconnect and polling fallback behavior is reliable.
- WS channel enforces authentication/authorization and does not bypass §5 controls.
- Real-time path remains operational when change streams are unavailable (fallback mode).

---

## 9. Production Security Hardening (Runtime + Plane Separation)

### Goal
Harden runtime security and strictly separate public traffic handling (data plane) from administrative surfaces (management plane), so one edge compromise cannot cascade into full environment takeover.

### Scope
- Container runtime hardening (non-root, capabilities, filesystem, privileges)
- Compose/network boundary design (public vs internal services)
- Dashboard serving path moved away from `proxy-waf`
- Management API exposure controls (allowlist/reverse proxy/auth gates)
- Secrets and config hygiene for deployment

### Current Risks
- Some services still run with root privileges.
- Dashboard static assets are served from the traffic-facing stack.
- Management services may be reachable too broadly.
- Secret handling relies on local discipline without strong guardrails.
- Startup ordering may allow partial boot with unavailable dependencies.

### Target Architecture

#### Data Plane
- `proxy-waf` is public-facing and handles only protected app traffic.
- No dashboard/admin static assets mounted into `proxy-waf`.
- Minimal runtime privileges and read-only filesystem where possible.

#### Management Plane
- Dashboard + management APIs served by `review-api` (or dedicated admin-web service).
- Exposed via separate host/path and strict access controls.
- Internal services stay on private Docker network by default.

### Implementation Steps

#### 9.1 Run Services as Non-Root
- Update Dockerfiles with explicit non-root `USER`.
- In Compose, enforce `user: "<uid>:<gid>"` for runtime.
- Ensure writable paths use explicit owned volumes only.

#### 9.2 Harden Container Runtime
- Add `read_only: true` where service allows.
- Add `cap_drop: ["ALL"]` and selectively add only required caps.
- Set `security_opt: ["no-new-privileges:true"]`.
- Avoid `privileged: true` and avoid mounting `docker.sock`.

#### 9.3 Separate Dashboard from proxy-waf
- Remove dashboard volume mount from `proxy-waf`.
- Serve dashboard static build from `review-api` (or dedicated admin-web).
- Keep `proxy-waf` focused on WAF + reverse proxy only.

#### 9.4 Lock Down Management Exposure
- Publish only required public ports.
- Put management endpoints behind dedicated reverse-proxy route/host.
- Restrict management ingress with IP allowlist/VPN where applicable.
- Enforce authenticated access and deny-by-default route policy.

#### 9.5 Network Segmentation in Compose
- Create distinct networks:
  - `public_net` for edge-facing services only
  - `private_net` for internal APIs/datastores
- Attach MongoDB/auth/internal services only to `private_net` unless explicitly required.

#### 9.6 Secrets and Env Hygiene
- Move secrets to runtime env injection or secret manager.
- Keep `.env.example` in repo; keep real `.env` out of git.
- Add secret scanning in CI and pre-commit checks.

#### 9.7 Health-Gated Startup
- Add `healthcheck` to critical services.
- Use `depends_on` with `condition: service_healthy` where supported.
- Fail fast when dependencies are unavailable instead of silent degraded boot.

#### 9.8 Observability + Audit Controls
- Log and metric events for auth failures, denied management access, and config drift.
- Add startup logs showing effective hardening config (uid/gid, readonly, caps).
- Alert on unexpected privileged settings in deployed manifests.

### Affected Files
| File | Changes |
|------|---------|
| `docker-compose.yml` | Add users, security opts, caps, read-only fs, network segmentation, health-gated dependencies |
| `proxy-waf/Dockerfile` | Create non-root runtime user and permissions |
| `services/review-api/Dockerfile` | Ensure non-root user and minimal writable paths |
| `services/auth-service/Dockerfile` | Ensure non-root user and reduced privileges |
| `proxy-waf/Caddyfile` | Keep only edge/public routing; remove dashboard serving concerns |
| `services/review-api/main.go` | Serve dashboard static assets securely (or route to admin-web) |
| `.env.example` | Document non-secret runtime config values |
| `.gitignore` | Ensure `.env` and secret files are excluded |
| `.github/workflows/*.yml` | Add secret scanning and deployment hardening checks |

### Verification
1. `docker compose ps` confirms all app services run as non-root UID/GID.
2. Container inspection confirms `no-new-privileges`, dropped caps, and read-only fs where configured.
3. `proxy-waf` container no longer contains dashboard mount/path.
4. Dashboard is reachable only through management route/service, not edge WAF path.
5. Internal services are not reachable from public interface/ports.
6. Secrets are absent from git history and excluded from future commits.
7. Service startup waits for healthy dependencies and fails clearly when dependencies are down.
8. Authz-denied and access-control logs/metrics appear in monitoring.

### Rollout Plan
- Phase 1: Non-root + runtime hardening in staging.
- Phase 2: Dashboard serving migration and network split.
- Phase 3: Management exposure restrictions and allowlists.
- Phase 4: CI enforcement (secret scan + hardening policy checks).
- Phase 5: Production cutover with rollback plan and smoke tests.

### Acceptance Criteria
- No critical service runs as root in production.
- Public-facing `proxy-waf` does not serve or mount dashboard/admin assets.
- Management plane is isolated and access-controlled.
- Secrets are not committed and are managed via secure runtime injection.
- Startup and runtime guardrails prevent insecure drift.
