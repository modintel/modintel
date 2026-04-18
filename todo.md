# ModIntel Scalability Implementation Plan

## Overview

This document outlines implementation plans for 5 backend scalability practices applied to the ModIntel WAF research system. Each section covers the technique, rationale, architecture, implementation steps, affected files, and testing.

---

## 1. Pagination

### What
Breaking large dataset responses into smaller chunks (pages) with offset or cursor-based navigation. Clients request `?page=1&limit=20` instead of receiving all 50,000 records.

### Why for ModIntel
- **Review Dashboard**: Displays attack logs/alerts - users need to browse history without loading thousands of records
- **Log Viewer**: Coraza audit logs can grow exponentially; pagination prevents memory exhaustion
- **Rule Lists**: CRS has ~300 rules; paginating makes the UI snappy
- **API Consumers**: Downstream systems consuming the review-api benefit from predictable response sizes

### Current State
No pagination exists; endpoints likely return full arrays.

### Implementation Steps

#### 1.1 Define Pagination Utilities
Create `api/pagination.go` in review-api:

```
page_offset = (page - 1) * limit
collection.Find(ctx, filter).Skip(page_offset).Limit(limit)
```

Response envelope:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1547,
    "total_pages": 78,
    "has_next": true,
    "has_prev": false
  }
}
```

#### 1.2 Update Endpoints
Paginate these existing endpoints:
- `GET /api/alerts` → `GET /api/alerts?page=1&limit=20`
- `GET /api/logs` → `GET /api/logs?page=1&limit=50`
- `GET /api/rules` → `GET /api/rules?page=1&limit=50`

#### 1.3 Frontend Updates
- Update dashboard tables to render pagination controls
- Add "Previous" / "Next" buttons with page numbers
- Store current page in URL query params for shareability

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/pagination.go` | New file - pagination helpers |
| `services/review-api/api/handlers.go` | Add page/limit params to queries |
| `services/review-api/main.go` | Register pagination middleware |
| `dashboard/js/*.js` | Add pagination UI components |

### Testing
1. Request `/api/alerts?page=1&limit=5` → verify 5 items returned
2. Request `/api/alerts?page=2&limit=5` → verify different 5 items
3. Request `/api/alerts?limit=1000` → verify capped at reasonable max (e.g., 100)
4. Verify `total` matches actual collection count
5. Dashboard pagination controls work correctly

---

## 2. Async Logging

### What
Buffering log entries in memory and flushing to disk/database in batches rather than writing synchronously on every request. Reduces I/O blocking and improves response latency.

### Why for ModIntel
- **Review-API Access Logs**: Every API request currently writes to MongoDB synchronously
- **Log-Collector**: Already tails Coraza logs; batching writes prevents write amplification
- **Performance Gain**: 200ms+ improvement per request by eliminating synchronous writes
- **MongoDB Load**: Batching reduces connection overhead and write operations

### Current State
- Review-api writes to MongoDB on every request synchronously
- Log-collector writes enriched logs immediately after parsing

### Implementation Steps

#### 2.1 Review-API: Buffered Logger
Create `api/async_logger.go` in review-api:

```
type AsyncLogger struct {
    buffer    chan LogEntry
    batchSize int
    flushInterval time.Duration
    client    *mongo.Client
}

- Channel buffered writes (non-blocking)
- Goroutine batch-collector runs every N seconds or when buffer reaches M items
- Graceful shutdown flushes remaining buffer
```

#### 2.2 Log-Collector: Batch Inserts
Update MongoDB write logic in log-collector:

```
- Accumulate parsed logs in slice
- Flush to MongoDB when slice reaches 100 items OR 5 seconds elapsed
- Use unordered bulk writes for performance
```

#### 2.3 Configuration
Add to `.env`:
```
ASYNC_LOG_BUFFER_SIZE=1000
ASYNC_LOG_FLUSH_INTERVAL=5s
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/async_logger.go` | New file - async logging logic |
| `services/review-api/api/handlers.go` | Replace direct MongoDB writes |
| `services/review-api/main.go` | Initialize AsyncLogger on startup |
| `services/log-collector/main.go` | Add batch insert logic |
| `.env` | Add async config variables |

### Testing
1. Send 100 API requests rapidly
2. Monitor MongoDB write operations (should be batched, not 100 individual writes)
3. Simulate crash → verify no more than flush_interval data loss
4. Verify graceful shutdown flushes all buffered logs
5. Monitor memory usage stays bounded with buffer size limit

---

## 3. Redis Caching

### What
Storing frequently accessed data in Redis (in-memory cache) instead of querying MongoDB or recomputing on every request. Cache invalidation happens on TTL expiration or explicit updates.

### Why for ModIntel
- **ML Inference Results**: Same request patterns (same URI, parameters) may recur; caching ML scores avoids redundant inference
- **WAF Rule Metadata**: Rule descriptions, categories rarely change; cache for instant lookups
- **Dashboard Aggregations**: Attack statistics, top blocked IPs computed periodically and cached
- **Session Data**: Dashboard user sessions can be Redis-backed for horizontal scaling

### Current State
Every request hits MongoDB directly; ML inference runs on every request.

### Implementation Steps

#### 3.1 Add Redis Dependency
```
go get github.com/redis/go-redis/v9
```

#### 3.2 Define Cache Keys
```
ml:inference:{hash(features)} → ML score (TTL: 5min)
rules:all → Rule list JSON (TTL: 1hr)
stats:daily:{date} → Daily attack statistics (TTL: 10min)
session:{token} → User session data (TTL: 30min)
```

#### 3.3 Implement Cache Service
Create `services/cache/redis.go`:
```
type RedisCache struct {
    client *redis.Client
}

func (c *RedisCache) Get(key string) ([]byte, error)
func (c *RedisCache) Set(key string, value []byte, ttl time.Duration) error
func (c *RedisCache) Delete(key string) error
func (c *RedisCache) DeletePattern(pattern string) error
```

#### 3.4 Update Inference Endpoint
```
1. Hash incoming features
2. Check Redis for cached score
3. If HIT: return cached score immediately
4. If MISS: run ML inference, cache result, return
```

#### 3.5 Update Dashboard Stats
```
1. Check Redis for cached stats
2. If HIT: return immediately
3. If MISS: query MongoDB, compute, cache, return
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/go.mod` | Add `go-redis/v9` |
| `services/review-api/services/cache/redis.go` | New file - Redis client wrapper |
| `services/review-api/services/cache/inference.go` | New file - ML cache logic |
| `services/review-api/api/handlers.go` | Add caching to relevant handlers |
| `services/review-api/main.go` | Initialize Redis connection |
| `docker-compose.yml` | Add Redis service |
| `.env` | Add Redis URL |

### Testing
1. Send identical inference request twice → second should be faster (cache hit)
2. Verify Redis contains key after first request
3. Wait for TTL expiry → verify cache miss on third request
4. Clear Redis → verify graceful degradation (still works, just slower)
5. Check Redis memory usage stays bounded

---

## 4. Payload Compression

### What
Compressing HTTP response bodies using gzip or brotli before sending to clients. Reduces bandwidth usage by 70-90% for JSON payloads.

### Why for ModIntel
- **Large JSON Responses**: Alert lists, ML feature vectors can be megabytes
- **Mobile Dashboard**: Users on mobile or slow connections benefit from compressed payloads
- **Network Efficiency**: Less data transfer = lower latency
- **Already Partial**: Caddy (reverse proxy) handles compression at the edge, but review-api itself should also compress for direct API consumers

### Current State
Caddy compresses responses, but direct API calls to review-api bypass Caddy and receive uncompressed JSON.

### Implementation Steps

#### 4.1 Review-API: Add Compression Middleware
Create `api/compression.go`:
```
- Use standard library compress/gzip
- Check Accept-Encoding header
- Wrap response writer to compress on write
- Minimum response size threshold (don't compress tiny responses)
- Compression level: default (slower but smaller) or fast
```

#### 4.2 Update Middleware Chain
Add compression after request logging, before response:
```
Recovery → Logger → Compressor → CORS → Handlers
```

#### 4.3 Configuration
```
COMPRESSION_ENABLED=true
COMPRESSION_LEVEL=5
COMPRESSION_MIN_SIZE=1024
```

#### 4.4 Alternative: Shared Compression
Since Caddy is in the stack, ensure review-api responses go through Caddy for compression when deployed. Add middleware only for direct API access scenarios.

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/compression.go` | New file - gzip middleware |
| `services/review-api/main.go` | Register compression middleware |
| `.env` | Add compression config |
| `docker-compose.yml` | Ensure Caddy routes through review-api |

### Testing
1. Request with `Accept-Encoding: gzip` → verify `Content-Encoding: gzip` in response
2. Compare raw vs compressed response sizes (should be 70-90% smaller)
3. Verify decompression works correctly on client side
4. Request without gzip header → verify no compression applied
5. Small responses (<1KB) → verify compression skipped

---

## 5. Connection Pooling

### What
Maintaining a pool of pre-established database connections that are reused across requests instead of creating/destroying a connection per request. Limits max connections, reduces latency.

### Why for ModIntel
- **MongoDB Connections**: Both review-api and log-collector connect to MongoDB; connection overhead is significant under load
- **Traffic Spikes**: WAF attacks generate bursts of logs; connection pooling handles spikes without connection exhaustion
- **Random Failures**: Without pooling, random "connection refused" errors occur when DB limits are hit
- **Resource Efficiency**: Fewer TCP handshakes, less memory fragmentation

### Current State
- Review-api uses `mongo.Connect()` - likely creates pool but may not configure limits
- Log-collector creates new connections on reconnection

### Implementation Steps

#### 5.1 Review-API: Configure MongoDB Pool
Update `main.go`:
```go
clientOpts := options.Client().
    ApplyURI(mongoURI).
    SetMaxPoolSize(100).
    SetMinPoolSize(10).
    SetMaxConnIdleTime(30 * time.Second)

client, err := mongo.Connect(ctx, clientOpts)
```

#### 5.2 Log-Collector: Configure MongoDB Pool
Same pool settings in log-collector `main.go`.

#### 5.3 Review-API: Configure Redis Pool (if caching implemented)
```go
redisOpts := &redis.Options{
    Addr:     redisAddr,
    PoolSize: 100,
    MinIdleConns: 10,
}
```

#### 5.4 Connection Health Checks
```go
// Ping to verify connection health
err = client.Ping(ctx, nil)
```

#### 5.5 Graceful Shutdown
```go
defer func() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    client.Disconnect(ctx)
}()
```

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/main.go` | Configure MongoDB pool options |
| `services/review-api/db/mongo.go` | Add pool configuration |
| `services/log-collector/main.go` | Configure MongoDB pool options |
| `services/log-collector/db/mongo.go` | Add pool configuration |

### Testing
1. Monitor MongoDB connections during load test (should stay within pool limits)
2. Concurrent requests: verify connections are reused
3. Simulate 1000 concurrent requests: verify no "connection limit exceeded" errors
4. Long idle period: verify min pool connections maintained
5. Shutdown: verify all connections closed gracefully

---

## Implementation Order

| Priority | Task | Rationale |
|----------|------|-----------|
| 1 | Connection Pooling | Foundation - improves everything, low risk |
| 2 | Pagination | High user impact, straightforward implementation |
| 3 | Redis Caching | Significant performance gain for ML and stats |
| 4 | Async Logging | Backend optimization, improves write throughput |
| 5 | Payload Compression | Lower priority due to Caddy already handling edge cases |

---

## Branch Strategy

- Branch from: `modintel-base`
- Feature branch: `feat/scalability-practices`

Implement in order above. Each practice should be a separate commit with tests passing before moving to next.

---

## Success Metrics

| Practice | Metric | Target |
|----------|--------|--------|
| Pagination | Dashboard load time with 10K alerts | < 500ms |
| Async Logging | Review-api p99 latency | < 50ms |
| Redis Caching | Cache hit rate | > 80% |
| Compression | Response size reduction | > 70% |
| Connection Pooling | Connection errors under load | 0 |

---

## 6. Dashboard Access Control Hardening (Auth/RBAC Gaps)

### Goal
Close weak frontend access-control behavior so dashboard route protection is enforceable, role-aware, and production-safe.

### Current Gaps
- Route protection is mostly client-side (`requireAuth()`), so static page URLs are not server-denied.
- No frontend role-based page guards (admin/analyst/viewer page-level access matrix not enforced in UI routing).
- Sign-in has demo fallback auth path when auth-service is unavailable.
- Frontend token storage uses `localStorage` (higher XSS exposure risk than httpOnly cookies).

### Implementation Tasks
- [ ] Remove demo fallback login flow from `dashboard/js/signin.js`.
- [ ] Add a centralized frontend route guard that checks role permissions before rendering page content.
- [ ] Define and enforce a page-to-role access matrix (e.g., destructive pages/actions hidden or blocked for viewer).
- [ ] Add `/api/whoami` check during app bootstrap to validate token + role before page render.
- [ ] Add server-side protection for dashboard routes in Caddy (redirect unauthenticated users to `/signin` where feasible).
- [ ] Keep API-side RBAC as source of truth and align frontend UX with backend permissions.
- [ ] Add explicit unauthorized page (`403`) handling in dashboard UI.

### Affected Files
| File | Changes |
|------|---------|
| `dashboard/js/signin.js` | Remove demo fallback and hardcoded dev credentials |
| `dashboard/js/auth.js` | Add role-aware route guard and bootstrap verification |
| `dashboard/*.html` | Apply centralized guard consistently |
| `proxy-waf/Caddyfile` | Add stronger route-level access controls/redirect logic |
| `docs/AUTHENTICATION_GUIDE.md` | Document frontend + backend access enforcement model |

### Verification
1. Unauthenticated request to `/events`, `/monitor`, `/settings` redirects to `/signin`.
2. Viewer cannot access admin-only flows in UI (and API still returns 403 if attempted directly).
3. Invalid/expired token always clears auth and redirects cleanly.
---

## 7. Graceful Error Handling and Crash Recovery

### What
Implementing robust error handling patterns to prevent information leakage, ensure logging with context, add recovery mechanisms (retries, fallbacks), and follow code patterns for Go and Python services. This includes sanitizing error responses, structured logging, and crash-safe operations.

### Why for ModIntel
- **Security**: Prevents exposure of internal details (e.g., stack traces, DB errors) in API responses.
- **Reliability**: Handles transient failures (network issues, DB timeouts) with retries and fallbacks.
- **Maintainability**: Structured logging aids debugging; consistent patterns reduce bugs.
- **User Experience**: Generic error messages for clients; graceful degradation during failures.
- **Current Gaps**: Some endpoints expose exception details; limited retry logic; basic logging without context.

### Current State
- Basic error handling exists but inconsistent (e.g., some APIs return full exceptions).
- Logging is minimal; no structured format or centralized aggregation.
- No retries or circuit breakers for external calls.
- ML pipelines lack fallbacks; services may crash without recovery.

### Implementation Steps

#### 7.1 Error Sanitization and Wrapping
- Update all HTTP responses to return generic messages (e.g., "Internal server error") while logging full details.
- In Go services: Use `pkg/errors` for wrapping; avoid exposing wrapped errors.
- In Python services: Use try-except with sanitized responses; log exceptions internally.

#### 7.2 Structured Logging
- Switch to `logrus` in Go (`sirupsen/logrus`) and `logging` with JSON formatters in Python.
- Add context (e.g., user ID, request ID) to logs.
- Centralize logs for aggregation (e.g., to Elasticsearch).

#### 7.3 Recovery Mechanisms
- Add retries with backoff for network/DB calls (e.g., `backoff` in Go, `tenacity` in Python).
- Implement fallbacks (e.g., default models in inference-engine).
- Use circuit breakers to prevent cascade failures.
- Add health checks and graceful shutdowns.

#### 7.4 Code Patterns
- Go: Early returns, `defer` for cleanup, custom error types.
- Python: try-except-else-finally, avoid bare except, raise custom exceptions.
- Add unit tests for error scenarios.

### Affected Files
| File | Changes |
|------|---------|
| `services/review-api/api/handler.go` | Sanitize errors, add wrapping |
| `services/log-collector/api/handler.go` | Sanitize errors |
| `services/inference-engine/main.py` | Sanitize exceptions, add fallbacks |
| `services/review-api/go.mod` | Add logging/error libraries |
| `services/inference-engine/requirements.txt` | Add tenacity for retries |
| `ml-pipeline/train_model.py` | Add error handling with checkpoints |

### Testing
1. Simulate failures (e.g., DB disconnect) → verify generic responses and logged details.
2. Test retries → verify backoff on transient errors.
3. Crash scenarios → verify graceful shutdown and no data loss.
4. Logging → verify structured output with context.

### Rating of Existing System
On a scale of 1-10 (10 being fully compliant), the current system scores **5/10**. Strengths: Basic exception handling in Python; some logging in Go services. Weaknesses: Exposed exception details in APIs (fixed partially); no retries or structured logging; inconsistent patterns; ML pipelines lack recovery. Prioritizing sanitization and logging will improve this to 8/10 with moderate effort.

---
