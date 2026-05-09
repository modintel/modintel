# ML Blocking — Layer 2 WAF Inline Blocking

## Objective

Add real-time ML-based blocking at Layer 2 for requests that pass through Coraza (Layer 1) without being blocked. Currently, regex + ML detection is done **post-factum** by log-collector tailing log files. This replaces that with **inline** blocking: a reverse proxy that runs regex → ML → block/allow before the request reaches the backend.

## Architecture Change

### Before
```
:8080 → proxy-waf-custom (log + body capture) → proxy-waf (Coraza) → juice-shop
                                                   ↑ post-factum miss detection (log-collector)
```

### After
```
:8080 → proxy-waf (Coraza + log + body capture) → waf-blocker (regex → ML) → juice-shop
:3000 → proxy-waf-custom → auth, training, review-api (unchanged, no Coraza)
```

### Key changes
- **Remove** `proxy-waf-custom:8080` (the extra Caddy hop)
- **Move** logging + body capture to `proxy-waf`'s Caddyfile (same volume, same file)
- **Expose** `proxy-waf:8080` directly (already has `trusted_proxies private_ranges`)
- **Add** `waf-blocker` service between proxy-waf and juice-shop
- **Keep** `proxy-waf-custom:3000` for dashboard/API routing (auth, training, review-api)

## WAF Blocker Service (`services/waf-blocker/`)

### Design Goals
- Minimal: Go stdlib only (net/http, regexp, encoding/json)
- Fail-open: if inference engine is down, allow request through
- Fast path: if no regex match, skip ML (reuse signatures from log-collector)
- WebSocket passthrough: skip buffering for upgrade requests

### Request Flow (per request)
```
1. Receive request from proxy-waf (port 8086, internal)
2. Check WebSocket upgrade? → forward directly (skip buffering)
3. Read & buffer request body
4. Run regex signatures on method + URI + headers + body
5. No match? → forward to juice-shop (fast path, ~99% of traffic)
6. Match? → POST /predict-miss to inference-engine:8083
7. Score >= threshold? → return 403 (blocked)
8. Score < threshold? → forward to juice-shop (allowed)
9. Inference error? → forward (fail-open)
```

### Configuration (Env Vars)
| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8086` | Listen address |
| `BACKEND_URL` | `http://juice-shop:3000` | Backend to forward to |
| `INFERENCE_URL` | `http://inference-engine:8083/predict-miss` | ML inference endpoint |
| `BLOCK_THRESHOLD` | `0.85` | Attack probability threshold for blocking |
| `SIGNATURES_FILE` | `/app/signatures/modintel_regex.signatures` | Regex patterns |

### Files to Create
- `services/waf-blocker/main.go` — HTTP server, regex matching, ML inference client, reverse proxy
- `services/waf-blocker/go.mod` — module `modintel.local/waf-blocker`, no external deps
- `services/waf-blocker/Dockerfile` — multi-stage Go build, ~5MB alpine image

### Files to Modify
- `proxy-waf-custom/Caddyfile` — remove `:8080` block entirely
- `proxy-waf/Caddyfile` — change `reverse_proxy juice-shop:3000` to `reverse_proxy waf-blocker:8086`
- `docker-compose.yml` — add waf-blocker service, remove proxy-waf-custom:8080 port, add proxy-waf:8080 port

## Side Effects & Notes

### log-collector changes
- `processCaddyAccessLogs` tails `waf-access.json` which is now written by **proxy-waf** instead of proxy-waf-custom. The same volume (`modintel_caddy_logs`) is mounted to both containers, so log-collector continues to work with no changes.
- Body cache (`getBodyCache` / `setBodyCache`) continues to be populated from the same Caddy access log, just written by proxy-waf now instead of proxy-waf-custom. No loss of this fallback.

### proxy-waf changes
- Already has `trusted_proxies private_ranges` on its reverse_proxy (line 25 of proxy-waf/Caddyfile) — no change needed.
- **Add** access logging with body capture (moved from proxy-waf-custom). Uses the same `modintel_caddy_logs` volume mounted to `/var/log/caddy`.
- Change `reverse_proxy` target from `juice-shop:3000` to `waf-blocker:8086`.

### Traffic Path Summary
```
Internet → host:8080 → container:proxy-waf:8080 (Coraza + security headers)
                     → container:waf-blocker:8086 (regex → ML → block/allow)
                     → container:juice-shop:3000 (backend)

Internet → host:3000 → container:proxy-waf-custom:3000 (routing only, no Coraza)
                     → container:auth-service:8084 (/api/v1/auth/*, /api/v1/users*)
                     → container:training-api:8085 (/api/training/*)
                     → container:review-api:8082 (dashboard + API)
```

### docker-compose.yml changes (diff)
```yaml
proxy-waf-custom:
    ports:
      - "8080:8080"   # ← REMOVE this line
      - "3000:3000"   # keep

proxy-waf:
    ports:
      - "8080:8080"   # ← ADD this line (expose directly)

waf-blocker:                           # ← NEW service
    build: ./services/waf-blocker
    volumes:
      - ./services/log-collector/signatures:/app/signatures:ro
    environment:
      - SIGNATURES_FILE=/app/signatures/modintel_regex.signatures
      - INFERENCE_URL=http://inference-engine:8083/predict-miss
      - BACKEND_URL=http://juice-shop:3000
      - BLOCK_THRESHOLD=0.85
    networks:
      - modintel-net
    restart: always
```

### proxy-waf/Caddyfile diff
```diff
  :8080 {
      header {
          X-Content-Type-Options nosniff
          X-Frame-Options DENY
          Referrer-Policy no-referrer
          Permissions-Policy geolocation=(), microphone=(), camera=()
      }

+     log {
+         output file /var/log/caddy/waf-access.json
+         format json
+     }
+     log_append captured_body "{http.request.body}"

      coraza_waf { ... }

-     reverse_proxy juice-shop:3000 {
+     reverse_proxy waf-blocker:8086 {
          trusted_proxies private_ranges
      }
  }
```

### proxy-waf-custom/Caddyfile change
```diff
- :8080 {
-     log {
-         output file /var/log/caddy/waf-access.json
-         format json
-     }
-     log_append captured_body "{http.request.body}"
-     reverse_proxy proxy-waf:8080 {
-         trusted_proxies private_ranges
-     }
- }

  :3000 { ... }  # keep unchanged
```

## Edge Cases Handled

| Case | Behavior |
|------|----------|
| Inference engine down | Fail-open: allow request through |
| Regex signatures file missing | Startup error, container won't start |
| Large request body | Buffered in memory (no size limit enforced) |
| WebSocket | Passthrough without buffering |
| Chunked transfer encoding | Handled by Go's httputil.ReverseProxy |
| Backend (juice-shop) down | 502 Bad Gateway from waf-blocker |
| ML score = 0.85 exactly | Blocked (>= threshold) |

## Verification

1. `docker compose build waf-blocker` — builds successfully
2. `docker compose up -d` — all services start
3. Test attack → `curl http://localhost:8080/?q=1' OR '1'='1` → blocked at Layer 1 (Coraza)
4. Test borderline attack → `curl -X POST http://localhost:8080/ -H "Content-Type: application/json" -d '{"q": "1 OR 1=1"}'` → may pass Layer 1, then waf-blocker checks
5. Test benign → `curl http://localhost:8080/` → passes through to juice-shop
6. Check `docker compose logs waf-blocker` → logs show "BLOCKED" or "ALLOWED" decisions
