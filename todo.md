# Rule Toggle Feature - Implementation Plan

## Overview
Enable users to enable/disable individual WAF rules from the dashboard with persistent settings and WAF restart on changes.

## Requirements
- **Scope**: Individual rules (e.g., 942100, not categories)
- **Persistence**: Disabled rules persist across restarts
- **Application**: Changes require WAF restart

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────┐     ┌─────────┐
│  Dashboard  │────▶│ Review-API  │────▶│ MongoDB  │────▶│ Coraza  │
│  (rules.html)     │   (Go)      │     │          │     │   WAF   │
└─────────────┘     └─────────────┘     └──────────┘     └─────────┘
```

## Implementation Steps

### 1. Database (MongoDB)
- Create `rule_configs` collection with all 31 current rules
- Schema:
  ```json
  {
    "rule_id": "942100",
    "enabled": true,
    "category": "SQL Injection",
    "description": "SQL Injection Attack",
    "created_at": "2026-04-08T...",
    "updated_at": "2026-04-08T..."
  }
  ```

### 2. Backend (Review-API)
**New Endpoints:**
- `GET /api/rules` - List all rules with enabled status
- `PUT /api/rules/:rule_id` - Toggle rule on/off
- `POST /api/rules/apply` - Apply changes (triggers WAF restart)

### 3. Frontend (Dashboard)
- Add toggle switch for each rule
- Show visual status (green = enabled, gray = disabled)
- Add "Apply Changes" button that triggers WAF restart
- Add loading state during restart

### 4. WAF Integration
- Generate `custom_rules.conf` from enabled rules in MongoDB
- Disabled rules = `SecRuleRemoveById <rule_id>`
- Restart Coraza container after config update

## Testing Plan
1. Load rules page - verify all 31 rules display
2. Toggle rule off → verify MongoDB updates
3. Click Apply → verify WAF restarts
4. Send attack for disabled rule → verify passes through
5. Re-enable rule → verify blocks again

---

# WebSocket Real-Time Alerts - Implementation Plan

## Overview
Migrate from HTTP polling (2s interval) to WebSocket for sub-second latency on new AI-enriched alerts. The WebSocket bridges MongoDB (enriched logs) to the Dashboard via Review-API.

## Requirements
- **Latency**: Sub-second alert delivery to dashboard
- **Reliability**: Auto-reconnect on disconnect
- **Architecture**: MongoDB ←→ Review-API ←→ Dashboard (WebSocket)

## Current Flow
```
WAF → audit.json → log-collector (tails + AI enrichment) → MongoDB
                                                            ↓
Dashboard ← (HTTP poll 2s) ← Review-API ← (query) ← MongoDB
```

## Target Flow
```
WAF → audit.json → log-collector (tails + AI enrichment) → MongoDB
                                                            ↓
                                                    Review-API (watches)
                                                            ↓
Dashboard ← (WebSocket real-time) ← Review-API ← (broadcast)
```

## Architecture

```
┌─────────────┐                ┌─────────────┐                ┌──────────┐
│  Dashboard  │◄───WebSocket───►│ Review-API  │◄───watch─────►│ MongoDB  │
│  (index.js) │                │   (Go)      │                │(enriched)│
└─────────────┘                └─────────────┘                └──────────┘
                                      │
                                      ▲
                                      │ notify (fallback)
                               ┌───────────────┐
                               │ Log-Collector │
                               └───────────────┘
```

## Branch
- Branch from: `modintel-base`
- Branch name: `feat/websocket-realtime`

## Implementation Steps

### 1. Backend - Review-API (WebSocket Server)
- Add `gorilla/websocket` dependency
- Create WebSocket hub (`ws_hub.go`)
  - `Register(client)`
  - `Unregister(client)`
  - `Broadcast(message)`
- Add endpoint `GET /api/ws` - WebSocket upgrade for dashboard connections
- Add endpoint `POST /api/notify` - fallback for log-collector notifications

### 2. Backend - MongoDB Watcher
- **Option A** (preferred): MongoDB Change Stream - requires replica set
- **Option B** (fallback): Polling with timestamp-based queries
- **Option C** (hybrid): Log-collector POST notification + polling backup
- Watch `modintel.alerts` collection for new enriched documents
- Broadcast new alerts to all connected WebSocket clients

### 3. Backend - Log-Collector (Notification Fallback)
- After `collection.InsertOne()`, call `POST http://review-api:8082/api/notify`
- Payload: `{"alert_id": "...", "timestamp": "..."}`
- Non-blocking, fire-and-forget (ensures delivery even if watcher fails)

### 4. Frontend - Dashboard
- Replace `setInterval` polling with WebSocket connection
- Connect to `ws://host/api/ws`
- On message: render new alert directly to table (prepend)
- Handle reconnection with exponential backoff
- Show connection status indicator (connected/reconnecting/disconnected)
- Fallback to HTTP polling if WebSocket fails after 3 retries

### 5. Message Format
```json
{
  "type": "new_alert",
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

## Files Changed
| File | Changes |
|------|---------|
| `services/review-api/go.mod` | Add `gorilla/websocket` |
| `services/review-api/ws_hub.go` | New file - WebSocket hub |
| `services/review-api/watcher.go` | New file - MongoDB watcher |
| `services/review-api/main.go` | Initialize WebSocket hub |
| `services/review-api/api/handler.go` | Add `/ws` and `/notify` endpoints |
| `services/log-collector/main.go` | Add notify call after insert |
| `dashboard/js/index.js` | Replace polling with WebSocket |
| `dashboard/css/index.css` | Add connection status indicator styles |

## Dependencies
- `github.com/gorilla/websocket` (Go)
- Native WebSocket API (JS - no library needed)

## Testing Plan
1. Open dashboard → verify WebSocket connects (status: green)
2. Trigger WAF attack → verify alert appears in table <500ms
3. Check MongoDB → verify document has `ai_status: "enriched"`
4. Kill review-api → verify dashboard shows "disconnected" (status: red)
5. Restart review-api → verify dashboard reconnects automatically
6. Multiple browser tabs → verify all receive same alert simultaneously