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
Migrate from HTTP polling (2s interval) to WebSocket for sub-second latency on new alerts.

## Requirements
- **Latency**: Sub-second alert delivery to dashboard
- **Reliability**: Auto-reconnect on disconnect
- **Architecture**: HTTP notify from log-collector → review-api → WebSocket broadcast

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────┐┌───────────────┐
│  Dashboard  │◄───►│ Review-API  │◄─── notify ───│ Log-Collector │
│  (index.js) │     │   (Go)      │     │        │
└─────────────┘WebSocket          └──────────┘     └───────────────┘
                                        │
                                        ▼
                                   MongoDB
```

## Branch
- Branch from: `modintel-base`
- Branch name: `feat/websocket-realtime`

## Implementation Steps

### 1. Backend - Review-API
- Add `gorilla/websocket` dependency
- Create WebSocket hub (`ws_hub.go`)
  - `Register(client)`
  - `Unregister(client)`
  - `Broadcast(message)`
- Add endpoint `GET /api/ws` - WebSocket upgrade
- Add endpoint `POST /api/notify` - called by log-collector

### 2. Backend - Log-Collector
- After `collection.InsertOne()`, call `POST http://review-api:8082/api/notify`
- Payload: `{"alert_id": "...", "timestamp": "..."}`
- Non-blocking, fire-and-forget

### 3. Frontend - Dashboard
- Replace `setInterval` polling with WebSocket connection
- Connect to `ws://host/api/ws`
- On message: fetch latest alerts or render directly
- Handle reconnection with exponential backoff
- Show connection status indicator

### 4. Fallback
- If WebSocket fails, fall back to HTTP polling
- Connection status indicator in dashboard

## Files Changed
| File | Changes |
|------|---------|
| `services/review-api/go.mod` | Add `gorilla/websocket` |
| `services/review-api/ws_hub.go` | New file - WebSocket hub |
| `services/review-api/main.go` | Initialize WebSocket hub |
| `services/review-api/api/handler.go` | Add `/ws` and `/notify` endpoints |
| `services/log-collector/main.go` | Add notify call after insert |
| `dashboard/js/index.js` | Replace polling with WebSocket |

## Dependencies
- `github.com/gorilla/websocket` (Go)
- Native WebSocket API (JS - no library needed)

## Testing Plan
1. Open dashboard → verify WebSocket connects
2. Trigger WAF alert → verify appears in <500ms
3. Disconnect network → verify reconnection
4. Multiple tabs open → verify all receive alerts
5. Kill review-api → verify dashboard shows "disconnected"