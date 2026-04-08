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