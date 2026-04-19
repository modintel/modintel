<div align="center">
  <h1><img src="docs/assets/logo.svg" width="23" height="21" /> Modintel</h1>
  
  <div>
  <img src="https://img.shields.io/badge/Engine-Go-00ADD8?style=flat&logo=go&logoColor=white&labelColor=333" />
  <img src="https://img.shields.io/badge/Model-Python-3776AB?style=flat&logo=python&logoColor=white&labelColor=333" />
  <img src="https://img.shields.io/badge/Database-MongoDB-47A248?style=flat&logo=mongodb&logoColor=white&labelColor=333" />
  <img src="https://img.shields.io/badge/Proxy-Caddy-00A2D0?style=flat&logo=caddy&logoColor=white&labelColor=333" />
  <img src="https://img.shields.io/badge/Infra-Docker-2496ED?style=flat&logo=docker&logoColor=white&labelColor=333" />
  </div>
  
  <br />

<b>Modintel</b> is a hybrid Web Application Firewall (WAF) research system designed to reduce false positives in rule-based WAFs using Machine Learning. 

It functions as an intelligence layer that sits alongside the OWASP Core Rule Set (CRS) running on Coraza. 

  <br/>

  <img src="docs/assets/dashboard.png" width="100%" />

</div>

## Architectural Philosophy

Rule-based systems are excellent at catching known attacks, but struggle with nuance, leading to high false-positive rates. Machine learning excels at nuance, but is dangerous if allowed to block traffic blindly without explicit rules.

ModIntel combines both:
**Rules detect (catch known attacks) → ML judges (handles nuance) → Humans verify (edge cases).**


### Traffic Flow

1. Incoming requests hit Caddy then pass through Coraza WAF with OWASP CRS + 31 custom rules
2. Coraza writes audit events to `/var/log/coraza/audit.json`
3. **Log Collector** tails the audit log, extracts features, and sends them to the **Inference Engine**
4. Inference Engine returns an advisory prediction (attack probability, confidence, SHAP explanations, priority band)
5. Log Collector enriches the alert document and upserts it into **MongoDB**
6. **Review API** serves alerts, rules, stats, and WAF management endpoints to the **Dashboard**
7. **Auth Service** handles login, JWT tokens, sessions, and RBAC
8. **Health Aggregator** continuously probes all services and streams Docker events


## Dashboard

A 10-page interface served statically via Caddy:

| Route | Purpose |
|-------|---------|
| `/signin` | JWT-based authentication |
| `/events` | Alert list with AI enrichment data |
| `/rules` | WAF rule browser and management |
| `/monitor` | Real-time service health monitoring |
| `/training` | ML model training interface |
| `/datasets` | Dataset management |
| `/reports` | Evaluation report viewer |
| `/settings` | System configuration |
| `/help` | Documentation |

## Directory Structure

```text
modintel/
├── proxy-waf/                 # Caddy + Coraza WAF configuration
│   ├── Caddyfile              # Reverse proxy, routing, dashboard hosting
│   ├── coraza.conf            # Coraza WAF base config
│   ├── custom_rules.conf      # 31 custom SecRules
│   └── overrides/             # Managed overrides (runtime rule disabling)
├── services/
│   ├── auth-service/          # Go — JWT auth, RBAC, session management
│   ├── review-api/            # Go — Alert/rule/stats CRUD API
│   ├── log-collector/         # Go — Coraza log tailing + AI enrichment
│   ├── inference-engine/      # Python/FastAPI — ML inference serving
│   ├── health-aggregator/     # Go — Service health aggregation
│   └── proxy-waf-custom/      # Custom Caddy Docker build
├── ml-pipeline/               # Python — Training, evaluation, datasets
│   ├── feature_extractor.py   # WAFFeatureExtractor (sklearn transformer)
│   ├── train_model.py         # Multi-model training + calibration
│   ├── evaluate_model.py      # Evaluation report generator (HTML)
│   ├── feature_schema.json    # Feature contract (v1.0.0)
│   └── tests/                 # pytest test suite
├── models/
│   ├── v1/                    # Model version 1
│   ├── v2/                    # Model version 2
│   └── v3/                    # Model version 3 (current)
├── dashboard/                 # Static HTML/CSS/JS admin dashboard
├── scripts/                   # Commit hooks and attack testing suite
├── docs/                      # SRS, SDS, AI plan, auth guide
├── .github/workflows/         # CI/CD pipelines (lint, test, e2e, docker, codeql)
├── docker-compose.yml         # Full 8-service orchestration
├── lefthook.yml               # Git commit hooks
├── todo.md                    # Scalability roadmap
└── .env.example               # Environment variable template
```

## Technology Stack

- **Reverse Proxy**: Caddy
- **WAF Engine**: Coraza (OWASP CRS)
- **Backend Services**: Go (Gin framework)
- **ML Inference**: Python (FastAPI, scikit-learn, SHAP)
- **ML Training**: XGBoost, LightGBM, Random Forest, Logistic Regression
- **Database**: MongoDB
- **Dashboard**: HTML/CSS/JS (static, served via Caddy)
- **Orchestration**: Docker Compose (8 services)

## CI/CD

7 GitHub Actions workflows on the `modintel-base` branch:

| Workflow | Description |
|----------|-------------|
| **Lint** | Go lint (golangci-lint), Python lint (ruff), YAML lint, format checks |
| **Test** | Go tests (race detector, Go 1.22/1.23/1.26), Python tests (3.11/3.12), build verification |
| **E2E** | Docker Compose build, start, health check, integration test |
| **Docker** | Docker image builds |
| **CodeQL** | Security analysis |
| **Link Check** | Documentation link validation |

## Development Setup

### Prerequisites
- Go 1.22+
- Python 3.11+
- Docker & Docker Compose
- Node.js & npm (for commit hooks)

### Quick Start

```bash
cp .env.example .env
docker compose up -d
```

The WAF proxy will be available at `http://localhost:8080` and the dashboard at `http://localhost:3000`.

### Commit Hooks
This project uses [lefthook](https://github.com/evilmartians/lefthook) for commit validation.

```bash
npm install
npx lefthook install
```

### Attack Testing

Run the 47-payload attack suite against the WAF:

```powershell
.\scripts\attack_suite.ps1 -RunCount 1
```

## Roadmap

See [todo.md](todo.md) and open GitHub issues (#14–#21):

- **#14** Connection Pooling & Timeouts
- **#15** Cursor and Offset-based Pagination
- **#16** Distributed Caching with Redis
- **#17** Asynchronous Buffered Logging
- **#18** Dashboard Access Control Hardening
- **#19** Unified Error Handling & Crash Recovery
- **#20** Rule Management Refactor
- **#21** Real-Time Alerts with WebSocket

## License

This project is licensed under the MIT License.
