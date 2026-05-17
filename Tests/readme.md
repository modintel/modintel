# ModIntel Test Commands

This document contains the commands to run the unit, integration, and system (End-to-End) tests for the ModIntel repository. Ensure you run these commands from the root directory of the project.

## 1. Unit Tests

Unit tests focus on individual components and functions.

### Go Services

**Log Collector:**
```bash
cd services/log-collector
go test -v -race ./...
```

**Review API:**
```bash
cd services/review-api
go test -v -race ./...
```

### Python Services

**Inference Engine:**
```bash
cd services/inference-engine
pytest -v
```

**ML Pipeline:**
```bash
cd ml-pipeline
pytest -v tests/
```

---

## 2. Integration Tests

Integration tests verify interactions between multiple components and are located under the `Tests/integration` folder.

**All Python Integration Tests (API & ML integration):**
```bash
pytest Tests/integration -v
```

**Go Integration Tests:**
```bash
cd Tests/integration
go test ./go/... -v
```

---

## 3. System / End-to-End Tests

System testing verifies the entire application stack by bringing up all services via Docker Compose and running test suites against them.

**Step 1: Configure the Environment**
Make sure you have an `.env` file configured in the root directory:
```bash
cp .env.example .env
```

**Step 2: Build and Start Services**
Build the Docker images and start the services in the background:
```bash
docker compose build --parallel
docker compose up -d
```
*(Wait a few seconds for the services to fully initialize, particularly the databases).*

**Step 3: Run the System Tests**
Run the dedicated test container defined in `docker-compose.yml`:
```bash
docker compose -f docker-compose.yml up --abort-on-container-exit test
```

**Step 4: Cleanup**
Once the tests finish, spin down the stack and remove orphans:
```bash
docker compose down --remove-orphans
```
