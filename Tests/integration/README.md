# Integration Tests

Tests that verify interactions between multiple components.

## Structure
- `go/`          → Go service integration (auth + review-api + DB)
- `python/`      → Python/ML integration
- `api/`         → API contract + end-to-end flows
- `e2e/`         → Full system with Docker Compose (in `system/`)

## How to Run
```bash
# All integration tests
pytest tests/integration -v

# Go integration tests
go test ./tests/integration/go -v