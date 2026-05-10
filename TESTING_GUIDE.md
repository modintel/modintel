# Unified Reliability Model - Testing Guide

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- PowerShell (for test scripts)
- ModIntel services running

### Start Services
```bash
cd modintel
docker-compose up --build -d
```

Wait for services to be healthy:
```bash
docker-compose ps
```

## Automated Testing

### Run Reliability Test Suite
```powershell
cd modintel
./scripts/test_reliability.ps1
```

**Tests Included**:
1. ✅ Health Check - Basic connectivity
2. ✅ Readiness Check - Dependency health verification
3. ✅ Response Envelope Format - Standard response structure
4. ✅ Request ID Preservation - Custom Request ID handling
5. ✅ Request ID Generation - Automatic UUID generation
6. ✅ CORS Headers - X-Request-ID exposure

**Expected Output**:
```
========================================
Unified Reliability Model Test Suite
========================================

=== Testing: Health Check ===
✓ Passed

=== Testing: Readiness Check ===
  Status: ready
  Checks: {"mongodb":"ok"}
✓ Passed

=== Testing: Response Envelope Format ===
  X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
✓ Passed

=== Testing: Request ID Preservation ===
  Request ID preserved: 12345678-1234-1234-1234-123456789012
✓ Passed

=== Testing: Request ID Generation ===
  Generated Request ID: 9b7d8c3a-2f1e-4d5c-8a6b-1e3f5d7c9a2b
✓ Passed

=== Testing: CORS Headers for X-Request-ID ===
  X-Request-ID properly exposed in CORS
✓ Passed

========================================
Test Summary
========================================
Passed: 6
Failed: 0

✓ All tests passed!
```

## Manual Testing

### 1. Test Request ID Propagation

**Send request with custom Request ID**:
```bash
curl -H "X-Request-ID: test-request-123" \
     http://localhost:3000/health \
     -v
```

**Expected**:
- Response header contains `X-Request-ID: test-request-123`
- Same Request ID appears in logs

**Verify in logs**:
```bash
docker-compose logs review-api | grep "test-request-123"
```

### 2. Test Request ID Generation

**Send request without Request ID**:
```bash
curl http://localhost:3000/health -v
```

**Expected**:
- Response header contains `X-Request-ID` with a valid UUID
- Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 3. Test Readiness Endpoint

**Check service readiness**:
```bash
curl http://localhost:3000/health/ready
```

**Expected (Healthy)**:
```json
{
  "status": "ready",
  "checks": {
    "mongodb": "ok"
  }
}
```

**Expected (Unhealthy - MongoDB down)**:
```json
{
  "status": "not_ready",
  "failed_dependencies": ["mongodb"],
  "checks": {
    "mongodb": "down"
  }
}
```

**Test with MongoDB down**:
```bash
# Stop MongoDB
docker-compose stop mongodb

# Check readiness
curl http://localhost:3000/health/ready

# Restart MongoDB
docker-compose start mongodb
```

### 4. Test Panic Recovery

**Trigger a panic** (requires code modification for testing):

Add a test endpoint in `handler.go`:
```go
r.GET("/test/panic", func(c *gin.Context) {
    panic("test panic")
})
```

**Send request**:
```bash
curl http://localhost:3000/test/panic
```

**Expected**:
- HTTP 500 response
- Sanitized error message (no stack trace)
- Service continues running
- Full stack trace in logs with Request ID

**Verify service is still running**:
```bash
curl http://localhost:3000/health
```

### 5. Test Structured Logging

**Check log format**:
```bash
docker-compose logs review-api --tail=50
```

**Expected log entry format**:
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "info",
  "service": "review-api",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Starting Review API",
  "port": "8082"
}
```

**Verify Request ID in logs**:
```bash
# Send request with custom ID
curl -H "X-Request-ID: log-test-123" http://localhost:3000/health

# Check logs
docker-compose logs review-api | grep "log-test-123"
```

### 6. Test Graceful Shutdown

**Test graceful shutdown**:
```bash
# Start service
docker-compose up review-api -d

# Send SIGTERM
docker-compose stop review-api

# Check logs for graceful shutdown
docker-compose logs review-api --tail=20
```

**Expected log messages**:
```
Shutdown signal received, initiating graceful shutdown
Graceful shutdown completed successfully
```

**Test with in-flight requests**:
```bash
# Start service
docker-compose up review-api -d

# Send long-running request in background
curl http://localhost:3000/api/logs &

# Immediately send SIGTERM
docker-compose stop review-api

# Check if request completed before shutdown
```

### 7. Test Error Sanitization

**Test database error sanitization**:
```bash
# Stop MongoDB
docker-compose stop mongodb

# Try to access API
curl http://localhost:3000/api/stats
```

**Expected**:
- HTTP 503 response
- Sanitized message: "Service temporarily unavailable"
- NO database error details in response
- Full error details in logs

**Restart MongoDB**:
```bash
docker-compose start mongodb
```

## Integration Testing

### Test End-to-End Request Flow

**1. Send authenticated request**:
```bash
# Get JWT token (replace with actual auth endpoint)
TOKEN="your-jwt-token"

# Send request with custom Request ID
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Request-ID: e2e-test-123" \
     http://localhost:3000/api/alerts
```

**2. Verify Request ID propagation**:
```bash
# Check review-api logs
docker-compose logs review-api | grep "e2e-test-123"

# Check if Request ID appears in all log entries for this request
```

### Test Concurrent Requests

**Send multiple concurrent requests**:
```bash
for i in {1..10}; do
  curl -H "X-Request-ID: concurrent-$i" \
       http://localhost:3000/health &
done
wait
```

**Verify**:
- All requests complete successfully
- Each has unique Request ID in logs
- No race conditions or crashes

## Performance Testing

### Test Response Time Impact

**Baseline (without middleware)**:
```bash
time curl http://localhost:3000/health
```

**With reliability middleware**:
```bash
time curl http://localhost:3000/health
```

**Expected overhead**: <1ms per request

### Load Test

**Using Apache Bench**:
```bash
ab -n 1000 -c 10 http://localhost:3000/health
```

**Expected**:
- No failures
- Consistent response times
- All requests have Request IDs

## Troubleshooting

### Issue: Tests fail with "connection refused"
**Solution**: Ensure services are running
```bash
docker-compose ps
docker-compose up -d
```

### Issue: Request ID not in response headers
**Solution**: Check middleware order in `SetupRouter()`
```go
r.Use(middleware.EnvelopeMiddleware())  // Must be first
r.Use(middleware.PanicRecoveryMiddleware(lgr.Logger))
```

### Issue: Readiness endpoint returns 503
**Solution**: Check MongoDB connection
```bash
docker-compose logs mongodb
docker-compose restart mongodb
```

### Issue: Logs not in JSON format
**Solution**: Check logger initialization
```go
appLogger := logger.New("review-api")
```

### Issue: Graceful shutdown timeout
**Solution**: Check for slow requests or increase timeout
```bash
# Check for slow queries
docker-compose logs review-api | grep "duration_ms"

# Increase timeout in .env
SHUTDOWN_TIMEOUT_SECONDS=60
```

## Verification Checklist

Before marking implementation complete, verify:

- [ ] All automated tests pass
- [ ] Request ID appears in all responses
- [ ] Request ID preserved when provided
- [ ] Request ID generated when missing
- [ ] Readiness endpoint returns correct status
- [ ] Panic recovery works (service doesn't crash)
- [ ] Logs are in JSON format
- [ ] Logs include Request ID
- [ ] Graceful shutdown completes within timeout
- [ ] Error messages are sanitized
- [ ] CORS headers include X-Request-ID
- [ ] Service starts successfully
- [ ] No performance degradation

## Next Steps

After basic testing:

1. **Load Testing**: Test under high load
2. **Chaos Testing**: Test with dependency failures
3. **Integration Testing**: Test across all services
4. **Property-Based Testing**: Add property tests
5. **Monitoring**: Set up metrics and alerts

## Support

For issues or questions:
- Check logs: `docker-compose logs review-api`
- Review implementation: `RELIABILITY_IMPLEMENTATION.md`
- Check design: `.kiro/specs/unified-reliability-model/design.md`
