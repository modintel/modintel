package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// Logger wraps stdlib log with structured JSON output
type Logger struct {
	Logger      *log.Logger
	serviceName string
	requestID   string
	fields      map[string]interface{}
}

// New creates a new structured JSON logger
func New(serviceName string) *Logger {
	return &Logger{
		Logger:      log.New(os.Stdout, "", 0),
		serviceName: serviceName,
		fields:      map[string]interface{}{"service": serviceName},
	}
}

func (l *Logger) log(level, msg string, extra map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"message":   msg,
		"service":   l.serviceName,
	}
	if l.requestID != "" {
		entry["request_id"] = l.requestID
	}
	for k, v := range l.fields {
		entry[k] = v
	}
	for k, v := range extra {
		entry[k] = v
	}
	b, _ := json.Marshal(entry)
	l.Logger.Println(string(b))
}

// WithRequestID creates a new logger with the request_id field
func (l *Logger) WithRequestID(requestID string) *Logger {
	newFields := make(map[string]interface{}, len(l.fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	return &Logger{
		Logger:      l.Logger,
		serviceName: l.serviceName,
		requestID:   requestID,
		fields:      newFields,
	}
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	extra := argsToMap(args...)
	l.log("info", msg, extra)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...interface{}) {
	extra := argsToMap(args...)
	l.log("error", msg, extra)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	extra := argsToMap(args...)
	l.log("warn", msg, extra)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	extra := argsToMap(args...)
	l.log("debug", msg, extra)
}

// LogRequest logs an HTTP request with standard fields
func (l *Logger) LogRequest(method, path string, statusCode int, durationMs int64) {
	l.log("info", "Request processed", map[string]interface{}{
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": durationMs,
	})
}

// LogRequestWithError logs an HTTP request that resulted in an error
func (l *Logger) LogRequestWithError(method, path string, statusCode int, durationMs int64, err error) {
	l.log("error", "Request failed", map[string]interface{}{
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": durationMs,
		"error":       fmt.Sprintf("%v", err),
	})
}

// GetServiceName returns the service name
func (l *Logger) GetServiceName() string {
	return l.serviceName
}

// GetRequestID returns the request ID if set
func (l *Logger) GetRequestID() string {
	return l.requestID
}

// Sync is a no-op for stdlib logger (satisfies interface compatibility)
func (l *Logger) Sync() error {
	return nil
}

// LogCircuitBreakerStateChange logs circuit breaker state transitions
func (l *Logger) LogCircuitBreakerStateChange(dependency, oldState, newState string, failureCount int) {
	level := "info"
	if newState == "Open" {
		level = "warn"
	}
	l.log(level, "Circuit breaker state changed", map[string]interface{}{
		"dependency":    dependency,
		"old_state":     oldState,
		"new_state":     newState,
		"failure_count": failureCount,
	})
}

// LogRetryAttempt logs a retry attempt
func (l *Logger) LogRetryAttempt(operation string, attempt, maxAttempts int, elapsedMs int64, err error) {
	l.log("debug", "Retry attempt", map[string]interface{}{
		"operation":    operation,
		"attempt":      attempt,
		"max_attempts": maxAttempts,
		"elapsed_ms":   elapsedMs,
		"error":        fmt.Sprintf("%v", err),
	})
}

// LogRetryExhausted logs when all retries are exhausted
func (l *Logger) LogRetryExhausted(operation string, totalAttempts int, totalElapsedMs int64, lastErr error) {
	l.log("error", "All retries exhausted", map[string]interface{}{
		"operation":        operation,
		"total_attempts":   totalAttempts,
		"total_elapsed_ms": totalElapsedMs,
		"error":            fmt.Sprintf("%v", lastErr),
	})
}

// argsToMap converts variadic key-value pairs to a map
func argsToMap(args ...interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for i := 0; i+1 < len(args); i += 2 {
		if key, ok := args[i].(string); ok {
			m[key] = args[i+1]
		}
	}
	return m
}
