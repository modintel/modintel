package api

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// AppLogger is a structured JSON logger backed by stdlib log.
type AppLogger struct {
	Logger      *log.Logger
	serviceName string
	requestID   string
}

// NewLogger creates a new AppLogger for the given service.
func NewLogger(serviceName string) *AppLogger {
	return &AppLogger{
		Logger:      log.New(os.Stdout, "", 0),
		serviceName: serviceName,
	}
}

// WithRequestID returns a copy of the logger with the request ID set.
func (l *AppLogger) WithRequestID(id string) *AppLogger {
	return &AppLogger{Logger: l.Logger, serviceName: l.serviceName, requestID: id}
}

func (l *AppLogger) emit(level, msg string, extra map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"service":   l.serviceName,
		"message":   msg,
	}
	if l.requestID != "" {
		entry["request_id"] = l.requestID
	}
	for k, v := range extra {
		entry[k] = v
	}
	b, _ := json.Marshal(entry)
	l.Logger.Println(string(b))
}

func (l *AppLogger) Info(msg string, kv ...interface{})  { l.emit("info", msg, kvToMap(kv...)) }
func (l *AppLogger) Warn(msg string, kv ...interface{})  { l.emit("warn", msg, kvToMap(kv...)) }
func (l *AppLogger) Error(msg string, kv ...interface{}) { l.emit("error", msg, kvToMap(kv...)) }

func (l *AppLogger) LogRequest(method, path string, status int, durationMs int64) {
	l.emit("info", "request", map[string]interface{}{
		"method": method, "path": path, "status": status, "duration_ms": durationMs,
	})
}

func (l *AppLogger) Sync() error { return nil }

func kvToMap(kv ...interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = fmt.Sprintf("%v", kv[i+1])
		}
	}
	return m
}
