package middleware

import (
	"context"
	"errors"
	"strings"

	"go.mongodb.org/mongo-driver/mongo"
)

// Common error mappings for sanitization
var errorMappings = map[error]string{
	mongo.ErrNoDocuments:        "Resource not found",
	context.DeadlineExceeded:    "Request timeout",
	context.Canceled:            "Request canceled",
	mongo.ErrClientDisconnected: "Service temporarily unavailable",
}

// SanitizeError converts internal errors to client-safe messages
func SanitizeError(err error) (int, string) {
	if err == nil {
		return 500, "Internal server error"
	}
	
	// Check for exact error matches
	for knownErr, message := range errorMappings {
		if errors.Is(err, knownErr) {
			return mapErrorToStatusCode(knownErr), message
		}
	}
	
	// Check for MongoDB errors
	if mongo.IsDuplicateKeyError(err) {
		return 409, "Resource already exists"
	}
	if mongo.IsNetworkError(err) || mongo.IsTimeout(err) {
		return 503, "Service temporarily unavailable"
	}
	
	// Check for context errors
	if errors.Is(err, context.DeadlineExceeded) {
		return 503, "Request timeout"
	}
	if errors.Is(err, context.Canceled) {
		return 499, "Request canceled"
	}
	
	// Check for sensitive patterns in error message
	errMsg := err.Error()
	if containsSensitivePattern(errMsg) {
		return 500, "Internal server error"
	}
	
	// Default to generic error
	return 500, "Internal server error"
}

// mapErrorToStatusCode maps known errors to HTTP status codes
func mapErrorToStatusCode(err error) int {
	switch err {
	case mongo.ErrNoDocuments:
		return 404
	case context.DeadlineExceeded:
		return 503
	case context.Canceled:
		return 499
	case mongo.ErrClientDisconnected:
		return 503
	default:
		return 500
	}
}

// containsSensitivePattern checks if error message contains sensitive information
func containsSensitivePattern(msg string) bool {
	lowerMsg := strings.ToLower(msg)
	
	// Database error patterns
	sensitivePatterns := []string{
		"duplicate key",
		"constraint",
		"foreign key",
		"syntax error",
		"table",
		"column",
		"database",
		"mongodb",
		"redis",
		"sql",
		// File path patterns
		"/var/",
		"/etc/",
		"/usr/",
		"/home/",
		"c:\\",
		"\\windows\\",
		// Stack trace patterns
		"goroutine",
		"panic:",
		"runtime.",
		"at line",
		"traceback",
		// Environment patterns
		"env",
		"password",
		"secret",
		"token",
		"api_key",
	}
	
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerMsg, pattern) {
			return true
		}
	}
	
	return false
}

// SanitizedErrorResponse sends a sanitized error response
func SanitizedErrorResponse(c interface{}, err error) {
	// This will be implemented when integrating with Gin
	// For now, it's a placeholder that can be used by handlers
}
