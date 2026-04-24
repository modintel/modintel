package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries int           // Maximum number of retry attempts
	BaseDelay  time.Duration // Base delay for exponential backoff
	MaxDelay   time.Duration // Maximum delay cap
	JitterPct  float64       // Jitter percentage (0.0 to 1.0)
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   5000 * time.Millisecond,
		JitterPct:  0.25,
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryMetrics holds metrics about retry attempts
type RetryMetrics struct {
	Attempt       int
	TotalAttempts int
	ElapsedTime   time.Duration
	LastError     error
}

// WithRetry executes a function with exponential backoff retry logic
func WithRetry(ctx context.Context, config RetryConfig, fn RetryableFunc) error {
	startTime := time.Now()
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Execute the function
		err := fn()
		
		// Success - return immediately
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !IsRetryable(err) {
			return err
		}
		
		// Last attempt - don't sleep, just return error
		if attempt == config.MaxRetries {
			return lastErr
		}
		
		// Calculate backoff delay
		delay := calculateBackoffDelay(attempt, config.BaseDelay, config.MaxDelay)
		
		// Add jitter
		delay = addJitter(delay, config.JitterPct)
		
		// Check context cancellation before sleeping
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	return lastErr
}

// calculateBackoffDelay calculates the exponential backoff delay
// Formula: min(baseDelay * 2^attempt, maxDelay)
func calculateBackoffDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	// Calculate exponential delay: baseDelay * 2^attempt
	multiplier := math.Pow(2, float64(attempt))
	delay := time.Duration(float64(baseDelay) * multiplier)
	
	// Cap at maxDelay
	if delay > maxDelay {
		delay = maxDelay
	}
	
	return delay
}

// addJitter adds random jitter to the delay
// Jitter range: [0, delay * jitterPct]
// Final delay range: [delay, delay * (1 + jitterPct)]
func addJitter(delay time.Duration, jitterPct float64) time.Duration {
	if jitterPct <= 0 {
		return delay
	}
	
	// Calculate maximum jitter
	maxJitter := float64(delay) * jitterPct
	
	// Generate random jitter between 0 and maxJitter
	jitter := time.Duration(rand.Float64() * maxJitter)
	
	return delay + jitter
}

// IsRetryable determines if an error should trigger a retry
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	
	// Context errors are not retryable
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	
	// Check for specific retryable error types
	// This can be extended based on specific error types
	errMsg := err.Error()
	
	// Network errors are typically retryable
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"network",
	}
	
	for _, pattern := range retryablePatterns {
		if contains(errMsg, pattern) {
			return true
		}
	}
	
	// Default to not retryable for safety
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// WithRetryMetrics executes a function with retry logic and returns metrics
func WithRetryMetrics(ctx context.Context, config RetryConfig, fn RetryableFunc) (RetryMetrics, error) {
	startTime := time.Now()
	var lastErr error
	metrics := RetryMetrics{
		TotalAttempts: config.MaxRetries + 1,
	}
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		metrics.Attempt = attempt + 1
		
		// Execute the function
		err := fn()
		
		// Success - return immediately
		if err == nil {
			metrics.ElapsedTime = time.Since(startTime)
			return metrics, nil
		}
		
		lastErr = err
		metrics.LastError = err
		
		// Check if error is retryable
		if !IsRetryable(err) {
			metrics.ElapsedTime = time.Since(startTime)
			return metrics, err
		}
		
		// Last attempt - don't sleep, just return error
		if attempt == config.MaxRetries {
			metrics.ElapsedTime = time.Since(startTime)
			return metrics, lastErr
		}
		
		// Calculate backoff delay
		delay := calculateBackoffDelay(attempt, config.BaseDelay, config.MaxDelay)
		
		// Add jitter
		delay = addJitter(delay, config.JitterPct)
		
		// Check context cancellation before sleeping
		select {
		case <-ctx.Done():
			metrics.ElapsedTime = time.Since(startTime)
			return metrics, ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	metrics.ElapsedTime = time.Since(startTime)
	return metrics, lastErr
}
