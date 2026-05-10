package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// State represents the circuit breaker state
type State int32

const (
	// StateClosed means the circuit breaker is closed (normal operation)
	StateClosed State = iota
	// StateOpen means the circuit breaker is open (failing fast)
	StateOpen
	// StateHalfOpen means the circuit breaker is half-open (testing with probe)
	StateHalfOpen
)

// String returns the string representation of the state
func (s State) String() string {
	switch s {
	case StateClosed:
		return "Closed"
	case StateOpen:
		return "Open"
	case StateHalfOpen:
		return "HalfOpen"
	default:
		return "Unknown"
	}
}

var (
	// ErrCircuitBreakerOpen is returned when the circuit breaker is open
	ErrCircuitBreakerOpen = errors.New("circuit breaker is open")
	// ErrTooManyRequests is returned when too many requests are made in half-open state
	ErrTooManyRequests = errors.New("too many requests in half-open state")
)

// CircuitBreakerMetrics holds metrics about the circuit breaker
type CircuitBreakerMetrics struct {
	State            State
	FailureCount     int
	SuccessCount     int
	LastFailureTime  time.Time
	LastStateChange  time.Time
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name          string
	maxFailures   int
	timeout       time.Duration
	halfOpenMax   int
	
	state         atomic.Int32
	failureCount  atomic.Int32
	successCount  atomic.Int32
	lastFailure   atomic.Int64 // Unix timestamp in nanoseconds
	lastStateChange atomic.Int64 // Unix timestamp in nanoseconds
	halfOpenCount atomic.Int32
	
	mu            sync.Mutex
	stateListeners []func(oldState, newState State)
}

// New creates a new circuit breaker
func New(name string, maxFailures int, timeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:          name,
		maxFailures:   maxFailures,
		timeout:       timeout,
		halfOpenMax:   1, // Allow only 1 probe request in half-open state
		stateListeners: make([]func(oldState, newState State), 0),
	}
	cb.state.Store(int32(StateClosed))
	cb.lastStateChange.Store(time.Now().UnixNano())
	return cb
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	// Check if context is already canceled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	
	// Get current state
	currentState := State(cb.state.Load())
	
	switch currentState {
	case StateClosed:
		// Normal operation - execute function
		return cb.executeInClosed(fn)
		
	case StateOpen:
		// Check if timeout has elapsed
		if cb.shouldTransitionToHalfOpen() {
			cb.transitionTo(StateHalfOpen)
			return cb.executeInHalfOpen(fn)
		}
		// Still open - fail fast
		return ErrCircuitBreakerOpen
		
	case StateHalfOpen:
		// Allow limited probe requests
		return cb.executeInHalfOpen(fn)
		
	default:
		return errors.New("unknown circuit breaker state")
	}
}

// executeInClosed executes function in closed state
func (cb *CircuitBreaker) executeInClosed(fn func() error) error {
	err := fn()
	
	if err != nil {
		// Increment failure count
		failures := int(cb.failureCount.Add(1))
		cb.lastFailure.Store(time.Now().UnixNano())
		
		// Check if we should transition to open
		if failures >= cb.maxFailures {
			cb.transitionTo(StateOpen)
		}
		
		return err
	}
	
	// Success - reset failure count
	cb.failureCount.Store(0)
	cb.successCount.Add(1)
	return nil
}

// executeInHalfOpen executes function in half-open state
func (cb *CircuitBreaker) executeInHalfOpen(fn func() error) error {
	// Check if we can allow this request
	halfOpenCount := cb.halfOpenCount.Add(1)
	if halfOpenCount > int32(cb.halfOpenMax) {
		cb.halfOpenCount.Add(-1)
		return ErrTooManyRequests
	}
	
	defer cb.halfOpenCount.Add(-1)
	
	err := fn()
	
	if err != nil {
		// Probe failed - transition back to open
		cb.failureCount.Add(1)
		cb.lastFailure.Store(time.Now().UnixNano())
		cb.transitionTo(StateOpen)
		return err
	}
	
	// Probe succeeded - transition to closed
	cb.failureCount.Store(0)
	cb.successCount.Add(1)
	cb.transitionTo(StateClosed)
	return nil
}

// shouldTransitionToHalfOpen checks if enough time has elapsed to transition to half-open
func (cb *CircuitBreaker) shouldTransitionToHalfOpen() bool {
	lastChange := time.Unix(0, cb.lastStateChange.Load())
	return time.Since(lastChange) >= cb.timeout
}

// transitionTo transitions the circuit breaker to a new state
func (cb *CircuitBreaker) transitionTo(newState State) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	oldState := State(cb.state.Load())
	if oldState == newState {
		return
	}
	
	// Update state
	cb.state.Store(int32(newState))
	cb.lastStateChange.Store(time.Now().UnixNano())
	
	// Reset half-open counter when transitioning
	if newState == StateHalfOpen {
		cb.halfOpenCount.Store(0)
	}
	
	// Notify listeners
	for _, listener := range cb.stateListeners {
		listener(oldState, newState)
	}
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() State {
	return State(cb.state.Load())
}

// GetMetrics returns current metrics
func (cb *CircuitBreaker) GetMetrics() CircuitBreakerMetrics {
	return CircuitBreakerMetrics{
		State:           State(cb.state.Load()),
		FailureCount:    int(cb.failureCount.Load()),
		SuccessCount:    int(cb.successCount.Load()),
		LastFailureTime: time.Unix(0, cb.lastFailure.Load()),
		LastStateChange: time.Unix(0, cb.lastStateChange.Load()),
	}
}

// GetName returns the circuit breaker name
func (cb *CircuitBreaker) GetName() string {
	return cb.name
}

// OnStateChange registers a listener for state changes
func (cb *CircuitBreaker) OnStateChange(listener func(oldState, newState State)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.stateListeners = append(cb.stateListeners, listener)
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.halfOpenCount.Store(0)
	cb.transitionTo(StateClosed)
}
