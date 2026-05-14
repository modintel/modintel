package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAggregator(t *testing.T) {
	agg := newAggregator("modintel")

	if len(agg.services) != 5 {
		t.Errorf("Expected 5 services, got %d", len(agg.services))
	}
}

func TestAggregator_SetAndSnapshot(t *testing.T) {
	agg := newAggregator("modintel")

	agg.set("review-api", "ok", "probe", "healthy")
	agg.set("inference-engine", "down", "docker-event", "die")

	snapshot := agg.snapshot()

	if snapshot["review-api"].Status != "ok" {
		t.Error("review-api status not updated correctly")
	}
	if snapshot["inference-engine"].Status != "down" {
		t.Error("inference-engine status not updated correctly")
	}
}

func TestApplyEvent(t *testing.T) {
	agg := newAggregator("modintel")

	testCases := []struct {
		action string
		want   string
	}{
		{"die", "down"},
		{"stop", "down"},
		{"start", "restarting"},
		{"health_status: healthy", "ok"},
		{"health_status: unhealthy", "down"},
	}

	for _, tc := range testCases {
		t.Run(tc.action, func(t *testing.T) {
			agg.set("review-api", "unknown", "init", "")
			agg.applyEvent("review-api", tc.action)

			snap := agg.snapshot()
			if snap["review-api"].Status != tc.want {
				t.Errorf("Expected status %s, got %s", tc.want, snap["review-api"].Status)
			}
		})
	}
}

func TestHandleHealth(t *testing.T) {
	agg := newAggregator("modintel")
	agg.set("review-api", "ok", "probe", "")

	req := httptest.NewRequest(http.MethodGet, "/aggregate/health", nil)
	rec := httptest.NewRecorder()

	agg.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if _, ok := resp["services"]; !ok {
		t.Error("Response should contain 'services' field")
	}
}

func TestHandleDetailed(t *testing.T) {
	agg := newAggregator("modintel")

	req := httptest.NewRequest(http.MethodGet, "/aggregate/health/detailed", nil)
	rec := httptest.NewRecorder()

	agg.handleDetailed(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}