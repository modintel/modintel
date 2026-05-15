package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"modintel.local/log-collector/db"
)

var mongoAvailable bool

func init() {
	mongoURI := os.Getenv("MONGO_URI")

	if mongoURI != "" {
		db.Connect()
		mongoAvailable = true
	}
}

func TestHandleMetrics(t *testing.T) {
	logsProcessedTotal = 25
	logsEnrichedTotal = 10

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(handleMetrics)
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	expectedContentType := "text/plain; version=0.0.4"

	if res.Header.Get("Content-Type") != expectedContentType {
		t.Errorf(
			"expected content type %s, got %s",
			expectedContentType,
			res.Header.Get("Content-Type"),
		)
	}

	body := rec.Body.String()

	if !strings.Contains(body, "modintel_logs_processed_total 25") {
		t.Error("processed metric missing")
	}

	if !strings.Contains(body, "modintel_logs_enriched_total 10") {
		t.Error("enriched metric missing")
	}
}

func TestHandleHealth(t *testing.T) {
	if !mongoAvailable {
		t.Skip("Skipping MongoDB integration test: MONGO_URI not set")
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(handleHealth)
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK &&
		res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unexpected status code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf(
			"expected application/json, got %s",
			res.Header.Get("Content-Type"),
		)
	}

	var response map[string]string

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["service"] != "log-collector" {
		t.Errorf(
			"expected service log-collector, got %s",
			response["service"],
		)
	}
}

func TestHandleStats(t *testing.T) {
	if !mongoAvailable {
		t.Skip("Skipping MongoDB integration test: MONGO_URI not set")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(handleStats)
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK &&
		res.StatusCode != http.StatusInternalServerError {
		t.Errorf("unexpected status code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf(
			"expected application/json, got %s",
			res.Header.Get("Content-Type"),
		)
	}

	if res.StatusCode == http.StatusOK {
		var response map[string]interface{}

		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if _, ok := response["total_alerts"]; !ok {
			t.Error("missing total_alerts")
		}

		if _, ok := response["latest_rule"]; !ok {
			t.Error("missing latest_rule")
		}
	}
}

func TestHandleLogs(t *testing.T) {
	if !mongoAvailable {
		t.Skip("Skipping MongoDB integration test: MONGO_URI not set")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	rec := httptest.NewRecorder()

	handler := http.HandlerFunc(handleLogs)
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK &&
		res.StatusCode != http.StatusInternalServerError {
		t.Errorf("unexpected status code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf(
			"expected application/json, got %s",
			res.Header.Get("Content-Type"),
		)
	}

	if res.StatusCode == http.StatusOK {
		var response map[string]interface{}

		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if _, ok := response["alerts"]; !ok {
			t.Error("missing alerts field")
		}
	}
}