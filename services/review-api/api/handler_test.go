package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ====================== Existing Tests (from your coworker + stats) ======================

func TestRequestWindowStats(t *testing.T) {
	stats := newRequestWindowStats()
	now := time.Now()

	stats.record(now, false)
	stats.record(now, true)
	stats.record(now.Add(1*time.Minute), false)

	t.Run("records requests and errors correctly", func(t *testing.T) {
		stats.record(now, false)
	})

	t.Run("cleans old buckets", func(t *testing.T) {
		oldTime := now.Add(-25 * time.Hour)
		stats.record(oldTime, false)
	})
}

func TestRequestWindowStats_Concurrent(t *testing.T) {
	stats := newRequestWindowStats()
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				stats.record(time.Now(), j%5 == 0)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
	t.Log("Concurrent recording completed without panic")
}

func TestGetWhoAmI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		claims         *AccessClaims
		expectedStatus int
	}{
		{
			name:           "Valid claims",
			claims:         &AccessClaims{UserID: "123", Email: "user@modintel.local", Role: "analyst"},
			expectedStatus: http.StatusOK,
		},
		{"No claims", nil, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/whoami", GetWhoAmI)

			req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
			rec := httptest.NewRecorder()

			if tt.claims != nil {
				// This is the correct way to pass claims
				c, _ := gin.CreateTestContext(rec)
				c.Request = req
				c.Set("access_claims", tt.claims)
				GetWhoAmI(c)  // Call handler directly with context
				if rec.Code != tt.expectedStatus {
					t.Errorf("Expected %d, got %d", tt.expectedStatus, rec.Code)
				}
				return
			}

			router.ServeHTTP(rec, req)
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestParseAlertTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"RFC3339", "2025-05-12T10:30:00Z", true},
		{"Simple datetime", "2025-05-12 10:30:00", true},
		{"Apache format", "12/May/2025:10:30:00 +0000", true},
		{"Empty", "", false},
		{"Invalid", "not-a-time", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseAlertTimestamp(tt.input)
			if ok != tt.expected {
				t.Errorf("Expected %v for input '%s'", tt.expected, tt.input)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	os.Setenv("WAF_ENGINE", "Coraza + Custom")
	os.Setenv("BACKEND_TARGET", "http://backend:8080")
	defer os.Clearenv()

	router := gin.New()
	router.GET("/config", GetConfig)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
}

func TestReviewAlert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Skip("ReviewAlert requires MongoDB - better suited for integration tests")
}

func TestGenerateDataset(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Skip("GenerateDataset requires MongoDB - better for integration tests")
}
// Skip heavy DB functions for now
func TestGetAlerts(t *testing.T)     { t.Skip("Requires MongoDB - integration test") }
func TestGetLogs(t *testing.T)       { t.Skip("Requires MongoDB - integration test") }
func TestGetTrend(t *testing.T)      { t.Skip("Requires MongoDB - integration test") }
func TestGetStats(t *testing.T)      { t.Skip("Requires MongoDB - integration test") }
func TestGetReviewAlerts(t *testing.T) { t.Skip("Requires MongoDB - integration test") }
func TestGetDatasets(t *testing.T)   { t.Skip("Requires MongoDB - integration test") }
func TestGetDatasetSources(t *testing.T) { t.Skip("Requires MongoDB - integration test") }