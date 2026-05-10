package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuditLog_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Capture log output
	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)

	router := gin.New()
	router.Use(AuditLog())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	router.POST("/login", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
	})

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"Successful GET request", http.MethodGet, "/test", http.StatusOK},
		{"Failed POST request", http.MethodPost, "/login", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuffer.Reset() // Clear previous logs

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check that audit log was written
			logOutput := logBuffer.String()
			if logOutput == "" {
				t.Error("Audit log should not be empty")
			}

			// Verify key information is logged
			if !contains(logOutput, tt.method) || !contains(logOutput, tt.path) {
				t.Errorf("Log output should contain method and path. Got: %s", logOutput)
			}

			if !contains(logOutput, "AUDIT") {
				t.Error("Log should contain 'AUDIT' marker")
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}