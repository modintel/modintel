package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestAuthRateLimiterBlocksAfterFailedAttempts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewAuthRateLimiter(2)
	router := gin.New()
	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false})
	})

	body := map[string]string{"email": "analyst@modintel.local", "password": "bad"}

	status1 := postJSON(t, router, "/login", body)
	status2 := postJSON(t, router, "/login", body)
	status3 := postJSON(t, router, "/login", body)

	if status1 != http.StatusUnauthorized || status2 != http.StatusUnauthorized {
		t.Fatalf("expected first two attempts 401, got %d and %d", status1, status2)
	}
	if status3 != http.StatusTooManyRequests {
		t.Fatalf("expected third attempt 429, got %d", status3)
	}
}

func TestAuthRateLimiterSuccessResetsFailedCount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewAuthRateLimiter(2)
	limiter.blockFor = 50 * time.Millisecond

	router := gin.New()
	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		var req map[string]string
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{})
			return
		}
		if req["password"] == "ok" {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"success": false})
	})

	bad := map[string]string{"email": "admin@modintel.local", "password": "bad"}
	good := map[string]string{"email": "admin@modintel.local", "password": "ok"}

	if status := postJSON(t, router, "/login", bad); status != http.StatusUnauthorized {
		t.Fatalf("expected bad attempt 401, got %d", status)
	}
	if status := postJSON(t, router, "/login", good); status != http.StatusOK {
		t.Fatalf("expected good attempt 200, got %d", status)
	}
	if status := postJSON(t, router, "/login", bad); status != http.StatusUnauthorized {
		t.Fatalf("expected failed count reset after success, got %d", status)
	}
}

func postJSON(t *testing.T, router http.Handler, path string, payload map[string]string) int {
	t.Helper()

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code
}
