package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthRateLimiter_BlocksAfterMaxAttempts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewAuthRateLimiter(2)
	router := gin.New()

	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false})
	})

	body := map[string]string{"email": "test@modintel.local", "password": "wrong"}

	t.Run("Blocks after reaching max failed attempts", func(t *testing.T) {
		if code := postJSON(router, "/login", body); code != http.StatusUnauthorized {
			t.Errorf("Attempt 1: expected 401, got %d", code)
		}
		if code := postJSON(router, "/login", body); code != http.StatusUnauthorized {
			t.Errorf("Attempt 2: expected 401, got %d", code)
		}
		if code := postJSON(router, "/login", body); code != http.StatusTooManyRequests {
			t.Errorf("Attempt 3: expected 429, got %d", code)
		}
	})
}

func TestAuthRateLimiter_SuccessResetsCounter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewAuthRateLimiter(2)

	router := gin.New()
	router.POST("/login", limiter.Middleware(), func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
		}
		_ = c.ShouldBindJSON(&req)

		if req.Password == "correct123" {
			c.JSON(http.StatusOK, gin.H{"success": true})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false})
		}
	})

	bad := map[string]string{"email": "user@modintel.local", "password": "wrong"}
	good := map[string]string{"email": "user@modintel.local", "password": "correct123"}

	if code := postJSON(router, "/login", bad); code != http.StatusUnauthorized {
		t.Fatal("First bad attempt should return 401")
	}

	if code := postJSON(router, "/login", good); code != http.StatusOK {
		t.Fatal("Successful login should return 200")
	}

	if code := postJSON(router, "/login", bad); code != http.StatusUnauthorized {
		t.Error("Counter should reset after successful login")
	}
}

// Helper
func postJSON(router http.Handler, path string, payload map[string]string) int {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code
}