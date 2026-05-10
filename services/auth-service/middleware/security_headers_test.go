package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Check status code
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Test all security headers
	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
	}

	for header, expectedValue := range headers {
		actual := rec.Header().Get(header)
		if actual != expectedValue {
			t.Errorf("Header %s: expected '%s', got '%s'", header, expectedValue, actual)
		}
	}
}

func TestSecurityHeaders_AppliedToAllRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeaders())

	// Test multiple routes
	routes := []string{"/login", "/refresh", "/profile", "/admin"}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			// Just check one critical header on each route
			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf("Security headers not applied on route %s", route)
			}
		})
	}
}