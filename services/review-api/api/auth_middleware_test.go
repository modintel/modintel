package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthMiddlewareMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", AuthMiddleware("test-secret-123456789012345678901234"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-123456789012345678901234"
	r := gin.New()
	r.GET("/protected", AuthMiddleware(secret), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signedAccessToken(t, secret, "u1", "admin@modintel.local", "admin", time.Now().Add(15*time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-123456789012345678901234"
	r := gin.New()
	r.GET("/protected", AuthMiddleware(secret), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signedAccessToken(t, secret, "u1", "admin@modintel.local", "admin", time.Now().Add(-1*time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireRolesForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-123456789012345678901234"
	r := gin.New()
	r.GET("/admin", AuthMiddleware(secret), RequireRoles("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signedAccessToken(t, secret, "u2", "analyst@modintel.local", "analyst", time.Now().Add(15*time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireRolesAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := "test-secret-123456789012345678901234"
	r := gin.New()
	r.GET("/admin", AuthMiddleware(secret), RequireRoles("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signedAccessToken(t, secret, "u1", "admin@modintel.local", "admin", time.Now().Add(15*time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func signedAccessToken(t *testing.T, secret, userID, email, role string, exp time.Time) string {
	t.Helper()
	claims := AccessClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(exp.UTC()),
			Subject:   userID,
		},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed signing token: %v", err)
	}
	return raw
}
