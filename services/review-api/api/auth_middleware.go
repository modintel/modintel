package api

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AccessClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	secret := strings.TrimSpace(jwtSecret)
	return func(c *gin.Context) {
		if secret == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth not configured"})
			c.Abort()
			return
		}

		raw := c.GetHeader("Authorization")
		parts := strings.SplitN(raw, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(parts[1], &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*AccessClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now().UTC()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "access token expired"})
			c.Abort()
			return
		}

		c.Set("access_claims", claims)
		c.Next()
	}
}

func RequireRoles(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[strings.ToLower(strings.TrimSpace(role))] = struct{}{}
	}

	return func(c *gin.Context) {
		claimsAny, exists := c.Get("access_claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		claims, ok := claimsAny.(*AccessClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if _, ok := allowed[strings.ToLower(strings.TrimSpace(claims.Role))]; !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func AuthAuditLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		userID := "unauthenticated"
		role := "unknown"
		if claimsAny, exists := c.Get("access_claims"); exists {
			if claims, ok := claimsAny.(*AccessClaims); ok {
				if strings.TrimSpace(claims.UserID) != "" {
					userID = claims.UserID
				}
				if strings.TrimSpace(claims.Role) != "" {
					role = claims.Role
				}
			}
		}

		log.Printf(
			"AUTH_AUDIT method=%s path=%s status=%d user_id=%s role=%s ip=%s latency_ms=%d",
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			userID,
			role,
			c.ClientIP(),
			time.Since(start).Milliseconds(),
		)
	}
}
