package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// ── UUID helpers ──────────────────────────────────────────────────────────────

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-00000000-0000-0000-0000-%012d", 0)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ── Response envelope ─────────────────────────────────────────────────────────

const requestIDKey = "request_id"

// ResponseEnvelope is the standard API response wrapper.
type ResponseEnvelope struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id"`
	Data      interface{} `json:"data,omitempty"`
}

// EnvelopeMiddleware attaches a request ID to every request/response.
func EnvelopeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" || !isValidUUID(id) {
			id = generateUUID()
		}
		c.Set(requestIDKey, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// GetRequestID returns the request ID stored in the Gin context.
func GetRequestID(c *gin.Context) string {
	if v, exists := c.Get(requestIDKey); exists {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// SuccessResponse writes a 200 envelope response.
func SuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(200, ResponseEnvelope{Code: 200, Message: "Success", RequestID: GetRequestID(c), Data: data})
}

// ErrorResponse writes an error envelope response.
func ErrorResponse(c *gin.Context, code int, message string) {
	c.JSON(code, ResponseEnvelope{Code: code, Message: message, RequestID: GetRequestID(c)})
}

// ── Panic recovery ────────────────────────────────────────────────────────────

// PanicRecoveryMiddleware catches panics, logs them, and returns a sanitized 500.
func PanicRecoveryMiddleware(logger *log.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())
				id := GetRequestID(c)
				if logger != nil {
					logger.Printf(`{"level":"error","message":"Panic recovered","request_id":"%s","method":"%s","path":"%s","panic":"%v","stack":%q}`,
						id, c.Request.Method, c.Request.URL.Path, err, stack)
				} else {
					log.Printf("panic recovered request_id=%s %v\n%s", id, err, stack)
				}
				ErrorResponse(c, 500, "Internal server error")
				c.Abort()
			}
		}()
		c.Next()
	}
}
