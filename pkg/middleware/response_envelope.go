package middleware

import (
	"github.com/gin-gonic/gin"
)

// ResponseEnvelope is the standardized response format for all API responses
type ResponseEnvelope struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id"`
	Data      interface{} `json:"data,omitempty"`
}

const requestIDKey = "request_id"

// EnvelopeMiddleware extracts or generates a Request_ID and stores it in the context
func EnvelopeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Request_ID from X-Request-ID header
		requestID := c.GetHeader("X-Request-ID")
		
		// Validate UUID format, generate new one if invalid or missing
		if requestID == "" || !ParseUUID(requestID) {
			requestID = GenerateUUID()
		}
		
		// Store Request_ID in context for handler access
		c.Set(requestIDKey, requestID)
		
		// Add Request_ID to response headers
		c.Header("X-Request-ID", requestID)
		
		c.Next()
	}
}

// GetRequestID retrieves the Request_ID from the Gin context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(requestIDKey); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// SuccessResponse sends a successful response with the standard envelope format
func SuccessResponse(c *gin.Context, data interface{}) {
	requestID := GetRequestID(c)
	envelope := ResponseEnvelope{
		Code:      200,
		Message:   "Success",
		RequestID: requestID,
		Data:      data,
	}
	c.JSON(200, envelope)
}

// ErrorResponse sends an error response with the standard envelope format
func ErrorResponse(c *gin.Context, code int, message string) {
	requestID := GetRequestID(c)
	envelope := ResponseEnvelope{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}
	c.JSON(code, envelope)
}
