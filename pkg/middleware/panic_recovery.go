package middleware

import (
	"log"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// PanicRecoveryMiddleware recovers from panics and returns a sanitized error response
func PanicRecoveryMiddleware(logger *log.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stackTrace := string(debug.Stack())
				requestID := GetRequestID(c)

				if logger != nil {
					logger.Printf(`{"level":"error","message":"Panic recovered","request_id":"%s","method":"%s","path":"%s","panic":"%v","stack_trace":%q}`,
						requestID, c.Request.Method, c.Request.URL.Path, err, stackTrace)
				} else {
					log.Printf("Panic recovered request_id=%s method=%s path=%s panic=%v\n%s",
						requestID, c.Request.Method, c.Request.URL.Path, err, stackTrace)
				}

				ErrorResponse(c, 500, "Internal server error")
				c.Abort()
			}
		}()

		c.Next()
	}
}
