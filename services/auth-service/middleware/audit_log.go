package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func AuditLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		ip := c.ClientIP()

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		log.Printf("AUDIT method=%s path=%s ip=%s status=%d latency_ms=%d", method, path, ip, status, latency.Milliseconds())
	}
}
