package api

import (
	"context"
	"net/http"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

// ReadinessCheck checks if the service and its dependencies are ready
func ReadinessCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]string)
	failedDeps := make([]string, 0)

	// Check MongoDB
	if err := checkMongoDB(ctx); err != nil {
		checks["mongodb"] = "down"
		failedDeps = append(failedDeps, "mongodb")
	} else {
		checks["mongodb"] = "ok"
	}

	// Determine overall status
	if len(failedDeps) > 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":              "not_ready",
			"failed_dependencies": failedDeps,
			"checks":              checks,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
		"checks": checks,
	})
}

// checkMongoDB checks if MongoDB is accessible
func checkMongoDB(ctx context.Context) error {
	client := db.GetClient()
	if client == nil {
		return mongo.ErrClientDisconnected
	}

	// Ping MongoDB
	return client.Ping(ctx, nil)
}
