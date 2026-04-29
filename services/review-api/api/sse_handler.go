package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"modintel/services/review-api/db"
)

func SSEAuth(jwtSecret string) gin.HandlerFunc {
	secret := strings.TrimSpace(jwtSecret)
	return func(c *gin.Context) {
		if secret == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth not configured"})
			c.Abort()
			return
		}

		tokenStr := c.Query("token")
		if tokenStr == "" {
			if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
				tokenStr = cookie
			}
		}
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
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

func SSEStreamHandler(c *gin.Context) {
	clientID := c.ClientIP() + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	ch := Hub.Register(clientID)
	defer Hub.Unregister(clientID)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		log.Println("SSE: streaming not supported")
		return
	}

	sendSSE := func(eventType, data string) {
		io.WriteString(c.Writer, "event: "+eventType+"\ndata: "+data+"\n\n")
		flusher.Flush()
	}

	writeInitialStats(sendSSE)
	writeInitialMetrics(sendSSE)
	writeInitialHealth(sendSSE)

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			sendSSE(event.Type, event.Data)
		}
	}
}

func writeInitialStats(send func(string, string)) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	total, _ := collection.CountDocuments(ctx, bson.M{})
	corazaCount, _ := collection.CountDocuments(ctx, bson.M{"source": bson.M{"$in": []string{"coraza", "waf_blocked"}}})
	mlMissCount, _ := collection.CountDocuments(ctx, bson.M{"source": "ml_miss_detector"})

	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var result bson.M
	latestPriority := "-"
	if err := collection.FindOne(ctx, bson.M{"ai_priority": bson.M{"$type": "string"}}, opts).Decode(&result); err == nil {
		if priority, ok := result["ai_priority"].(string); ok && priority != "" {
			latestPriority = priority
		}
	}

	payload := map[string]interface{}{
		"total_alerts":    total,
		"coraza_count":    corazaCount,
		"ml_miss_count":   mlMissCount,
		"latest_priority": latestPriority,
	}
	data, _ := json.Marshal(payload)
	send("stats", string(data))
}

func writeInitialMetrics(send func(string, string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "metrics")
	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var doc bson.M
	if err := collection.FindOne(ctx, bson.M{}, opts).Decode(&doc); err != nil {
		return
	}

	delete(doc, "_id")
	if doc["timestamp"] != nil {
		if t, ok := doc["timestamp"].(primitive.DateTime); ok {
			doc["timestamp"] = t.Time().Format(time.RFC3339)
		}
	}

	systemData := map[string]interface{}{
		"mongodb_connections":         doc["mongodb_connections"],
		"memory_used_mb":              doc["memory_used_mb"],
		"memory_total_mb":             doc["memory_total_mb"],
		"memory_percent":              doc["memory_percent"],
		"goroutines":                  doc["goroutines"],
		"mongodb_database_size_bytes": doc["mongodb_database_size_bytes"],
	}

	timeSeries := buildInitialTimeSeries(collection)

	payload := map[string]interface{}{
		"avg_inference_ms":    doc["avg_inference_ms"],
		"requests_per_minute": doc["requests_per_minute"],
		"p50_latency_ms":      doc["p50_latency_ms"],
		"p95_latency_ms":      doc["p95_latency_ms"],
		"p99_latency_ms":      doc["p99_latency_ms"],
		"system":              systemData,
		"time_series":         timeSeries,
	}
	data, _ := json.Marshal(payload)
	send("metrics", string(data))
}

func buildInitialTimeSeries(collection *mongo.Collection) []map[string]interface{} {
	window := 1 * time.Hour
	startTime := time.Now().UTC().Add(-window)

	filter := bson.M{"timestamp": bson.M{"$gte": startTime}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil
	}
	defer cursor.Close(ctx)

	var series []map[string]interface{}
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		entry := map[string]interface{}{
			"timestamp":           doc["timestamp"],
			"requests_per_minute": doc["requests_per_minute"],
			"errors_per_minute":   doc["errors_per_minute"],
		}
		series = append(series, entry)
	}
	return series
}

func writeInitialHealth(send func(string, string)) {
	statuses := CollectServiceHealth()
	healthData := map[string]interface{}{
		"services":  statuses,
		"timestamp": time.Now().UTC(),
	}
	data, _ := json.Marshal(healthData)
	send("health", string(data))
}

var LastHealthSnapshot map[string]string

func CollectServiceHealth() map[string]string {
	services := map[string]string{
		"review-api": "ok",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := db.Client.Ping(ctx, nil); err != nil {
		services["review-api"] = "degraded"
	}

	services["log-collector"] = checkHTTPService("http://log-collector:8081/health", 3*time.Second)
	services["inference-engine"] = checkHTTPService("http://inference-engine:8083/health", 3*time.Second)
	services["proxy-waf"] = checkTCPService("proxy-waf", 8080, 3*time.Second)
	services["auth-service"] = checkHTTPService("http://auth-service:8084/health", 3*time.Second)

	return services
}
