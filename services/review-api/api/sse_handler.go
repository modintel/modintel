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
	"sync"
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
		if _, err := io.WriteString(c.Writer, "event: "+eventType+"\ndata: "+data+"\n\n"); err != nil {
			return
		}
		flusher.Flush()
	}

	writeInitialStats(sendSSE)
	writeInitialMetrics(sendSSE)
	writeInitialHealth(sendSSE)

	ctx := c.Request.Context()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(c.Writer, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
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
	hasDoc := collection.FindOne(ctx, bson.M{}, opts).Decode(&doc) == nil

	systemData := map[string]interface{}{}
	avgInferenceMs := interface{}(nil)
	requestsPerMin := interface{}(nil)
	p50 := interface{}(nil)
	p95 := interface{}(nil)
	p99 := interface{}(nil)

	if hasDoc {
		delete(doc, "_id")
		if doc["timestamp"] != nil {
			if t, ok := doc["timestamp"].(primitive.DateTime); ok {
				doc["timestamp"] = t.Time().Format(time.RFC3339)
			}
		}
		systemData = map[string]interface{}{
			"mongodb_connections":         doc["mongodb_connections"],
			"memory_used_mb":              doc["memory_used_mb"],
			"memory_total_mb":             doc["memory_total_mb"],
			"memory_percent":              doc["memory_percent"],
			"goroutines":                  doc["goroutines"],
			"mongodb_database_size_bytes": doc["mongodb_database_size_bytes"],
		}
		avgInferenceMs = doc["avg_inference_ms"]
		requestsPerMin = doc["requests_per_minute"]
		p50 = doc["p50_latency_ms"]
		p95 = doc["p95_latency_ms"]
		p99 = doc["p99_latency_ms"]
	}

	time1h := buildInitialTimeSeries(collection, "1h")
	time6h := buildInitialTimeSeries(collection, "6h")
	time24h := buildInitialTimeSeries(collection, "24h")
	time7d := buildInitialTimeSeries(collection, "7d")

	payload := map[string]interface{}{
		"avg_inference_ms":    avgInferenceMs,
		"requests_per_minute": requestsPerMin,
		"p50_latency_ms":      p50,
		"p95_latency_ms":      p95,
		"p99_latency_ms":      p99,
		"system":              systemData,
		"time_1h":             time1h,
		"time_6h":             time6h,
		"time_24h":            time24h,
		"time_7d":             time7d,
	}
	data, _ := json.Marshal(payload)
	send("metrics", string(data))
}

func buildInitialTimeSeries(collection *mongo.Collection, rangeType string) []map[string]interface{} {
	var window time.Duration
	var bucketCount int
	switch rangeType {
	case "1h":
		window = 1 * time.Hour
		bucketCount = 60
	case "6h":
		window = 6 * time.Hour
		bucketCount = 72
	case "24h":
		window = 24 * time.Hour
		bucketCount = 96
	case "7d":
		window = 7 * 24 * time.Hour
		bucketCount = 168
	default:
		window = 1 * time.Hour
		bucketCount = 60
	}

	bucketSize := window / time.Duration(bucketCount)
	startTime := time.Now().UTC().Add(-window)

	values := make([]float64, bucketCount)
	errValues := make([]float64, bucketCount)
	counts := make([]int, bucketCount)

	filter := bson.M{"timestamp": bson.M{"$gte": startTime}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}).SetProjection(bson.M{
		"timestamp": 1, "requests_per_minute": 1, "errors_per_minute": 1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var mdoc struct {
			Timestamp time.Time `bson:"timestamp"`
			ReqPerMin float64   `bson:"requests_per_minute"`
			ErrPerMin float64   `bson:"errors_per_minute"`
		}
		if err := cursor.Decode(&mdoc); err != nil {
			continue
		}
		elapsed := mdoc.Timestamp.Sub(startTime)
		idx := int(elapsed / bucketSize)
		if idx >= 0 && idx < bucketCount {
			values[idx] += mdoc.ReqPerMin
			errValues[idx] += mdoc.ErrPerMin
			counts[idx]++
		}
	}

	series := make([]map[string]interface{}, 0, bucketCount)
	for i := 0; i < bucketCount; i++ {
		ts := startTime.Add(time.Duration(i) * bucketSize)
		reqVal := values[i]
		errVal := errValues[i]
		if counts[i] > 0 {
			reqVal /= float64(counts[i])
			errVal /= float64(counts[i])
		}
		series = append(series, map[string]interface{}{
			"timestamp":           ts,
			"requests_per_minute": reqVal,
			"errors_per_minute":   errVal,
		})
	}

	return series
}

func writeInitialHealth(send func(string, string)) {
	statuses := CollectServiceHealth()
	inferenceMetrics := GetInferenceMetrics()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	systemMetrics := GetSystemMetrics(ctx)

	healthData := map[string]interface{}{
		"services":               statuses,
		"timestamp":              time.Now().UTC(),
		"avg_inference_ms":       inferenceMetrics.AvgLatencyMs,
		"p50_latency_ms":         inferenceMetrics.P50LatencyMs,
		"p95_latency_ms":         inferenceMetrics.P95LatencyMs,
		"p99_latency_ms":         inferenceMetrics.P99LatencyMs,
		"total_predictions":      inferenceMetrics.TotalPredictions,
		"predictions_per_minute": inferenceMetrics.PredictionsPerMinute,
		"requests_per_minute":    GetRequestsPerMin(),
		"system": map[string]interface{}{
			"mongodb_connections":         systemMetrics.MongoDBConnections,
			"memory_used_mb":              systemMetrics.MemoryUsedMB,
			"memory_total_mb":             systemMetrics.MemoryTotalMB,
			"memory_percent":              systemMetrics.MemoryPercent,
			"goroutines":                  systemMetrics.Goroutines,
			"mongodb_database_size_bytes": systemMetrics.MongoDBDatabaseSizeBytes,
		},
	}
	data, _ := json.Marshal(healthData)
	send("health", string(data))
}

var LastHealthSnapshot map[string]string

func CollectServiceHealth() map[string]string {
	services := map[string]string{
		"review-api": "ok",
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := db.Client.Ping(ctx, nil); err != nil {
		services["review-api"] = "degraded"
	}

	wg.Add(4)
	go func() { defer wg.Done(); s := checkHTTPService("http://log-collector:8081/health", 3*time.Second); mu.Lock(); services["log-collector"] = s; mu.Unlock() }()
	go func() { defer wg.Done(); s := checkHTTPService("http://inference-engine:8083/health", 3*time.Second); mu.Lock(); services["inference-engine"] = s; mu.Unlock() }()
	go func() { defer wg.Done(); s := checkTCPService("proxy-waf", 8080, 3*time.Second); mu.Lock(); services["proxy-waf"] = s; mu.Unlock() }()
	go func() { defer wg.Done(); s := checkHTTPService("http://auth-service:8084/health", 3*time.Second); mu.Lock(); services["auth-service"] = s; mu.Unlock() }()
	wg.Wait()

	return services
}
