package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modintel_api_requests_total",
			Help: "Total API requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "modintel_api_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"method", "endpoint"},
	)
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "modintel_api_active_connections",
			Help: "Number of active connections",
		},
	)
	inferenceRequestsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "modintel_inference_requests_total",
			Help: "Total inference requests through review-api",
		},
	)
	totalRequests atomic.Uint64
	totalErrors  atomic.Uint64
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(inferenceRequestsTotal)
}

func SetupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(requestTracker())

	r.GET("/health", HealthCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	r.GET("/api/logs", GetLogs)
	r.GET("/api/stats", GetStats)
	r.GET("/api/trend", GetTrend)
	r.GET("/api/config", GetConfig)
	r.GET("/api/monitor/health", GetmonitorHealth)
	r.GET("/api/monitor/metrics", GetmonitorMetrics)
	r.DELETE("/api/logs", ClearLogs)
	return r
}

func requestTracker() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		totalRequests.Add(1)
		statusCode := c.Writer.Status()
		if statusCode >= 400 {
			totalErrors.Add(1)
		}
	}
}

func GetConfig(c *gin.Context) {
	backendTarget := os.Getenv("BACKEND_TARGET")
	inferenceURL := os.Getenv("INFERENCE_ENGINE_URL")
	wafEngine := os.Getenv("WAF_ENGINE")

	if wafEngine == "" {
		wafEngine = "Coraza (Caddy edge)"
	}

	if backendTarget == "" {
		backendTarget = "not-set"
	}

	if inferenceURL == "" {
		inferenceURL = "not-set"
	}

	c.JSON(http.StatusOK, gin.H{
		"waf_engine":           wafEngine,
		"backend_target":       backendTarget,
		"inference_engine_url": inferenceURL,
	})
}

func parseAlertTimestamp(raw string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
		"02/Jan/2006:15:04:05 -0700",
		"2006-01-02T15:04:05Z07:00",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}

	if t, err := time.Parse(time.RFC1123Z, raw); err == nil {
		return t.UTC(), true
	}

	return time.Time{}, false
}

func GetTrend(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rangeType := c.DefaultQuery("range", "day")
	now := time.Now().UTC()

	var bucketCount int
	var bucketSize time.Duration
	var start time.Time

	switch rangeType {
	case "week":
		bucketCount = 84
		bucketSize = 2 * time.Hour
		start = now.Truncate(2 * time.Hour).Add(-time.Duration(bucketCount-1) * bucketSize)
	case "month":
		bucketCount = 120
		bucketSize = 6 * time.Hour
		start = now.Truncate(6 * time.Hour).Add(-time.Duration(bucketCount-1) * bucketSize)
	case "day":
		bucketCount = 96
		bucketSize = 15 * time.Minute
		start = now.Truncate(15 * time.Minute).Add(-time.Duration(bucketCount-1) * bucketSize)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "range must be day, week, or month"})
		return
	}

	values := make([]int, bucketCount)
	labels := make([]string, bucketCount)

	for i := 0; i < bucketCount; i++ {
		bucketTime := start.Add(time.Duration(i) * bucketSize)
		if rangeType == "day" {
			labels[i] = bucketTime.Format("15:04")
		} else if rangeType == "week" {
			labels[i] = bucketTime.Format("Mon 15:04")
		} else {
			labels[i] = bucketTime.Format("02 Jan 15:04")
		}
	}

	opts := options.Find().SetProjection(bson.M{"timestamp": 1})
	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		log.Println("Error fetching trend data:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var record bson.M
		if err := cursor.Decode(&record); err != nil {
			continue
		}

		rawTS, ok := record["timestamp"].(string)
		if !ok || rawTS == "" {
			continue
		}

		ts, ok := parseAlertTimestamp(rawTS)
		if !ok || ts.Before(start) || ts.After(now.Add(time.Minute)) {
			continue
		}

		idx := int(ts.Sub(start) / bucketSize)
		if idx >= 0 && idx < bucketCount {
			values[idx]++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"range":  rangeType,
		"labels": labels,
		"values": values,
	})
}

func GetLogs(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(500).
		SetProjection(bson.M{
			"timestamp":              1,
			"client_ip":              1,
			"uri":                    1,
			"anomaly_score":          1,
			"triggered_rules":        1,
			"ai_status":              1,
			"ai_score":               1,
			"ai_confidence":          1,
			"ai_priority":            1,
			"ai_explanation":         1,
			"ai_model_version":       1,
			"ai_entropy":             1,
			"ai_confidence_interval": 1,
		})
	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		log.Println("Error finding logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err := cursor.All(ctx, &results); err != nil {
		log.Println("Error decoding logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	type AlertResponse struct {
		Timestamp            string                 `json:"timestamp"`
		ClientIP             string                 `json:"client_ip"`
		URI                  string                 `json:"uri"`
		AnomalyScore         float64                `json:"anomaly_score"`
		TriggeredRules       []string               `json:"triggered_rules"`
		AIStatus             string                 `json:"ai_status"`
		AIScore              *float64               `json:"ai_score"`
		AIConfidence         *float64               `json:"ai_confidence"`
		AIPriority           *string                `json:"ai_priority"`
		AIExplanation        map[string]interface{} `json:"ai_explanation"`
		AIModelVersion       *string                `json:"ai_model_version"`
		AIEntropy            *float64               `json:"ai_entropy"`
		AIConfidenceInterval *map[string]float64    `json:"ai_confidence_interval"`
	}

	alerts := make([]AlertResponse, 0, len(results))
	for _, r := range results {
		alert := AlertResponse{
			Timestamp:      r["timestamp"].(string),
			ClientIP:       r["client_ip"].(string),
			URI:            r["uri"].(string),
			TriggeredRules: []string{},
		}

		if score, ok := r["anomaly_score"].(float64); ok {
			alert.AnomalyScore = score
		}

		if rules, ok := r["triggered_rules"].(bson.A); ok {
			for _, r := range rules {
				alert.TriggeredRules = append(alert.TriggeredRules, r.(string))
			}
		}

		if status, ok := r["ai_status"].(string); ok {
			alert.AIStatus = status
		}
		if score, ok := r["ai_score"].(float64); ok {
			alert.AIScore = &score
		}
		if conf, ok := r["ai_confidence"].(float64); ok {
			alert.AIConfidence = &conf
		}
		if priority, ok := r["ai_priority"].(string); ok {
			alert.AIPriority = &priority
		}
		if expl, ok := r["ai_explanation"].(map[string]interface{}); ok {
			alert.AIExplanation = expl
		}
		if modelVer, ok := r["ai_model_version"].(string); ok {
			alert.AIModelVersion = &modelVer
		}
		if entropy, ok := r["ai_entropy"].(float64); ok {
			alert.AIEntropy = &entropy
		}
		if ci, ok := r["ai_confidence_interval"].(map[string]interface{}); ok {
			interval := make(map[string]float64)
			if low, ok := ci["low"].(float64); ok {
				interval["low"] = low
			}
			if high, ok := ci["high"].(float64); ok {
				interval["high"] = high
			}
			if len(interval) > 0 {
				alert.AIConfidenceInterval = &interval
			}
		}

		alerts = append(alerts, alert)
	}

	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

func GetStats(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Println("Error counting alerts:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var result bson.M
	err = collection.FindOne(ctx, bson.M{}, opts).Decode(&result)
	latestRule := "—"
	latestPriority := "—"
	if err == nil {
		if rules, ok := result["triggered_rules"].(bson.A); ok && len(rules) > 0 {
			if rule, ok := rules[0].(string); ok {
				latestRule = rule
			}
		}
		if priority, ok := result["ai_priority"].(string); ok && priority != "" {
			latestPriority = priority
		}
	}

	aiEnrichedCount, err := collection.CountDocuments(ctx, bson.M{"ai_status": "enriched"})
	if err != nil {
		log.Println("Error counting AI enriched documents:", err)
		aiEnrichedCount = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":      total,
		"latest_rule":       latestRule,
		"latest_priority":   latestPriority,
		"ai_enriched_count": aiEnrichedCount,
	})
}

func ClearLogs(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := collection.DeleteMany(ctx, bson.M{})
	if err != nil {
		log.Println("Error clearing logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": result.DeletedCount})
}

func HealthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.Client.Ping(ctx, nil)
	status := "ok"
	statusCode := http.StatusOK

	if err != nil {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, gin.H{
		"status":  status,
		"service": "review-api",
	})
}

func GetmonitorHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	services := map[string]string{
		"review-api": "ok",
	}

	if err := db.Client.Ping(ctx, nil); err != nil {
		services["review-api"] = "degraded"
	}

	services["log-collector"] = checkHTTPService("http://log-collector:8081/health", 3*time.Second)
	services["inference-engine"] = checkHTTPService("http://inference-engine:8083/health", 3*time.Second)
	services["proxy-waf"] = checkTCPService("proxy-waf", 8080, 3*time.Second)

	c.JSON(http.StatusOK, gin.H{
		"services":  services,
		"timestamp": time.Now().UTC(),
	})
}

func checkHTTPService(url string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "unknown"
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "down"
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "ok"
	}
	return "degraded"
}

func checkTCPService(host string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "down"
	}
	conn.Close()
	return "ok"
}

func GetmonitorMetrics(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

	totalAlerts, _ := collection.CountDocuments(ctx, bson.M{})
	aiEnrichedCount, _ := collection.CountDocuments(ctx, bson.M{"ai_status": "enriched"})

	inferenceMetrics := getInferenceMetrics()
	systemMetrics := getSystemMetrics(ctx)

	var errorRate float64
	if totalRequests > 0 {
		errorRate = totalErrors / totalRequests
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":        totalAlerts,
		"ai_enriched_count":   aiEnrichedCount,
		"avg_inference_ms":    inferenceMetrics.avgLatencyMs,
		"p50_latency_ms":      inferenceMetrics.p50LatencyMs,
		"p95_latency_ms":      inferenceMetrics.p95LatencyMs,
		"p99_latency_ms":      inferenceMetrics.p99LatencyMs,
		"total_predictions":   inferenceMetrics.totalPredictions,
		"predictions_per_minute": inferenceMetrics.predictionsPerMinute,
		"model_version":       inferenceMetrics.modelVersion,
		"inference_uptime_seconds": inferenceMetrics.uptimeSeconds,
		"requests_per_minute":  inferenceMetrics.predictionsPerMinute,
		"error_rate":          errorRate,
		"total_requests":      totalRequests,
		"total_errors":        totalErrors,
		"mongodb_connections": systemMetrics.MongoDBConnections,
		"timestamp":           time.Now().UTC(),
		"system":              systemMetrics,
	})
}

type inferenceMetricsData struct {
	avgLatencyMs         float64
	p50LatencyMs         float64
	p95LatencyMs         float64
	p99LatencyMs         float64
	totalPredictions     int
	predictionsPerMinute float64
	modelVersion         string
	uptimeSeconds        float64
}

func getInferenceMetrics() inferenceMetricsData {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://inference-engine:8083/metrics", nil)
	if err != nil {
		return inferenceMetricsData{}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return inferenceMetricsData{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return inferenceMetricsData{}
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return inferenceMetricsData{}
	}

	metrics := inferenceMetricsData{}

	if v, ok := result["avg_inference_latency_ms"].(float64); ok {
		metrics.avgLatencyMs = v
	}
	if v, ok := result["p50_latency_ms"].(float64); ok {
		metrics.p50LatencyMs = v
	}
	if v, ok := result["p95_latency_ms"].(float64); ok {
		metrics.p95LatencyMs = v
	}
	if v, ok := result["p99_latency_ms"].(float64); ok {
		metrics.p99LatencyMs = v
	}
	if v, ok := result["total_predictions"].(float64); ok {
		metrics.totalPredictions = int(v)
	}
	if v, ok := result["predictions_per_minute"].(float64); ok {
		metrics.predictionsPerMinute = v
	}
	if v, ok := result["model_version"].(string); ok {
		metrics.modelVersion = v
	}
	if v, ok := result["uptime_seconds"].(float64); ok {
		metrics.uptimeSeconds = v
	}

	return metrics
}

type systemMetricsData struct {
	Hostname            string  `json:"hostname"`
	GoVersion           string  `json:"go_version"`
	UptimeSeconds       float64 `json:"uptime_seconds"`
	CpuPercent          float64 `json:"cpu_percent"`
	MemoryUsedMB        uint64  `json:"memory_used_mb"`
	MemoryTotalMB       uint64  `json:"memory_total_mb"`
	MemoryPercent       float64 `json:"memory_percent"`
	Goroutines          int     `json:"goroutines"`
	MongoDBConnections  int     `json:"mongodb_connections"`
	MongoDBDatabaseSize int64   `json:"mongodb_database_size_bytes"`
	MongoDBAlertCount   int64   `json:"mongodb_alert_count"`
}

var serviceStartTime = time.Now()

func getSystemMetrics(ctx context.Context) systemMetricsData {
	metrics := systemMetricsData{
		Hostname:      getHostname(),
		GoVersion:    runtime.Version(),
		UptimeSeconds: time.Since(serviceStartTime).Seconds(),
		Goroutines:    runtime.NumGoroutine(),
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.MemoryUsedMB = m.Alloc / (1024 * 1024)
	metrics.MemoryTotalMB = m.TotalAlloc / (1024 * 1024)
	if m.TotalAlloc > 0 {
		metrics.MemoryPercent = float64(m.Alloc) / float64(m.TotalAlloc) * 100
	}

	metrics.CpuPercent = getCPULoad()

	if db.Client != nil {
		dbName := "modintel"

		if err := db.Client.Ping(ctx, nil); err == nil {
			metrics.MongoDBConnections = 1
		}

		alertColl := db.GetCollection(dbName, "alerts")
		count, err := alertColl.CountDocuments(ctx, bson.M{})
		if err == nil {
			metrics.MongoDBAlertCount = count
		}

		var result bson.M
		collStatsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = alertColl.Database().RunCommand(collStatsCtx, bson.D{{Key: "collStats", Value: "alerts"}}).Decode(&result)
		if err == nil {
			if size, ok := result["size"].(int64); ok {
				metrics.MongoDBDatabaseSize = size
			}
		}
	}

	return metrics
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

func getCPULoad() float64 {
	return 0.0
}
