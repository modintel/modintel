package api

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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

	r.GET("/api/logs", GetLogs)
	r.GET("/api/stats", GetStats)
	r.GET("/api/trend", GetTrend)
	r.GET("/api/config", GetConfig)
	r.DELETE("/api/logs", ClearLogs)
	return r
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

	bucketCount := 96
	bucketSize := 15 * time.Minute
	start := now.Truncate(15 * time.Minute).Add(-time.Duration(bucketCount-1) * bucketSize)

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
