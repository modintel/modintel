package api

import (
	"context"
	"log"
	"net/http"
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
	return r
}

func GetLogs(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(50)
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
		Timestamp          string                 `json:"timestamp"`
		ClientIP           string                 `json:"client_ip"`
		URI                string                 `json:"uri"`
		AnomalyScore       float64                `json:"anomaly_score"`
		TriggeredRules     []string               `json:"triggered_rules"`
		AIStatus           string                 `json:"ai_status"`
		AIScore            *float64               `json:"ai_score"`
		AIConfidence       *float64               `json:"ai_confidence"`
		AIPriority         *string                `json:"ai_priority"`
		AIExplanation      map[string]interface{} `json:"ai_explanation"`
		AIModelVersion     *string                `json:"ai_model_version"`
		AIEntropy          *float64               `json:"ai_entropy"`
		AIConfidenceInterval *map[string]float64   `json:"ai_confidence_interval"`
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

	aiEnrichedCount, _ := collection.CountDocuments(ctx, bson.M{"ai_status": "enriched"})

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":      total,
		"latest_rule":       latestRule,
		"latest_priority":   latestPriority,
		"ai_enriched_count": aiEnrichedCount,
	})
}
