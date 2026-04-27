package main

import (
	"context"
	"log"
	"modintel/services/review-api/api"
	"modintel/services/review-api/db"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var lastTotalRequests uint64
var lastTotalErrors uint64

func main() {
	db.Connect()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	go metricsAggregator()

	log.Printf("Starting Review API on port %s", port)
	router := api.SetupRouter()
	log.Fatal(router.Run(":" + port))
}

func metricsAggregator() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	collection := db.GetCollection("modintel", "metrics")
	ctx := context.Background()

	for range ticker.C {
		totalRequests := api.GetTotalRequests()
		totalErrors := api.GetTotalErrors()
		inferenceMetrics := api.GetInferenceMetrics()
		systemMetrics := api.GetSystemMetrics(ctx)

		ts := time.Now().UTC().Truncate(10 * time.Second)

		reqDelta := int(0)
		errDelta := int(0)
		if lastTotalRequests > 0 {
			if totalRequests >= lastTotalRequests {
				reqDelta = int(totalRequests - lastTotalRequests)
			}
		}
		if lastTotalErrors > 0 {
			if totalErrors >= lastTotalErrors {
				errDelta = int(totalErrors - lastTotalErrors)
			}
		}
		lastTotalRequests = totalRequests
		lastTotalErrors = totalErrors

		reqDeltaPerMin := float64(reqDelta) * 6
		errDeltaPerMin := float64(errDelta) * 6

		doc := bson.M{
			"timestamp":                   ts,
			"requests_delta":              reqDelta,
			"errors_delta":                errDelta,
			"requests_per_minute":         reqDeltaPerMin,
			"errors_per_minute":           errDeltaPerMin,
			"avg_inference_ms":            inferenceMetrics.AvgLatencyMs,
			"p50_latency_ms":              inferenceMetrics.P50LatencyMs,
			"p95_latency_ms":              inferenceMetrics.P95LatencyMs,
			"p99_latency_ms":              inferenceMetrics.P99LatencyMs,
			"predictions_per_minute":      inferenceMetrics.PredictionsPerMinute,
			"mongodb_connections":         systemMetrics.MongoDBConnections,
			"memory_used_mb":              systemMetrics.MemoryUsedMB,
			"goroutines":                  systemMetrics.Goroutines,
			"mongodb_database_size_bytes": systemMetrics.MongoDBDatabaseSizeBytes,
			"total_alerts":                systemMetrics.TotalAlerts,
			"ai_enriched_count":           systemMetrics.AIEnrichedCount,
			"ml_miss_count":               systemMetrics.MLMissCount,
		}

		filter := bson.M{"timestamp": ts}
		opts := options.Replace().SetUpsert(true)
		_, err := collection.ReplaceOne(ctx, filter, doc, opts)
		if err != nil {
			log.Printf("Metrics aggregation error: %v", err)
		}
	}
}
