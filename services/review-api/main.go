package main

import (
	"context"
	"encoding/json"
	"log"
	"modintel/services/review-api/api"
	"modintel/services/review-api/db"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var lastTotalRequests uint64
var lastTotalErrors uint64

func main() {
	db.Connect()
	api.InitHub()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	go metricsAggregator()
	go watchAlerts()
	go broadcastHealth()

	log.Printf("Starting Review API on port %s", port)
	router := api.SetupRouter()
	log.Fatal(router.Run(":" + port))
}

const metricsWindow = 60 * time.Second

func metricsAggregator() {
	ticker := time.NewTicker(metricsWindow)
	defer ticker.Stop()

	collection := db.GetCollection("modintel", "metrics")
	ctx := context.Background()

	for range ticker.C {
		totalRequests := api.GetTotalRequests()
		totalErrors := api.GetTotalErrors()
		inferenceMetrics := api.GetInferenceMetrics()
		systemMetrics := api.GetSystemMetrics(ctx)

		ts := time.Now().UTC().Truncate(metricsWindow)

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

		reqDeltaPerMin := float64(reqDelta)
		errDeltaPerMin := float64(errDelta)

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
			"memory_total_mb":             systemMetrics.MemoryTotalMB,
			"memory_percent":              systemMetrics.MemoryPercent,
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

		systemPayload := map[string]interface{}{
			"mongodb_connections":         systemMetrics.MongoDBConnections,
			"memory_used_mb":              systemMetrics.MemoryUsedMB,
			"memory_total_mb":             systemMetrics.MemoryTotalMB,
			"memory_percent":              systemMetrics.MemoryPercent,
			"goroutines":                  systemMetrics.Goroutines,
			"mongodb_database_size_bytes": systemMetrics.MongoDBDatabaseSizeBytes,
		}

		timeSeries1h := buildMetricsTimeSeries(collection, "1h")
		timeSeries6h := buildMetricsTimeSeries(collection, "6h")
		timeSeries24h := buildMetricsTimeSeries(collection, "24h")
		timeSeries7d := buildMetricsTimeSeries(collection, "7d")

		payload := map[string]interface{}{
			"avg_inference_ms":    inferenceMetrics.AvgLatencyMs,
			"requests_per_minute": reqDeltaPerMin,
			"p50_latency_ms":      inferenceMetrics.P50LatencyMs,
			"p95_latency_ms":      inferenceMetrics.P95LatencyMs,
			"p99_latency_ms":      inferenceMetrics.P99LatencyMs,
			"system":              systemPayload,
			"time_1h":             timeSeries1h,
			"time_6h":             timeSeries6h,
			"time_24h":            timeSeries24h,
			"time_7d":             timeSeries7d,
		}
		data, _ := json.Marshal(payload)
		api.Hub.Broadcast(api.SSEEvent{Type: "metrics", Data: string(data)})
	}
}

func buildMetricsTimeSeries(collection *mongo.Collection, rangeType string) []map[string]interface{} {
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
	now := time.Now().UTC()
	startTime := now.Add(-window)

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
		var doc struct {
			Timestamp time.Time `bson:"timestamp"`
			ReqPerMin float64   `bson:"requests_per_minute"`
			ErrPerMin float64   `bson:"errors_per_minute"`
		}
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		elapsed := doc.Timestamp.Sub(startTime)
		idx := int(elapsed / bucketSize)
		if idx >= 0 && idx < bucketCount {
			values[idx] += doc.ReqPerMin
			errValues[idx] += doc.ErrPerMin
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

func watchAlerts() {
	collection := db.GetCollection("modintel", "alerts")
	ctx := context.Background()

	for {
		cs, err := collection.Watch(ctx, mongo.Pipeline{
			{{Key: "$match", Value: bson.M{"operationType": "insert"}}},
		})
		if err != nil {
			log.Printf("Change Stream unavailable, falling back to cursor polling: %v", err)
			pollAlertsCursor(ctx, collection)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Change Stream watching alerts collection")

		for cs.Next(ctx) {
			var changeEvent struct {
				FullDocument bson.M `bson:"fullDocument"`
			}
			if err := cs.Decode(&changeEvent); err != nil {
				log.Printf("Change Stream decode error: %v", err)
				continue
			}

			if changeEvent.FullDocument == nil {
				continue
			}

			delete(changeEvent.FullDocument, "_id")
			if ts, ok := changeEvent.FullDocument["timestamp"]; ok {
				if t, ok := ts.(primitive.DateTime); ok {
					changeEvent.FullDocument["timestamp"] = t.Time().Format(time.RFC3339)
				}
			}

			alertJSON, err := json.Marshal(changeEvent.FullDocument)
			if err != nil {
				log.Printf("Alert JSON marshal error: %v", err)
				continue
			}

			api.Hub.Broadcast(api.SSEEvent{Type: "alert", Data: string(alertJSON)})

			broadcastUpdatedStats()
		}

		if err := cs.Err(); err != nil {
			log.Printf("Change Stream error: %v", err)
		}
		cs.Close(ctx)
		time.Sleep(2 * time.Second)
	}
}

func pollAlertsCursor(ctx context.Context, collection *mongo.Collection) {
	var lastID primitive.ObjectID

	opts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
	var latest bson.M
	if err := collection.FindOne(ctx, bson.M{}, opts).Decode(&latest); err == nil {
		if id, ok := latest["_id"].(primitive.ObjectID); ok {
			lastID = id
		}
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		filter := bson.M{"_id": bson.M{"$gt": lastID}}
		findOpts := options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
		cursor, err := collection.Find(ctx, filter, findOpts)
		if err != nil {
			continue
		}

		for cursor.Next(ctx) {
			var doc bson.M
			if err := cursor.Decode(&doc); err != nil {
				continue
			}
			if id, ok := doc["_id"].(primitive.ObjectID); ok {
				lastID = id
			}
			delete(doc, "_id")
			if ts, ok := doc["timestamp"]; ok {
				if t, ok := ts.(primitive.DateTime); ok {
					doc["timestamp"] = t.Time().Format(time.RFC3339)
				}
			}
			alertJSON, _ := json.Marshal(doc)
			api.Hub.Broadcast(api.SSEEvent{Type: "alert", Data: string(alertJSON)})
		}
		cursor.Close(ctx)
		broadcastUpdatedStats()
	}
}

func broadcastUpdatedStats() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

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
	api.Hub.Broadcast(api.SSEEvent{Type: "stats", Data: string(data)})
}

func broadcastHealth() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		currentHealth := api.CollectServiceHealth()

		if api.LastHealthSnapshot == nil {
			api.LastHealthSnapshot = make(map[string]string)
		}

		changed := len(api.LastHealthSnapshot) == 0
		if !changed {
			for svc, status := range currentHealth {
				if prev, ok := api.LastHealthSnapshot[svc]; !ok || prev != status {
					changed = true
					break
				}
			}
			for svc := range api.LastHealthSnapshot {
				if _, ok := currentHealth[svc]; !ok {
					changed = true
					break
				}
			}
		}

		if changed {
			api.LastHealthSnapshot = currentHealth
		}

		inferenceMetrics := api.GetInferenceMetrics()
		ctx := context.Background()
		systemMetrics := api.GetSystemMetrics(ctx)

		payload := map[string]interface{}{
			"services":               currentHealth,
			"timestamp":              time.Now().UTC(),
			"avg_inference_ms":       inferenceMetrics.AvgLatencyMs,
			"p50_latency_ms":         inferenceMetrics.P50LatencyMs,
			"p95_latency_ms":         inferenceMetrics.P95LatencyMs,
			"p99_latency_ms":         inferenceMetrics.P99LatencyMs,
			"total_predictions":      inferenceMetrics.TotalPredictions,
			"predictions_per_minute": inferenceMetrics.PredictionsPerMinute,
			"requests_per_minute":    inferenceMetrics.PredictionsPerMinute,
			"system": map[string]interface{}{
				"mongodb_connections":         systemMetrics.MongoDBConnections,
				"memory_used_mb":              systemMetrics.MemoryUsedMB,
				"memory_total_mb":             systemMetrics.MemoryTotalMB,
				"memory_percent":              systemMetrics.MemoryPercent,
				"goroutines":                  systemMetrics.Goroutines,
				"mongodb_database_size_bytes": systemMetrics.MongoDBDatabaseSizeBytes,
			},
		}
		data, _ := json.Marshal(payload)
		api.Hub.Broadcast(api.SSEEvent{Type: "health", Data: string(data)})
	}
}
