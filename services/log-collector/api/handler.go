package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
)

func Serve() {
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/stats", handleStats)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/metrics", handleMetrics)

	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: -1}}).SetLimit(100)
	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var alerts []parsers.AlertDocument
	if err = cursor.All(ctx, &alerts); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(bson.M{"alerts": alerts}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, _ := collection.CountDocuments(ctx, bson.M{})

	opts := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
	var last parsers.AlertDocument
	err := collection.FindOne(ctx, bson.M{}, opts).Decode(&last)

	lastRule := "—"
	if err == nil && len(last.TriggeredRules) > 0 {
		lastRule = last.TriggeredRules[len(last.TriggeredRules)-1]
	}

	if err := json.NewEncoder(w).Encode(bson.M{
		"total_alerts": total,
		"latest_rule":  lastRule,
		"status":       "protected",
	}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")
	err := collection.Database().Client().Ping(ctx, nil)

	status := "ok"
	statusCode := http.StatusOK
	if err != nil {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  status,
		"service": "log-collector",
	}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

var logsProcessedTotal int64
var logsEnrichedTotal int64

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	metrics := fmt.Sprintf(`# HELP modintel_logs_processed_total Total logs processed by log-collector
# TYPE modintel_logs_processed_total counter
modintel_logs_processed_total %d
# HELP modintel_logs_enriched_total Total logs enriched with AI
# TYPE modintel_logs_enriched_total counter
modintel_logs_enriched_total %d
`, logsProcessedTotal, logsEnrichedTotal)

	if _, err := w.Write([]byte(metrics)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
