package api

import (
	"context"
	"encoding/json"
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

	http.ListenAndServe(":8081", nil)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var alerts []parsers.AlertDocument
	if err = cursor.All(ctx, &alerts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(bson.M{"alerts": alerts})
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

	json.NewEncoder(w).Encode(bson.M{
		"total_alerts": total,
		"latest_rule":  lastRule,
		"status":       "protected",
	})
}
