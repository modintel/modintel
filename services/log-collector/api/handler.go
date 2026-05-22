package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
)

func Serve() {
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/stats", handleStats)
	http.HandleFunc("/api/waf/traffic", handleWAFTraffic)
	http.HandleFunc("/api/waf/block-event", handleBlockEvent)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/metrics", handleMetrics)

	srv := &http.Server{
		Addr:         ":8081",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
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

func handleWAFTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	snapshot := GetWAFTrafficSnapshot(time.Now())
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleBlockEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var evt struct {
		Method      string            `json:"method"`
		URI         string            `json:"uri"`
		Headers     map[string]string `json:"headers"`
		Body        string            `json:"body"`
		MatchedIDs  []string          `json:"matched_ids"`
		Probability float64           `json:"probability"`
		Timestamp   string            `json:"timestamp"`
		Source      string            `json:"source"`
		ClientIP    string            `json:"client_ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	alertKey := sha256Of(evt.Method + "|" + evt.URI + "|" + evt.Body + "|" + evt.Timestamp)
	collection := db.GetCollection("modintel", "alerts")

	clientIP := evt.ClientIP
	if clientIP == "" {
		clientIP = extractClientIP(evt.Headers)
	}
	doc := bson.M{
		"alert_key":          alertKey,
		"timestamp":          evt.Timestamp,
		"client_ip":          clientIP,
		"method":             evt.Method,
		"uri":                evt.URI,
		"headers":            evt.Headers,
		"body":               evt.Body,
		"body_length":        len(evt.Body),
		"source":             "ml_miss_detector",
		"status":             "generated",
		"triggered_rules":    evt.MatchedIDs,
		"matched_signatures": evt.MatchedIDs,
		"http_status":        403,
		"ml_score":           evt.Probability,
		"ai_status":          "pending",
		"coraza_flagged":     false,
		"anomaly_score":      0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := collection.UpdateOne(
		ctx,
		bson.M{"alert_key": alertKey},
		bson.M{"$set": doc},
		options.Update().SetUpsert(true),
	); err != nil {
		log.Printf("Failed to upsert block event: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	go enrichMissAlert(alertKey, &evt)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(bson.M{"status": "ok"}); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func inferenceURL() string {
	if u := os.Getenv("INFERENCE_ENGINE_URL"); u != "" {
		return u
	}
	return "http://inference-engine:8083"
}

func enrichMissAlert(alertKey string, evt *struct {
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	MatchedIDs  []string          `json:"matched_ids"`
	Probability float64           `json:"probability"`
	Timestamp   string            `json:"timestamp"`
	Source      string            `json:"source"`
	ClientIP    string            `json:"client_ip"`
}) {
	payload := map[string]interface{}{
		"method":  evt.Method,
		"uri":     evt.URI,
		"headers": evt.Headers,
		"body":    evt.Body,
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(inferenceURL()+"/predict-miss", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("AI enrichment for block event %s: %v", alertKey, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("AI enrichment for block event %s: status %d", alertKey, resp.StatusCode)
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("AI enrichment for block event %s: decode error: %v", alertKey, err)
		return
	}

	set := bson.M{"ai_status": "enriched"}
	if v, ok := result["attack_probability"].(float64); ok {
		set["ai_score"] = v
	}
	if v, ok := result["confidence_score"].(float64); ok {
		set["ai_confidence"] = v
	}
	if v, ok := result["recommended_priority"].(string); ok {
		set["ai_priority"] = v
	}
	if v, ok := result["model_version"].(string); ok {
		set["ai_model_version"] = v
	}
	if v, ok := result["entropy"].(float64); ok {
		set["ai_entropy"] = v
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	collection := db.GetCollection("modintel", "alerts")
	if _, err := collection.UpdateOne(ctx, bson.M{"alert_key": alertKey}, bson.M{"$set": set}); err != nil {
		log.Printf("Failed to update enriched block event %s: %v", alertKey, err)
	}
}

func sha256Of(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:16])
}

func extractClientIP(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	if ip, ok := headers["X-Forwarded-For"]; ok && ip != "" {
		if idx := strings.IndexByte(ip, ','); idx >= 0 {
			return strings.TrimSpace(ip[:idx])
		}
		return strings.TrimSpace(ip)
	}
	if ip, ok := headers["X-Real-IP"]; ok && ip != "" {
		return strings.TrimSpace(ip)
	}
	return ""
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
