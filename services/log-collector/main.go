package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/nxadm/tail"
	"modintel.local/log-collector/api"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
)

func inferenceEngineURL() string {
	if u := os.Getenv("INFERENCE_ENGINE_URL"); u != "" {
		return u
	}
	return "http://localhost:8083"
}

func enrichWithAI(doc *parsers.AlertDocument) {
	ruleSev := make(map[string]string)
	ruleMsg := make(map[string]string)
	for _, rd := range doc.RuleDetails {
		ruleSev[rd.RuleID] = rd.Severity
		ruleMsg[rd.RuleID] = rd.Message
	}

	payload := map[string]interface{}{
		"fired_rule_ids":    doc.TriggeredRules,
		"rule_severities":   ruleSev,
		"rule_messages":     ruleMsg,
		"anomaly_score":     doc.AnomalyScore,
		"inbound_threshold": 0.0,
		"method":            doc.Method,
		"uri":               doc.URI,
		"headers":           doc.Headers,
		"body":              doc.Body,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("AI enrichment: failed to marshal request: %v", err)
		doc.AIStatus = "unavailable"
		return
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(inferenceEngineURL()+"/predict", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("AI enrichment: request failed: %v", err)
		doc.AIStatus = "unavailable"
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("AI enrichment: non-2xx status %d", resp.StatusCode)
		doc.AIStatus = "unavailable"
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("AI enrichment: failed to read response body: %v", err)
		doc.AIStatus = "unavailable"
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		log.Printf("AI enrichment: failed to decode response: %v", err)
		doc.AIStatus = "unavailable"
		return
	}

	doc.AIStatus = "enriched"

	if v, ok := result["attack_probability"].(float64); ok {
		doc.AIScore = &v
	}
	if v, ok := result["confidence_score"].(float64); ok {
		doc.AIConfidence = &v
	}
	if v, ok := result["recommended_priority"].(string); ok {
		doc.AIPriority = &v
	}
	if v, ok := result["explanation"].(map[string]interface{}); ok {
		doc.AIExplanation = v
	}
	if v, ok := result["model_version"].(string); ok {
		doc.AIModelVersion = &v
	}
	if v, ok := result["entropy"].(float64); ok {
		doc.AIEntropy = &v
	}
	if ci, ok := result["confidence_interval"].(map[string]interface{}); ok {
		interval := make(map[string]float64)
		if low, ok := ci["low"].(float64); ok {
			interval["low"] = low
		}
		if high, ok := ci["high"].(float64); ok {
			interval["high"] = high
		}
		doc.AIConfidenceInterval = interval
	}
}

func main() {
	_ = godotenv.Load("../../.env")

	db.Connect()

	go api.Serve()

	logFile := "/var/log/coraza/audit.json"
	if envLog := os.Getenv("LOG_FILE_PATH"); envLog != "" {
		logFile = envLog
	}

	log.Printf("Starting Log Collector, reading from %s", logFile)

	for {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Printf("Waiting for log file %s to be created...", logFile)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true,
	})

	if err != nil {
		log.Fatalf("Failed to tail log file: %v", err)
	}

	collection := db.GetCollection("modintel", "alerts")

	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error reading tail line: %v", line.Err)
			continue
		}

		if line.Text == "" {
			continue
		}

		doc, err := parsers.ParseCorazaLog([]byte(line.Text))
		if err != nil {
			log.Printf("Failed to parse log line: %v (line: %s)", err, line.Text)
			continue
		}

		enrichWithAI(doc)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = collection.InsertOne(ctx, doc)
		cancel()

		if err != nil {
			log.Printf("Failed to insert alert to MongoDB: %v", err)
		} else {
			log.Printf("Successfully ingested WAF log: %s", doc.URI)
		}
	}
}
