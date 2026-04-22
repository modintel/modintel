package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/nxadm/tail"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"modintel.local/log-collector/api"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
	"modintel.local/log-collector/signatures"
)

func inferenceEngineURL() string {
	if u := os.Getenv("INFERENCE_ENGINE_URL"); u != "" {
		return u
	}
	return "http://localhost:8083"
}

func hashHeaders(headers map[string]string) string {
	h := sha256.New()
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + "=" + headers[k] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func uniqueAlertKey(doc *parsers.AlertDocument) string {
	rules := make([]string, len(doc.TriggeredRules))
	copy(rules, doc.TriggeredRules)
	sort.Strings(rules)
	h := sha256.New()
	h.Write([]byte(doc.Method + "|" + doc.URI + "|" + doc.Body + "|" + doc.ClientIP + "|" + doc.Timestamp + "|" + strings.Join(rules, ",") + "|" + hashHeaders(doc.Headers)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func uniqueMissKey(doc *parsers.AlertDocument) string {
	rules := make([]string, len(doc.TriggeredRules))
	copy(rules, doc.TriggeredRules)
	sort.Strings(rules)
	h := sha256.New()
	h.Write([]byte(doc.Method + "|" + doc.URI + "|" + doc.Body + "|" + doc.ClientIP + "|" + doc.Timestamp + "|" + strings.Join(rules, ",") + "|" + hashHeaders(doc.Headers)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func isAlreadyEnriched(doc *parsers.AlertDocument) bool {
	return doc.AIStatus == "enriched" && doc.AIScore != nil
}

func isBlocked(doc *parsers.AlertDocument) bool {
	return doc.AnomalyScore > 0
}

func enrichWithAI(doc *parsers.AlertDocument) bool {
	if isAlreadyEnriched(doc) {
		return true
	}

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
		return false
	}

	maxRetries := 3
	backoff := 500 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("AI enrichment: retry %d/%d after %v", attempt+1, maxRetries, backoff)
			time.Sleep(backoff)
			backoff *= 2
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(inferenceEngineURL()+"/predict", "application/json", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("AI enrichment: request failed (attempt %d): %v", attempt+1, err)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("AI enrichment: non-2xx status %d (attempt %d)", resp.StatusCode, attempt+1)
			resp.Body.Close()
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("AI enrichment: failed to read response body: %v", err)
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(respBytes, &result); err != nil {
			log.Printf("AI enrichment: failed to decode response: %v", err)
			continue
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

		return true
	}

	log.Printf("AI enrichment: all retries exhausted, marking as unavailable")
	doc.AIStatus = "unavailable"
	return false
}

func enrichMiss(doc *parsers.AlertDocument) bool {
	payload := map[string]interface{}{
		"fired_rule_ids":    []string{},
		"rule_severities":   map[string]string{},
		"rule_messages":     map[string]string{},
		"anomaly_score":     0.0,
		"inbound_threshold": 0.0,
		"method":            doc.Method,
		"uri":               doc.URI,
		"headers":           doc.Headers,
		"body":              doc.Body,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Miss enrichment: failed to marshal request: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Post(inferenceEngineURL()+"/predict-miss", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Miss enrichment: request failed: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Miss enrichment: non-2xx status %d", resp.StatusCode)
		doc.AIStatus = "unavailable"
		return false
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Miss enrichment: failed to read response body: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		log.Printf("Miss enrichment: failed to decode response: %v", err)
		doc.AIStatus = "unavailable"
		return false
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
	if v, ok := result["model_version"].(string); ok {
		doc.AIModelVersion = &v
	}
	if v, ok := result["entropy"].(float64); ok {
		doc.AIEntropy = &v
	}

	return true
}

func processCorazaAuditLogs(sigPrefilter *signatures.Prefilter) {
	logFile := "/var/log/coraza/audit.json"
	if envLog := os.Getenv("CORAZA_LOG_PATH"); envLog != "" {
		logFile = envLog
	}

	log.Printf("Starting Coraza audit log processor, reading from %s", logFile)

	for {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Printf("Waiting for Coraza log file %s to be created...", logFile)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	if err := os.Truncate(logFile, 0); err != nil {
		log.Printf("Warning: failed to truncate Coraza audit log: %v", err)
	} else {
		log.Printf("Coraza audit log truncated")
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
	})
	if err != nil {
		log.Fatalf("Failed to tail Coraza log file: %v", err)
	}

	collection := db.GetCollection("modintel", "alerts")

	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error reading Coraza tail line: %v", line.Err)
			continue
		}
		if line.Text == "" {
			continue
		}

		doc, err := parsers.ParseCorazaLog([]byte(line.Text))
		if err != nil {
			log.Printf("Failed to parse Coraza log line: %v", err)
			continue
		}

		alertKey := uniqueAlertKey(doc)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var existing bson.M
		err = collection.FindOne(ctx, bson.M{"alert_key": alertKey}).Decode(&existing)
		cancel()

		if err == nil && existing["ai_status"] == "enriched" {
			log.Printf("Skipping already-enriched alert (key=%s, uri=%s)", alertKey, doc.URI)
			continue
		}
		if err == nil {
			log.Printf("Alert exists but not enriched (key=%s), re-enriching...", alertKey)
		}

		blocked := isBlocked(doc) || len(doc.TriggeredRules) > 0
		if !blocked {
			continue
		}
		doc.Source = "coraza"
		enrichWithAI(doc)

		docJSON, err := json.Marshal(doc)
		if err != nil {
			log.Printf("Failed to marshal doc: %v", err)
			continue
		}
		var docMap map[string]interface{}
		if err := json.Unmarshal(docJSON, &docMap); err != nil {
			log.Printf("Failed to unmarshal doc: %v", err)
			continue
		}
		docMap["alert_key"] = alertKey
		docMap["coraza_flagged"] = true

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = collection.UpdateOne(
			ctx,
			bson.M{"alert_key": alertKey},
			bson.M{"$set": docMap},
			options.Update().SetUpsert(true),
		)
		cancel()

		if err != nil {
			log.Printf("Failed to upsert Coraza alert to MongoDB: %v", err)
		} else {
			log.Printf("Coraza alert ingested: %s", doc.URI)
		}
	}
}

func processCaddyAccessLogs(sigPrefilter *signatures.Prefilter) {
	logFile := "/var/log/caddy/access.json"
	if envLog := os.Getenv("CADDY_LOG_PATH"); envLog != "" {
		logFile = envLog
	}

	log.Printf("Starting Caddy access log processor, reading from %s", logFile)

	for {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Printf("Waiting for Caddy log file %s to be created...", logFile)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	if err := os.Truncate(logFile, 0); err != nil {
		log.Printf("Warning: failed to truncate Caddy access log: %v", err)
	} else {
		log.Printf("Caddy access log truncated")
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
	})
	if err != nil {
		log.Fatalf("Failed to tail Caddy log file: %v", err)
	}

	collection := db.GetCollection("modintel", "alerts")

	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error reading Caddy tail line: %v", line.Err)
			continue
		}
		if line.Text == "" {
			continue
		}

		doc, err := parsers.ParseCaddyAccessLog([]byte(line.Text))
		if err != nil {
			log.Printf("Failed to parse Caddy log line: %v", err)
			continue
		}

		if sigPrefilter == nil {
			continue
		}

		sigHit, matchedSigs := sigPrefilter.Evaluate(doc.Method, doc.URI, doc.Body, doc.Headers)
		if !sigHit {
			continue
		}

		alertKey := uniqueMissKey(doc)

		wafBlocked := parsers.IsBlockedByWAF(doc.HTTPStatus)
		wafPassed := parsers.IsWAFPassed(doc.HTTPStatus)

		if wafBlocked {
			log.Printf("Signature matched but WAF blocked (status=%d, uri=%s)", doc.HTTPStatus, doc.URI)
			continue
		}

		if wafPassed {
			doc.Source = "ml_miss_detector"
			doc.TriggeredRules = matchedSigs
			enrichMiss(doc)

			docJSON, err := json.Marshal(doc)
			if err != nil {
				log.Printf("Failed to marshal miss doc: %v", err)
				continue
			}
			var docMap map[string]interface{}
			if err := json.Unmarshal(docJSON, &docMap); err != nil {
				log.Printf("Failed to unmarshal miss doc: %v", err)
				continue
			}
			docMap["alert_key"] = alertKey
			docMap["matched_signatures"] = matchedSigs

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = collection.UpdateOne(
				ctx,
				bson.M{"alert_key": alertKey},
				bson.M{"$set": docMap},
				options.Update().SetUpsert(true),
			)
			cancel()

			if err != nil {
				log.Printf("Failed to upsert miss alert to MongoDB: %v", err)
			} else {
				log.Printf("MISS DETECTED: %s (status=%d, ai_score=%v)", doc.URI, doc.HTTPStatus, doc.AIScore)
			}
		}
	}
}

func main() {
	_ = godotenv.Load("../../.env")

	db.Connect()

	var sigPrefilter *signatures.Prefilter
	if sigFile := os.Getenv("MODINTEL_SIGNATURES_FILE"); sigFile != "" {
		var err error
		sigPrefilter, err = signatures.Load(sigFile)
		if err != nil {
			log.Printf("Warning: failed to load signatures: %v", err)
		} else {
			log.Printf("Loaded signatures from %s", sigFile)
		}
	}

	go api.Serve()
	go processCorazaAuditLogs(sigPrefilter)
	processCaddyAccessLogs(sigPrefilter)
}
