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
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nxadm/tail"
	"go.mongodb.org/mongo-driver/bson"
	"modintel.local/log-collector/api"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
)

type writeModel struct {
	alertKey string
	docMap   map[string]interface{}
}

func inferenceEngineURL() string {
	if u := os.Getenv("INFERENCE_ENGINE_URL"); u != "" {
		return u
	}
	return "http://localhost:8083"
}

func uniqueAlertKey(doc *parsers.AlertDocument) string {
	rules := make([]string, len(doc.TriggeredRules))
	copy(rules, doc.TriggeredRules)
	sort.Strings(rules)
	h := sha256.New()
	h.Write([]byte(doc.URI + "|" + doc.Timestamp + "|" + strings.Join(rules, ",")))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func isAlreadyEnriched(doc *parsers.AlertDocument) bool {
	return doc.AIStatus == "enriched" && doc.AIScore != nil
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

	if err := os.Truncate(logFile, 0); err != nil {
		log.Printf("Warning: failed to truncate audit log: %v", err)
	} else {
		log.Printf("Audit log truncated — will process only new entries from this point")
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
	})
	if err != nil {
		log.Printf("failed to tail log file: %v", err)
		return
	}

	collection := db.GetCollection("modintel", "alerts")

	writeCh := make(chan writeModel, 256)

	var closeOnce sync.Once
	closeWrite := func() { closeOnce.Do(func() { close(writeCh) }) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sigCh:
			log.Println("Shutting down...")
			cancel()
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bulkWriter(ctx, collection, writeCh)
	}()

	for {
		select {
		case <-ctx.Done():
			closeWrite()
			wg.Wait()
			return
		case line, ok := <-t.Lines:
			if !ok {
				closeWrite()
				wg.Wait()
				return
			}
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

			alertKey := uniqueAlertKey(doc)
			dedupCtx, dedupCancel := context.WithTimeout(ctx, 5*time.Second)
			var existing bson.M
			err = collection.FindOne(dedupCtx, bson.M{"alert_key": alertKey}).Decode(&existing)
			dedupCancel()
			if err == nil && existing["ai_status"] == "enriched" {
				log.Printf("Skipping already-enriched alert (key=%s, uri=%s)", alertKey, doc.URI)
				continue
			}
			if err == nil {
				log.Printf("Alert exists but not enriched (key=%s), re-enriching...", alertKey)
			}

			enrichWithAI(doc)

			raw, err := bson.Marshal(doc)
			if err != nil {
				log.Printf("Failed to marshal doc: %v", err)
				continue
			}

			var docMap bson.M
			if err := bson.Unmarshal(raw, &docMap); err != nil {
				log.Printf("Failed to unmarshal doc: %v", err)
				continue
			}
			docMap["alert_key"] = alertKey

			select {
			case writeCh <- writeModel{alertKey: alertKey, docMap: docMap}:
			default:
				log.Printf("Write channel full, dropping alert key=%s", alertKey)
			}
		}
	}
}
