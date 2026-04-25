package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
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

type bodyCacheEntry struct {
	Body     string
	ExpireAt time.Time
}

var (
	bodyCache   = make(map[string]bodyCacheEntry)
	bodyCacheMu sync.RWMutex
)

func cacheKey(method, uri string) string {
	h := sha256.New()
	h.Write([]byte(method + "|" + uri))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func setBodyCache(method, uri, body string) {
	key := cacheKey(method, uri)
	bodyCacheMu.Lock()
	defer bodyCacheMu.Unlock()
	bodyCache[key] = bodyCacheEntry{Body: body, ExpireAt: time.Now().Add(5 * time.Minute)}
}

func getBodyCache(method, uri string) string {
	key := cacheKey(method, uri)
	bodyCacheMu.RLock()
	defer bodyCacheMu.RUnlock()
	if entry, ok := bodyCache[key]; ok && time.Now().Before(entry.ExpireAt) {
		return entry.Body
	}
	return ""
}

func cleanupBodyCache() {
	bodyCacheMu.Lock()
	defer bodyCacheMu.Unlock()
	now := time.Now()
	for k, v := range bodyCache {
		if now.After(v.ExpireAt) {
			delete(bodyCache, k)
		}
	}
}

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

func enrichWithAI(doc *parsers.AlertDocument) bool {
	if isAlreadyEnriched(doc) {
		return true
	}

	log.Printf("AI ENRICHMENT START: uri=%s method=%s rules=%v", doc.URI, doc.Method, doc.TriggeredRules)

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
	var resp *http.Response
	for i := 0; i < maxRetries; i++ {
		req, _ := http.NewRequest("POST", inferenceEngineURL()+"/predict", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		log.Printf("AI enrichment: request failed (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
	if err != nil {
		log.Printf("AI enrichment: failed after retries: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("AI enrichment: got status %d", resp.StatusCode)
		doc.AIStatus = "unavailable"
		return false
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("AI enrichment: failed to decode response: %v", err)
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
	if v, ok := result["explanation"].(map[string]interface{}); ok {
		doc.AIExplanation = v
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
	if ci, ok := result["confidence_interval"].(map[string]interface{}); ok {
		low, _ := ci["low"].(float64)
		high, _ := ci["high"].(float64)
		doc.AIConfidenceInterval = map[string]float64{"low": low, "high": high}
	}

	return true
}

func enrichMiss(doc *parsers.AlertDocument) bool {
	if isAlreadyEnriched(doc) {
		return true
	}

	ruleSev := make(map[string]string)
	for _, rid := range doc.TriggeredRules {
		ruleSev[rid] = "high"
	}

	payload := map[string]interface{}{
		"fired_rule_ids":  doc.TriggeredRules,
		"rule_severities": ruleSev,
		"method":          doc.Method,
		"uri":             doc.URI,
		"headers":         doc.Headers,
		"body":            doc.Body,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Miss enrichment: failed to marshal: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}

	req, _ := http.NewRequest("POST", inferenceEngineURL()+"/predict-miss", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Miss enrichment failed: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Miss enrichment: failed to decode: %v", err)
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
	if v, ok := result["explanation"].(map[string]interface{}); ok {
		doc.AIExplanation = v
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
	if ci, ok := result["confidence_interval"].(map[string]interface{}); ok {
		low, _ := ci["low"].(float64)
		high, _ := ci["high"].(float64)
		doc.AIConfidenceInterval = map[string]float64{"low": low, "high": high}
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
			continue
		}
		if err == nil {
			log.Printf("Alert exists but not enriched (key=%s), re-enriching...", alertKey)
		}

		if doc.AnomalyScore <= 0 {
			continue
		}
		doc.Source = "coraza"

		if doc.Body == "" {
			if cached := getBodyCache(doc.Method, doc.URI); cached != "" {
				doc.Body = cached
				doc.BodyLength = len(cached)
			}
		}

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
		res, err := collection.UpdateOne(
			ctx,
			bson.M{"alert_key": alertKey},
			bson.M{"$set": docMap},
			options.Update().SetUpsert(true),
		)
		cancel()

		if err != nil {
			log.Printf("Failed to upsert Coraza alert to MongoDB: %v", err)
		} else {
			log.Printf("Coraza alert ingested: %s (matched=%d, upserted=%v)", doc.URI, res.MatchedCount, res.UpsertedID)
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

		if doc.Body != "" {
			setBodyCache(doc.Method, doc.URI, doc.Body)
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
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			cleanupBodyCache()
		}
	}()
	go processCorazaAuditLogs(sigPrefilter)
	processCaddyAccessLogs(sigPrefilter)
}
