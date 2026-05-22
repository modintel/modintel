package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/nxadm/tail"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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

type circuitBreaker struct {
	mu          sync.Mutex
	failures    int
	lastFailure time.Time
	state       string // closed, open, half-open
}

func (cb *circuitBreaker) call(fn func() error) error {
	cb.mu.Lock()
	if cb.state == "open" {
		if time.Since(cb.lastFailure) < 10*time.Second {
			cb.mu.Unlock()
			return fmt.Errorf("circuit breaker open")
		}
		cb.state = "half-open"
	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.failures >= 5 {
			cb.state = "open"
			log.Printf("Circuit breaker tripped (open) after %d failures", cb.failures)
		}
		return err
	}
	cb.failures = 0
	if cb.state == "half-open" {
		cb.state = "closed"
		log.Println("Circuit breaker reset (closed)")
	}
	return nil
}

var inferenceCB = &circuitBreaker{}
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:      20,
		IdleConnTimeout:   90 * time.Second,
		DisableKeepAlives: false,
	},
}

var aiWorkers = make(chan struct{}, 20)
var missWorkers = make(chan struct{}, 3)

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

func isInternalIP(ip string) bool {
	if ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	networks := []string{"172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"}
	for _, cidr := range networks {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) && !addr.IsLoopback() {
			return !strings.HasSuffix(ip, ".1")
		}
	}
	return false
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

	if err := inferenceCB.call(func() error { return doEnrichRequest(payload, doc) }); err != nil {
		log.Printf("AI enrichment: circuit breaker or failure: %v", err)
		doc.AIStatus = "unavailable"
		return false
	}
	return true
}

func doEnrichRequest(payload map[string]interface{}, doc *parsers.AlertDocument) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, _ := http.NewRequest("POST", inferenceEngineURL()+"/predict", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("AI enrichment: got status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
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

	return nil
}

func _enrichMiss(doc *parsers.AlertDocument) bool {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := httpClient.Do(req.WithContext(ctx))
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

		if strings.Contains(doc.URI, "/socket.io/") {
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

		doc.AIStatus = "pending"

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

		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		opts := options.Update().SetUpsert(true)
		_, err = collection.UpdateOne(ctx2, bson.M{"alert_key": alertKey}, bson.M{"$set": docMap}, opts)
		cancel2()

		if err != nil {
			log.Printf("Failed to upsert Coraza alert: %v", err)
			continue
		}

		corazaTs, corazaTsErr := time.Parse(time.RFC3339, doc.Timestamp)
		if corazaTsErr == nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			delResult, _ := collection.DeleteOne(cleanupCtx, bson.M{
				"uri":       doc.URI,
				"method":    doc.Method,
				"client_ip": doc.ClientIP,
				"source":    "ml_miss_detector",
				"timestamp": bson.M{
					"$gte": corazaTs.Add(-2 * time.Second).Format(time.RFC3339),
					"$lte": corazaTs.Add(2 * time.Second).Format(time.RFC3339),
				},
			})
			if delResult != nil && delResult.DeletedCount > 0 {
				log.Printf("Dedup: cleaned up %d ml_miss alert(s) for %s %s (replaced by coraza alert)", delResult.DeletedCount, doc.Method, doc.URI)
			}
			cleanupCancel()
		}

		aiWorkers <- struct{}{}
		docCopy := *doc
		key := alertKey
		go func() {
			defer func() { <-aiWorkers }()
			enrichWithAI(&docCopy)
			if docCopy.AIStatus == "enriched" {
				aiJSON, _ := json.Marshal(docCopy)
				var aiMap map[string]interface{}
				if err := json.Unmarshal(aiJSON, &aiMap); err != nil {
					log.Printf("AI re-enrich: failed to unmarshal: %v", err)
					return
				}
				upCtx, upCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer upCancel()
				if _, err := collection.UpdateOne(upCtx, bson.M{"alert_key": key}, bson.M{"$set": aiMap}); err != nil {
					log.Printf("AI re-enrich: failed to update: %v", err)
				}
			}
		}()
	}
}

func processCaddyAccessLogs(sigPrefilter *signatures.Prefilter) {
	logFile := os.Getenv("CADDY_LOG_PATH")
	if logFile == "" {
		logFile = "/var/log/caddy/waf-access.json"
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
		log.Fatalf("Failed to tail Caddy access log: %v", err)
	}
	defer func() { _ = t.Stop() }()

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

		ts, err := time.Parse(time.RFC3339, doc.Timestamp)
		if err != nil {
			ts = time.Now().UTC()
		}
		wafBlocked := parsers.IsBlockedByWAF(doc.HTTPStatus)
		api.RecordWAFRequest(ts, wafBlocked)

		if isInternalIP(doc.ClientIP) {
			continue
		}

		if strings.Contains(doc.URI, "/socket.io/") {
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

		wafPassed := parsers.IsWAFPassed(doc.HTTPStatus)

		if wafBlocked {
			log.Printf("Signature matched but WAF blocked (status=%d, uri=%s)", doc.HTTPStatus, doc.URI)
			continue
		}

		if wafPassed {
			dedupCtx, dedupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			existing, err := findExistingAlert(dedupCtx, collection, doc.URI, doc.Method, ts, doc.ClientIP)
			dedupCancel()
			if err == nil && existing != nil {
				log.Printf("Dedup: skipping ml_miss for %s %s (existing %s alert)", doc.Method, doc.URI, existing["source"])
				continue
			}

			doc.Source = "ml_miss_detector"
			doc.Status = "generated"
			doc.TriggeredRules = matchedSigs

			missWorkers <- struct{}{}
			docCopy := *doc
			key := alertKey
			sigs := matchedSigs
			go func() {
				defer func() { <-missWorkers }()
				_enrichMiss(&docCopy)

				// Re-check for existing coraza alert (created concurrently while _enrichMiss ran)
				reTs, err := time.Parse(time.RFC3339, docCopy.Timestamp)
				if err != nil {
					reTs = time.Now().UTC()
				}
				reCtx, reCancel := context.WithTimeout(context.Background(), 3*time.Second)
				existing, err := findExistingAlert(reCtx, collection, docCopy.URI, docCopy.Method, reTs, docCopy.ClientIP)
				reCancel()
				if err == nil && existing != nil {
					log.Printf("Dedup (post-inference): skipping ml_miss upsert for %s %s (existing %s alert)", docCopy.Method, docCopy.URI, existing["source"])
					return
				}

				docJSON, err := json.Marshal(docCopy)
				if err != nil {
					log.Printf("Failed to marshal miss doc: %v", err)
					return
				}
				var docMap map[string]interface{}
				if err := json.Unmarshal(docJSON, &docMap); err != nil {
					log.Printf("Failed to unmarshal miss doc: %v", err)
					return
				}
				docMap["alert_key"] = key
				docMap["matched_signatures"] = sigs

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err = collection.UpdateOne(
					ctx,
					bson.M{"alert_key": key},
					bson.M{"$set": docMap},
					options.Update().SetUpsert(true),
				)
				if err != nil {
					log.Printf("Failed to upsert miss alert to MongoDB: %v", err)
				}
			}()
		}
	}
}

func findExistingAlert(ctx context.Context, collection *mongo.Collection, uri, method string, ts time.Time, clientIP string) (bson.M, error) {
	var existing bson.M
	err := collection.FindOne(ctx, bson.M{
		"uri":       uri,
		"method":    method,
		"source":    bson.M{"$in": []string{"coraza", "ml_miss_detector"}},
		"client_ip": clientIP,
		"timestamp": bson.M{
			"$gte": ts.Add(-2 * time.Second).Format(time.RFC3339),
			"$lte": ts.Add(2 * time.Second).Format(time.RFC3339),
		},
	}).Decode(&existing)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return existing, nil
}

func backfillPendingAlerts() {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{"ai_status": "pending"})
	if err != nil {
		log.Printf("Backfill: failed to query pending alerts: %v", err)
		return
	}
	defer cursor.Close(ctx)

	var docs []bson.M
	if err := cursor.All(ctx, &docs); err != nil {
		log.Printf("Backfill: failed to read pending alerts: %v", err)
		return
	}

	if len(docs) == 0 {
		return
	}

	log.Printf("Backfill: re-enriching %d pending alerts", len(docs))
	for _, doc := range docs {
		k, _ := doc["alert_key"].(string)
		if k == "" {
			continue
		}
		alertKey := k
		docRef := doc
		aiWorkers <- struct{}{}
		go func() {
			defer func() { <-aiWorkers }()
			var alert parsers.AlertDocument
			b, err := bson.Marshal(docRef)
			if err != nil {
				log.Printf("Backfill: failed to marshal: %v", err)
				return
			}
			if err := bson.Unmarshal(b, &alert); err != nil {
				log.Printf("Backfill: failed to unmarshal: %v", err)
				return
			}
			enrichWithAI(&alert)
			if alert.AIStatus == "enriched" {
				aiJSON, _ := json.Marshal(alert)
				var aiMap map[string]interface{}
				if err := json.Unmarshal(aiJSON, &aiMap); err != nil {
					log.Printf("Backfill: failed to unmarshal aiJSON: %v", err)
					return
				}
				upCtx, upCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer upCancel()
				if _, err := collection.UpdateOne(upCtx, bson.M{"alert_key": alertKey}, bson.M{"$set": aiMap}); err != nil {
					log.Printf("Backfill: failed to update: %v", err)
				}
			}
		}()
	}
	log.Printf("Backfill: queued %d pending alerts for re-enrichment", len(docs))
}

func main() {
	_ = godotenv.Load("../../.env")

	db.Connect()

	go backfillPendingAlerts()

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
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			backfillPendingAlerts()
		}
	}()
	go processCorazaAuditLogs(sigPrefilter)
	processCaddyAccessLogs(sigPrefilter)
}
