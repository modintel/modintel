package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type SignaturePattern struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Patterns    []string `json:"patterns"`
	Description string   `json:"description"`
	Enabled     *bool    `json:"enabled"`
}

type Prefilter struct {
	patterns []SignaturePattern
	compiled map[string][]*regexp.Regexp
}

func LoadPrefilter(path string) (*Prefilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signatures: %w", err)
	}

	var patterns []SignaturePattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return nil, fmt.Errorf("parse signatures: %w", err)
	}

	pf := &Prefilter{
		patterns: patterns,
		compiled: make(map[string][]*regexp.Regexp, len(patterns)),
	}

	for _, p := range patterns {
		if p.Enabled != nil && !*p.Enabled {
			log.Printf("Skipping disabled signature: %s", p.ID)
			continue
		}
		var regs []*regexp.Regexp
		for _, pat := range p.Patterns {
			if r, err := regexp.Compile(pat); err == nil {
				regs = append(regs, r)
			} else {
				log.Printf("Warning: failed to compile pattern %q for sig %s: %v", pat, p.ID, err)
			}
		}
		if len(regs) > 0 {
			pf.compiled[p.ID] = regs
		}
	}

	return pf, nil
}

func (pf *Prefilter) Evaluate(method, uri, body string, headers map[string]string) (matchedIDs []string) {
	text := method + " " + uri + " " + body
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk != "user-agent" && lk != "cookie" && !strings.HasPrefix(lk, "accept") && lk != "sec-fetch-site" && lk != "sec-fetch-mode" && lk != "sec-fetch-dest" {
			text += " " + v
		}
	}
	text = strings.ToLower(text)

	for _, p := range pf.patterns {
		regs, ok := pf.compiled[p.ID]
		if !ok {
			continue
		}
		for _, r := range regs {
			if r.MatchString(text) {
				matchedIDs = append(matchedIDs, p.ID)
				break
			}
		}
	}
	return matchedIDs
}

type inferRequest struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type inferResponse struct {
	AttackProbability   float64 `json:"attack_probability"`
	ConfidenceScore     float64 `json:"confidence_score"`
	RecommendedPriority string  `json:"recommended_priority"`
	AdvisoryOnly        bool    `json:"advisory_only"`
	Error               string  `json:"error,omitempty"`
}

type evalMissRequest struct {
	Method    string            `json:"method"`
	URI       string            `json:"uri"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	RateScore float64           `json:"rate_score"`
	RepScore  float64           `json:"rep_score"`
}

type evalMissResponse struct {
	MLScore     float64           `json:"ml_score"`
	RateScore   float64           `json:"rate_score"`
	RepScore    float64           `json:"rep_score"`
	Composite   float64           `json:"composite"`
	Decision    string            `json:"decision"`
	Breakdown   map[string]float64 `json:"breakdown"`
	ModelVersion string           `json:"model_version"`
}

type trafficBucket struct {
	Total   uint64
	Blocked uint64
	Allowed uint64
}

type trafficStats struct {
	mu      sync.Mutex
	buckets map[int64]*trafficBucket
}

func newTrafficStats() *trafficStats {
	return &trafficStats{buckets: make(map[int64]*trafficBucket)}
}

func (s *trafficStats) record(ts time.Time, blocked bool) {
	minute := ts.UTC().Truncate(time.Minute).Unix()
	cutoff := minute - int64((24*time.Hour)/time.Minute)

	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.buckets[minute]
	if !ok {
		bucket = &trafficBucket{}
		s.buckets[minute] = bucket
	}
	bucket.Total++
	if blocked {
		bucket.Blocked++
	} else {
		bucket.Allowed++
	}
	for key := range s.buckets {
		if key < cutoff {
			delete(s.buckets, key)
		}
	}
}

func (s *trafficStats) liveRPM(now time.Time) (float64, float64, float64) {
	currentMinute := now.UTC().Truncate(time.Minute).Unix()
	var total, blocked, allowed uint64
	var count int

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := int64(0); i < 2; i++ {
		minute := currentMinute - i
		if bucket, ok := s.buckets[minute]; ok {
			total += bucket.Total
			blocked += bucket.Blocked
			allowed += bucket.Allowed
			count++
		}
	}
	if count == 0 {
		return 0, 0, 0
	}
	denom := float64(count)
	return float64(total) / denom, float64(blocked) / denom, float64(allowed) / denom
}

type trafficSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	RequestsPerMin float64   `json:"requests_per_minute"`
	BlockedPerMin  float64   `json:"blocked_per_minute"`
	AllowedPerMin  float64   `json:"allowed_per_minute"`
}

type blockEvent struct {
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

type ipRateEntry struct {
	Timestamps []time.Time
}

type ipBlockEntry struct {
	ExpiresAt time.Time
	Reason    string
}

type ipReputation struct {
	RepScore float64
	Updated  time.Time
}

type Blocker struct {
	prefilter      *Prefilter
	inferenceURL   string
	evalMissURL    string
	blockThreshold float64
	reportURL      string
	proxy          *httputil.ReverseProxy
	client         *http.Client
	traffic        *trafficStats
	thresholdMu    sync.RWMutex

	blocklistMu  sync.RWMutex
	blocklist    map[string]ipBlockEntry

	rateMu       sync.Mutex
	rateTracker  map[string]*ipRateEntry

	repMu        sync.RWMutex
	repCache     map[string]ipReputation

	maxRateRPM    float64
	blockTTL      time.Duration
	rateWindowSec int
}

func (b *Blocker) SetThreshold(t float64) {
	b.thresholdMu.Lock()
	defer b.thresholdMu.Unlock()
	b.blockThreshold = t
}

func (b *Blocker) GetThreshold() float64 {
	b.thresholdMu.RLock()
	defer b.thresholdMu.RUnlock()
	return b.blockThreshold
}

func NewBlocker(prefilter *Prefilter, inferenceURL, backendURL, reportURL string, blockThreshold float64) *Blocker {
	target, _ := url.Parse(backendURL)
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			r.Host = target.Host
		},
		Transport: transport,
	}
	return &Blocker{
		prefilter:      prefilter,
		inferenceURL:   inferenceURL,
		evalMissURL:    strings.Replace(inferenceURL, "/predict-miss", "/eval-miss", 1),
		blockThreshold: blockThreshold,
		reportURL:      reportURL,
		proxy:          proxy,
		traffic:        newTrafficStats(),
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		blocklist:   make(map[string]ipBlockEntry),
		rateTracker: make(map[string]*ipRateEntry),
		repCache:    make(map[string]ipReputation),
		maxRateRPM:  120.0,
		blockTTL:    30 * time.Minute,
		rateWindowSec: 60,
	}
}

func (b *Blocker) callInference(method, uri string, headers map[string]string, body string) (float64, error) {
	req := inferRequest{Method: method, URI: uri, Headers: headers, Body: body}
	data, _ := json.Marshal(req)

	resp, err := b.client.Post(b.inferenceURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("inference call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("inference returned %d: %s", resp.StatusCode, string(errBody))
	}

	var result inferResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode inference response: %w", err)
	}

	return result.AttackProbability, nil
}

func (b *Blocker) callEvalMiss(method, uri string, headers map[string]string, body string, rateScore, repScore float64) (*evalMissResponse, error) {
	req := evalMissRequest{
		Method: method, URI: uri, Headers: headers, Body: body,
		RateScore: rateScore, RepScore: repScore,
	}
	data, _ := json.Marshal(req)

	resp, err := b.client.Post(b.evalMissURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("eval-miss call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("eval-miss returned %d: %s", resp.StatusCode, string(errBody))
	}

	var result evalMissResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode eval-miss response: %w", err)
	}

	return &result, nil
}

func (b *Blocker) reportBlock(r *http.Request, matchedIDs []string, probability float64, body string) {
	evt := blockEvent{
		Method:      r.Method,
		URI:         r.URL.RequestURI(),
		Headers:     headersToMap(r.Header),
		Body:        body,
		MatchedIDs:  matchedIDs,
		Probability: probability,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Source:      "ml_miss_detector",
		ClientIP:    extractClientIP(r),
	}
	data, _ := json.Marshal(evt)
	go func() {
		resp, err := b.client.Post(b.reportURL, "application/json", bytes.NewReader(data))
		if err != nil {
			log.Printf("Failed to report block event: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

func extractClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if idx := strings.IndexByte(ip, ','); idx >= 0 {
			return strings.TrimSpace(ip[:idx])
		}
		return strings.TrimSpace(ip)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

func isWebSocket(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (b *Blocker) getRateScore(ip string) float64 {
	now := time.Now()
	cutoff := now.Add(-time.Duration(b.rateWindowSec) * time.Second)

	b.rateMu.Lock()
	entry, exists := b.rateTracker[ip]
	if !exists {
		entry = &ipRateEntry{Timestamps: make([]time.Time, 0, 16)}
		b.rateTracker[ip] = entry
	}

	entry.Timestamps = append(entry.Timestamps, now)

	filtered := entry.Timestamps[:0]
	for _, ts := range entry.Timestamps {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	entry.Timestamps = filtered
	count := len(filtered)
	b.rateMu.Unlock()

	frequency := float64(count)
	baseline := float64(count) * 0.9
	if count < 2 {
		baseline = 1.0
	}

	frequencyScore := frequency / b.maxRateRPM
	if frequencyScore > 1.0 {
		frequencyScore = 1.0
	}

	var burstScore float64
	if baseline > 0.5 {
		ratio := (frequency - baseline) / baseline
		burstScore = ratio / (1.0 + ratio)
		if burstScore > 1.0 {
			burstScore = 1.0
		}
	} else {
		burstScore = 0.0
	}

	return 0.6*frequencyScore + 0.4*burstScore
}

func (b *Blocker) getRepScore(ip string) float64 {
	b.repMu.RLock()
	rep, exists := b.repCache[ip]
	b.repMu.RUnlock()
	if exists && time.Since(rep.Updated) < 5*time.Minute {
		return rep.RepScore
	}
	return 0.0
}

func (b *Blocker) isBlocked(ip string) bool {
	b.blocklistMu.RLock()
	entry, exists := b.blocklist[ip]
	b.blocklistMu.RUnlock()

	if !exists {
		return false
	}
	if time.Now().After(entry.ExpiresAt) {
		b.blocklistMu.Lock()
		delete(b.blocklist, ip)
		b.blocklistMu.Unlock()
		return false
	}
	return true
}

func (b *Blocker) addToBlocklist(ip string, reason string) {
	b.blocklistMu.Lock()
	b.blocklist[ip] = ipBlockEntry{
		ExpiresAt: time.Now().Add(b.blockTTL),
		Reason:    reason,
	}
	b.blocklistMu.Unlock()
	log.Printf("BLOCKLIST: added %s (reason: %s, TTL: %v)", ip, reason, b.blockTTL)
}

func (b *Blocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isWebSocket(r) {
		b.traffic.record(time.Now(), false)
		b.proxy.ServeHTTP(w, r)
		return
	}

	clientIP := extractClientIP(r)

	if b.isBlocked(clientIP) {
		log.Printf("BLOCKED (blocklist) %s %s from %s", r.Method, r.URL.RequestURI(), clientIP)
		b.traffic.record(time.Now(), true)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "blocked",
			"reason":  "ip_blocklisted",
			"message": "Your IP has been blocked by Layer 2 WAF",
		})
		return
	}

	headers := headersToMap(r.Header)

	uriMatched := b.prefilter.Evaluate(r.Method, r.URL.RequestURI(), "", headers)
	if len(uriMatched) == 0 {
		b.traffic.record(time.Now(), false)
		b.proxy.ServeHTTP(w, r)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	matched := b.prefilter.Evaluate(r.Method, r.URL.RequestURI(), string(bodyBytes), headers)
	if len(matched) == 0 {
		b.traffic.record(time.Now(), false)
		b.proxy.ServeHTTP(w, r)
		return
	}

	log.Printf("Regex matched [%s] for %s %s", strings.Join(matched, ", "), r.Method, r.URL.RequestURI())

	rateScore := b.getRateScore(clientIP)
	repScore := b.getRepScore(clientIP)

	evalResult, err := b.callEvalMiss(r.Method, r.URL.RequestURI(), headers, string(bodyBytes), rateScore, repScore)
	if err != nil {
		log.Printf("Eval-miss error (falling back to /predict-miss): %v", err)
		probability, err2 := b.callInference(r.Method, r.URL.RequestURI(), headers, string(bodyBytes))
		if err2 != nil {
			log.Printf("Inference error (fail-open): %v", err2)
			b.traffic.record(time.Now(), false)
			b.proxy.ServeHTTP(w, r)
			return
		}
		if probability >= b.GetThreshold() {
			log.Printf("BLOCKED (fallback) %s %s (p=%.4f >= %.2f)", r.Method, r.URL.RequestURI(), probability, b.GetThreshold())
			b.traffic.record(time.Now(), true)
			go b.reportBlock(r, matched, probability, string(bodyBytes))
			b.addToBlocklist(clientIP, fmt.Sprintf("ml_score=%.4f (fallback)", probability))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "blocked",
				"reason":  "ml_layer2",
				"score":   probability,
				"message": "Blocked by ML-based Layer 2 WAF",
			})
			return
		}
		log.Printf("ALLOWED (fallback) %s %s (p=%.4f < %.2f)", r.Method, r.URL.RequestURI(), probability, b.GetThreshold())
		b.traffic.record(time.Now(), false)
		b.proxy.ServeHTTP(w, r)
		return
	}

	log.Printf("Eval: %s %s ml=%.4f rate=%.4f rep=%.4f composite=%.4f decision=%s",
		r.Method, r.URL.RequestURI(), evalResult.MLScore, evalResult.RateScore, evalResult.RepScore,
		evalResult.Composite, evalResult.Decision)

	threshold := b.GetThreshold()
	if evalResult.Composite >= threshold {
		log.Printf("BLOCKED %s %s (composite=%.4f >= %.2f)", r.Method, r.URL.RequestURI(), evalResult.Composite, threshold)
		b.traffic.record(time.Now(), true)
		go b.reportBlock(r, matched, evalResult.MLScore, string(bodyBytes))
		b.addToBlocklist(clientIP, fmt.Sprintf("composite=%.4f ml=%.4f rate=%.4f rep=%.4f",
			evalResult.Composite, evalResult.MLScore, evalResult.RateScore, evalResult.RepScore))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "blocked",
			"reason":    "ml_layer2",
			"score":     evalResult.MLScore,
			"composite": evalResult.Composite,
			"breakdown": evalResult.Breakdown,
			"message":   "Blocked by ML-based Layer 2 WAF",
		})
		return
	}

	log.Printf("ALLOWED %s %s (composite=%.4f < %.2f)", r.Method, r.URL.RequestURI(), evalResult.Composite, threshold)
	b.traffic.record(time.Now(), false)
	b.proxy.ServeHTTP(w, r)
}

func (b *Blocker) handleTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	now := time.Now()
	total, blocked, allowed := b.traffic.liveRPM(now)
	json.NewEncoder(w).Encode(trafficSnapshot{
		Timestamp:      now.UTC(),
		RequestsPerMin: total,
		BlockedPerMin:  blocked,
		AllowedPerMin:  allowed,
	})
}

func (b *Blocker) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (b *Blocker) handleThreshold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Threshold float64 `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Threshold < 0.85 || req.Threshold > 1.0 {
		http.Error(w, "Threshold must be between 0.85 and 1.0", http.StatusBadRequest)
		return
	}
	b.SetThreshold(req.Threshold)
	log.Printf("Threshold updated to %.2f", req.Threshold)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"threshold": b.GetThreshold(),
	})
}

func (b *Blocker) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	now := time.Now()

	switch r.Method {
	case http.MethodGet:
		b.blocklistMu.RLock()
		type entry struct {
			IP        string `json:"ip"`
			ExpiresIn string `json:"expires_in"`
			Reason    string `json:"reason"`
		}
		var entries []entry
		for ip, e := range b.blocklist {
			if now.After(e.ExpiresAt) {
				continue
			}
			entries = append(entries, entry{
				IP:        ip,
				ExpiresIn: e.ExpiresAt.Sub(now).Round(time.Second).String(),
				Reason:    e.Reason,
			})
		}
		b.blocklistMu.RUnlock()
		if entries == nil {
			entries = []entry{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(entries),
			"entries": entries,
		})

	case http.MethodDelete:
		ip := strings.TrimPrefix(r.URL.Path, "/api/waf/blocklist/")
		if ip == "" || ip == r.URL.Path {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}
		b.blocklistMu.Lock()
		delete(b.blocklist, ip)
		b.blocklistMu.Unlock()
		log.Printf("BLOCKLIST: removed %s (manual unblock)", ip)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "ip": ip})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (b *Blocker) handleReputation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP       string  `json:"ip"`
		RepScore float64 `json:"rep_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	b.repMu.Lock()
	b.repCache[req.IP] = ipReputation{
		RepScore: req.RepScore,
		Updated:  time.Now(),
	}
	b.repMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	signaturesFile := env("SIGNATURES_FILE", "/app/signatures/modintel_regex.signatures")
	inferenceURL := env("INFERENCE_URL", "http://inference-engine:8083/predict-miss")
	backendURL := env("BACKEND_URL", "http://juice-shop:3000")
	reportURL := env("REPORT_URL", "http://log-collector:8081/api/waf/block-event")
	listenAddr := env("LISTEN_ADDR", ":8086")
	blockThreshold := 0.85

	log.Printf("Loading signatures from %s", signaturesFile)
	prefilter, err := LoadPrefilter(signaturesFile)
	if err != nil {
		log.Fatalf("Failed to load signatures: %v", err)
	}
	log.Printf("Loaded %d signature patterns", len(prefilter.patterns))

	blocker := NewBlocker(prefilter, inferenceURL, backendURL, reportURL, blockThreshold)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/waf/traffic", blocker.handleTraffic)
	mux.HandleFunc("/api/waf/threshold", blocker.handleThreshold)
	mux.HandleFunc("/api/waf/blocklist/", blocker.handleBlocklist)
	mux.HandleFunc("/api/waf/blocklist", blocker.handleBlocklist)
	mux.HandleFunc("/api/waf/reputation", blocker.handleReputation)
	mux.HandleFunc("/health", blocker.handleHealth)
	mux.Handle("/", blocker)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting waf-blocker on %s (threshold=%.2f, eval-miss=%s, backend=%s, report=%s)",
		listenAddr, blockThreshold, blocker.evalMissURL, backendURL, reportURL)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
