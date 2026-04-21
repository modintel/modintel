package api
  
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modintel_api_requests_total",
			Help: "Total API requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "modintel_api_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"method", "endpoint"},
	)
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "modintel_api_active_connections",
			Help: "Number of active connections",
		},
	)
	inferenceRequestsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "modintel_inference_requests_total",
			Help: "Total inference requests through review-api",
		},
	)
	totalRequests    atomic.Uint64
	totalErrors      atomic.Uint64
	requestStats     = newRequestWindowStats()
	ruleIDPattern    = regexp.MustCompile(`^[0-9]+$`)
	restartInFlight  atomic.Bool
	dockerHTTPClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, "unix", "/var/run/docker.sock")
			},
			DisableKeepAlives: true,
		},
		Timeout: 15 * time.Second,
	}
)

type requestMinuteBucket struct {
	Requests uint64
	Errors   uint64
}

type requestWindowStats struct {
	mu      sync.Mutex
	buckets map[int64]*requestMinuteBucket
}

func newRequestWindowStats() *requestWindowStats {
	return &requestWindowStats{buckets: make(map[int64]*requestMinuteBucket)}
}

func (s *requestWindowStats) record(ts time.Time, isError bool) {
	minute := ts.UTC().Truncate(time.Minute).Unix()
	cutoff := minute - int64((24*time.Hour)/time.Minute)

	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.buckets[minute]
	if !ok {
		bucket = &requestMinuteBucket{}
		s.buckets[minute] = bucket
	}
	bucket.Requests++
	if isError {
		bucket.Errors++
	}

	for key := range s.buckets {
		if key < cutoff {
			delete(s.buckets, key)
		}
	}
}

func (s *requestWindowStats) totals(window time.Duration, now time.Time) (uint64, uint64) {
	if window <= 0 {
		window = time.Hour
	}

	startMinute := now.UTC().Add(-window).Truncate(time.Minute).Unix()
	endMinute := now.UTC().Truncate(time.Minute).Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	var requests uint64
	var errors uint64
	for minute, bucket := range s.buckets {
		if minute < startMinute || minute > endMinute {
			continue
		}
		requests += bucket.Requests
		errors += bucket.Errors
	}

	return requests, errors
}

type WAFRule struct {
	ID          string    `json:"id" bson:"id"`
	Category    string    `json:"category" bson:"category"`
	Description string    `json:"description" bson:"description"`
	Enabled     bool      `json:"enabled" bson:"enabled"`
	UpdatedAt   time.Time `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
}

type toggleRuleRequest struct {
	Enabled *bool `json:"enabled"`
}

var defaultWAFRules = []WAFRule{
	{ID: "990001", Category: "LFI", Description: "Custom LFI Protection: etc/passwd access denied", Enabled: true},
	{ID: "990002", Category: "LFI", Description: "Custom LFI Protection: etc/shadow access denied", Enabled: true},
	{ID: "990003", Category: "LFI", Description: "Custom LFI Protection: Windows System32 access denied", Enabled: true},
	{ID: "990004", Category: "CMDi", Description: "Custom CMDi Protection: Backtick operator detected", Enabled: true},
	{ID: "990005", Category: "RCE", Description: "Custom Log4Shell Protection: JNDI in User-Agent", Enabled: true},
	{ID: "990006", Category: "Protocol", Description: "Custom Protocol Protection: CRLF Injection detected", Enabled: true},
	{ID: "990007", Category: "XXE", Description: "Custom XXE Protection: DTD/Entity detected in body", Enabled: true},
	{ID: "990008", Category: "NoSQLi", Description: "Custom NoSQLi Protection: MongoDB operator detected", Enabled: true},
	{ID: "990009", Category: "NoSQLi", Description: "Custom NoSQLi Protection: URI based NoSQLi detected", Enabled: true},
	{ID: "990010", Category: "NoSQLi", Description: "Custom NoSQLi Protection: $where operator detected", Enabled: true},
	{ID: "990011", Category: "SSTI", Description: "Custom SSTI Protection: Handlebars Template markers detected", Enabled: true},
	{ID: "990012", Category: "SSTI", Description: "Custom SSTI Protection: EL/JEXL Template markers detected", Enabled: true},
	{ID: "990020", Category: "SQLi", Description: "Custom SQLi Protection: SQL keyword detected", Enabled: true},
	{ID: "990021", Category: "SQLi", Description: "Custom SQLi Protection: SQL keyword in URI detected", Enabled: true},
	{ID: "990022", Category: "SQLi", Description: "Custom SQLi Protection: SQL phrase detected", Enabled: true},
	{ID: "990023", Category: "SQLi", Description: "Custom SQLi Protection: OR/AND 1=1 detected", Enabled: true},
	{ID: "990024", Category: "SQLi", Description: "Custom SQLi Protection: Time-based SQL injection detected", Enabled: true},
	{ID: "990030", Category: "XSS", Description: "Custom XSS Protection: HTML tag detected", Enabled: true},
	{ID: "990031", Category: "XSS", Description: "Custom XSS Protection: Event handler detected", Enabled: true},
	{ID: "990032", Category: "XSS", Description: "Custom XSS Protection: javascript: URI detected", Enabled: true},
	{ID: "990033", Category: "XSS", Description: "Custom XSS Protection: JS function detected", Enabled: true},
	{ID: "990040", Category: "CMDi", Description: "Custom CMDi Protection: Pipe command detected", Enabled: true},
	{ID: "990041", Category: "CMDi", Description: "Custom CMDi Protection: Command injection chars detected", Enabled: true},
	{ID: "990042", Category: "CMDi", Description: "Custom CMDi Protection: Shell command in URI", Enabled: true},
	{ID: "990050", Category: "SSRF", Description: "Custom SSRF Protection: URL scheme detected", Enabled: true},
	{ID: "990051", Category: "SSRF", Description: "Custom SSRF Protection: Localhost/internal IP detected", Enabled: true},
}

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(inferenceRequestsTotal)
}

func SetupRouter() *gin.Engine {
	r := gin.Default()
	jwtSecret := os.Getenv("JWT_SECRET")

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(requestTracker())

	r.GET("/health", HealthCheck)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.GET("/api/whoami", AuthMiddleware(jwtSecret), GetWhoAmI)

	api := r.Group("/api")
	api.Use(AuthMiddleware(jwtSecret))
	api.Use(AuthAuditLog())
	{
		api.GET("/rules", RequireRoles("admin", "analyst", "viewer"), GetRules)
		api.PUT("/rules/:id", RequireRoles("admin"), UpdateRuleStatus)
		api.GET("/alerts", RequireRoles("admin", "analyst", "viewer"), GetAlerts)
		api.GET("/logs", RequireRoles("admin", "analyst", "viewer"), GetLogs)
		api.GET("/stats", RequireRoles("admin", "analyst", "viewer"), GetStats)
		api.GET("/trend", RequireRoles("admin", "analyst", "viewer"), GetTrend)
		api.GET("/config", RequireRoles("admin", "analyst", "viewer"), GetConfig)
		api.GET("/monitor/health", RequireRoles("admin", "analyst", "viewer"), GetmonitorHealth)
		api.GET("/monitor/metrics", RequireRoles("admin", "analyst", "viewer"), GetmonitorMetrics)
		api.POST("/system/restart/proxy-waf", RequireRoles("admin"), RestartProxyWAF)
		api.DELETE("/logs", RequireRoles("admin", "analyst"), ClearLogs)
	}
	return r
}

type dockerContainerInfo struct {
	ID string `json:"Id"`
}

func RestartProxyWAF(c *gin.Context) {
	if !restartInFlight.CompareAndSwap(false, true) {
		c.JSON(http.StatusAccepted, gin.H{"success": true, "service": "proxy-waf", "status": "restart_already_queued"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()

	containerID, err := dockerFindComposeServiceContainer(ctx, "proxy-waf")
	if err != nil {
		restartInFlight.Store(false)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy-waf container not found"})
		return
	}

	go func(id string) {
		defer restartInFlight.Store(false)
		bgCtx, cancelBg := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelBg()
		if restartErr := dockerRestartContainer(bgCtx, id); restartErr != nil {
			log.Printf("failed restarting proxy-waf container=%s error=%v", id, restartErr)
		}
	}(containerID)

	c.JSON(http.StatusAccepted, gin.H{"success": true, "service": "proxy-waf", "status": "restart_queued"})
}

func dockerFindComposeServiceContainer(ctx context.Context, service string) (string, error) {
	labels := []string{fmt.Sprintf("com.docker.compose.service=%s", service)}
	project := strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME"))
	if project == "" {
		project = strings.TrimSpace(os.Getenv("PROJECT_NAME"))
	}
	if project != "" {
		labels = append(labels, fmt.Sprintf("com.docker.compose.project=%s", project))
	}

	filterPayload := map[string][]string{"label": labels}
	filterBytes, err := json.Marshal(filterPayload)
	if err != nil {
		return "", err
	}

	filters := string(filterBytes)
	path := fmt.Sprintf("http://docker/containers/json?filters=%s", url.QueryEscape(filters))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}

	resp, err := dockerHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("docker api returned status %d", resp.StatusCode)
	}

	containers := make([]dockerContainerInfo, 0)
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return "", err
	}

	if len(containers) == 0 {
		return "", fmt.Errorf("no container found for compose service %s", service)
	}

	return containers[0].ID, nil
}

func dockerRestartContainer(ctx context.Context, containerID string) error {
	path := fmt.Sprintf("http://docker/containers/%s/restart?t=10", url.PathEscape(containerID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, nil)
	if err != nil {
		return err
	}

	resp, err := dockerHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("docker api returned status %d", resp.StatusCode)
	}

	return nil
}

func requestTracker() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		now := time.Now().UTC()
		statusCode := c.Writer.Status()
		isErr := statusCode >= 400
		totalRequests.Add(1)
		requestStats.record(now, isErr)
		if isErr {
			totalErrors.Add(1)
		}
	}
}

func GetRules(c *gin.Context) {
	params, err := parseOffsetParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")

	rules := make([]WAFRule, 0, len(defaultWAFRules))
	rules = append(rules, defaultWAFRules...)

	cursor, err := ruleColl.Find(ctx, bson.M{})
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var override WAFRule
			if decodeErr := cursor.Decode(&override); decodeErr != nil {
				continue
			}
			for i := range rules {
				if rules[i].ID == override.ID {
					rules[i].Enabled = override.Enabled
					rules[i].UpdatedAt = override.UpdatedAt
					break
				}
			}
		}
	}

	totalCount := int64(len(rules))
	totalPages := int((totalCount + int64(params.Limit) - 1) / int64(params.Limit))
	skip := (params.Page - 1) * params.Limit

	start := skip
	end := skip + params.Limit
	if start > len(rules) {
		start = len(rules)
	}
	if end > len(rules) {
		end = len(rules)
	}
	paginatedRules := rules[start:end]

	response := OffsetResponse{
		Data:       paginatedRules,
		Page:       params.Page,
		PageSize:   params.Limit,
		TotalCount: totalCount,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func UpdateRuleStatus(c *gin.Context) {
	ruleID := strings.TrimSpace(c.Param("id"))
	if ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule id is required"})
		return
	}

	if !ruleIDPattern.MatchString(ruleID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id format"})
		return
	}

	known := false
	for _, rule := range defaultWAFRules {
		if rule.ID == ruleID {
			known = true
			break
		}
	}
	if !known {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var req toggleRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")
	_, err := ruleColl.UpdateOne(
		ctx,
		bson.M{"id": ruleID},
		bson.M{"$set": bson.M{"enabled": *req.Enabled, "updated_at": time.Now().UTC()}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed updating rule status"})
		return
	}

	if err := syncManagedWAFOverrides(ctx); err != nil {
		log.Printf("failed syncing managed overrides: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed syncing waf overrides"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "id": ruleID, "enabled": *req.Enabled})
}

func getWAFOverridesFilePath() string {
	path := strings.TrimSpace(os.Getenv("WAF_OVERRIDES_FILE"))
	if path == "" {
		path = "/waf-overrides/managed-overrides.conf"
	}
	return path
}

func syncManagedWAFOverrides(ctx context.Context) error {
	ruleColl := db.GetCollection("modintel", "waf_rules")

	cur, err := ruleColl.Find(ctx, bson.M{"enabled": false})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)

	disabledIDs := make([]string, 0)
	for cur.Next(ctx) {
		var rec struct {
			ID string `bson:"id"`
		}
		if decodeErr := cur.Decode(&rec); decodeErr != nil {
			continue
		}
		id := strings.TrimSpace(rec.ID)
		if id == "" || !ruleIDPattern.MatchString(id) {
			continue
		}
		disabledIDs = append(disabledIDs, id)
	}

	sort.Strings(disabledIDs)

	content := strings.Builder{}
	content.WriteString("# Auto-generated by review-api. Do not edit manually.\n")
	content.WriteString(fmt.Sprintf("# Generated at %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	for _, id := range disabledIDs {
		content.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", id))
	}

	overridesPath := getWAFOverridesFilePath()
	if err := os.MkdirAll(filepath.Dir(overridesPath), 0o755); err != nil {
		return err
	}

	if err := os.WriteFile(overridesPath, []byte(content.String()), 0o644); err != nil {
		return err
	}

	return nil
}

func GetConfig(c *gin.Context) {
	backendTarget := os.Getenv("BACKEND_TARGET")
	inferenceURL := os.Getenv("INFERENCE_ENGINE_URL")
	wafEngine := os.Getenv("WAF_ENGINE")

	if wafEngine == "" {
		wafEngine = "Coraza (Caddy edge)"
	}

	if backendTarget == "" {
		backendTarget = "not-set"
	}

	if inferenceURL == "" {
		inferenceURL = "not-set"
	}

	c.JSON(http.StatusOK, gin.H{
		"waf_engine":           wafEngine,
		"backend_target":       backendTarget,
		"inference_engine_url": inferenceURL,
	})
}

func GetWhoAmI(c *gin.Context) {
	claimsAny, exists := c.Get("access_claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	claims, ok := claimsAny.(*AccessClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"user_id": claims.UserID,
			"email":   claims.Email,
			"role":    claims.Role,
		},
	})
}

func parseAlertTimestamp(raw string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
		"02/Jan/2006:15:04:05 -0700",
		"2006-01-02T15:04:05Z07:00",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}

	if t, err := time.Parse(time.RFC1123Z, raw); err == nil {
		return t.UTC(), true
	}

	return time.Time{}, false
}

func GetTrend(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rangeType := c.DefaultQuery("range", "day")
	now := time.Now().UTC()

	var bucketCount int
	var bucketSize time.Duration
	var start time.Time

	switch rangeType {
	case "week":
		bucketCount = 84
		bucketSize = 2 * time.Hour
		start = now.Truncate(2 * time.Hour).Add(-time.Duration(bucketCount-1) * bucketSize)
	case "month":
		bucketCount = 120
		bucketSize = 6 * time.Hour
		start = now.Truncate(6 * time.Hour).Add(-time.Duration(bucketCount-1) * bucketSize)
	case "day":
		bucketCount = 96
		bucketSize = 15 * time.Minute
		start = now.Truncate(15 * time.Minute).Add(-time.Duration(bucketCount-1) * bucketSize)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "range must be day, week, or month"})
		return
	}

	values := make([]int, bucketCount)
	labels := make([]string, bucketCount)

	for i := 0; i < bucketCount; i++ {
		bucketTime := start.Add(time.Duration(i) * bucketSize)
		if rangeType == "day" {
			labels[i] = bucketTime.Format("15:04")
		} else if rangeType == "week" {
			labels[i] = bucketTime.Format("Mon 15:04")
		} else {
			labels[i] = bucketTime.Format("02 Jan 15:04")
		}
	}

	opts := options.Find().SetProjection(bson.M{"timestamp": 1})
	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		log.Println("Error fetching trend data:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var record bson.M
		if err := cursor.Decode(&record); err != nil {
			continue
		}

		rawTS, ok := record["timestamp"].(string)
		if !ok || rawTS == "" {
			continue
		}

		ts, ok := parseAlertTimestamp(rawTS)
		if !ok || ts.Before(start) || ts.After(now.Add(time.Minute)) {
			continue
		}

		idx := int(ts.Sub(start) / bucketSize)
		if idx >= 0 && idx < bucketCount {
			values[idx]++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"range":  rangeType,
		"labels": labels,
		"values": values,
	})
}

func GetLogs(c *gin.Context) {
	params, err := parseCursorParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filter, err := buildCursorFilter(params.Cursor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "_id", Value: 1}}).
		SetLimit(int64(params.Limit + 1)).
		SetProjection(bson.M{
			"_id":                    1,
			"timestamp":              1,
			"client_ip":              1,
			"uri":                    1,
			"anomaly_score":          1,
			"triggered_rules":        1,
			"ai_status":              1,
			"ai_score":               1,
			"ai_confidence":          1,
			"ai_priority":            1,
			"ai_explanation":         1,
			"ai_model_version":       1,
			"ai_entropy":             1,
			"ai_confidence_interval": 1,
		})
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		log.Println("Error finding logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err := cursor.All(ctx, &results); err != nil {
		log.Println("Error decoding logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	var nextCursor *string
	if len(results) > params.Limit {
		results = results[:params.Limit]
		if lastID, ok := results[len(results)-1]["_id"].(primitive.ObjectID); ok {
			cursorStr := lastID.Hex()
			nextCursor = &cursorStr
		}
	}

	type AlertResponse struct {
		Timestamp            string                 `json:"timestamp"`
		ClientIP             string                 `json:"client_ip"`
		URI                  string                 `json:"uri"`
		AnomalyScore         float64                `json:"anomaly_score"`
		TriggeredRules       []string               `json:"triggered_rules"`
		AIStatus             string                 `json:"ai_status"`
		AIScore              *float64               `json:"ai_score"`
		AIConfidence         *float64               `json:"ai_confidence"`
		AIPriority           *string                `json:"ai_priority"`
		AIExplanation        map[string]interface{} `json:"ai_explanation"`
		AIModelVersion       *string                `json:"ai_model_version"`
		AIEntropy            *float64               `json:"ai_entropy"`
		AIConfidenceInterval *map[string]float64    `json:"ai_confidence_interval"`
	}

	alerts := make([]AlertResponse, 0, len(results))
	for _, r := range results {
		alert := AlertResponse{
			Timestamp:      r["timestamp"].(string),
			ClientIP:       r["client_ip"].(string),
			URI:            r["uri"].(string),
			TriggeredRules: []string{},
		}

		if score, ok := r["anomaly_score"].(float64); ok {
			alert.AnomalyScore = score
		}

		if rules, ok := r["triggered_rules"].(bson.A); ok {
			for _, r := range rules {
				alert.TriggeredRules = append(alert.TriggeredRules, r.(string))
			}
		}

		if status, ok := r["ai_status"].(string); ok {
			alert.AIStatus = status
		}
		if score, ok := r["ai_score"].(float64); ok {
			alert.AIScore = &score
		}
		if conf, ok := r["ai_confidence"].(float64); ok {
			alert.AIConfidence = &conf
		}
		if priority, ok := r["ai_priority"].(string); ok {
			alert.AIPriority = &priority
		}
		if expl, ok := r["ai_explanation"].(map[string]interface{}); ok {
			alert.AIExplanation = expl
		}
		if modelVer, ok := r["ai_model_version"].(string); ok {
			alert.AIModelVersion = &modelVer
		}
		if entropy, ok := r["ai_entropy"].(float64); ok {
			alert.AIEntropy = &entropy
		}
		if ci, ok := r["ai_confidence_interval"].(map[string]interface{}); ok {
			interval := make(map[string]float64)
			if low, ok := ci["low"].(float64); ok {
				interval["low"] = low
			}
			if high, ok := ci["high"].(float64); ok {
				interval["high"] = high
			}
			if len(interval) > 0 {
				alert.AIConfidenceInterval = &interval
			}
		}

		alerts = append(alerts, alert)
	}

	response := CursorResponse{
		Data:       alerts,
		NextCursor: nextCursor,
		Limit:      params.Limit,
	}

	c.JSON(http.StatusOK, response)
}

func GetAlerts(c *gin.Context) {
	params, err := parseCursorParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filter, err := buildCursorFilter(params.Cursor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "_id", Value: 1}}).
		SetLimit(int64(params.Limit + 1)).
		SetProjection(bson.M{
			"_id":                    1,
			"timestamp":              1,
			"client_ip":              1,
			"uri":                    1,
			"anomaly_score":          1,
			"triggered_rules":        1,
			"ai_status":              1,
			"ai_score":               1,
			"ai_confidence":          1,
			"ai_priority":            1,
			"ai_explanation":         1,
			"ai_model_version":       1,
			"ai_entropy":             1,
			"ai_confidence_interval": 1,
		})
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		log.Println("Error finding alerts:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	if err := cursor.All(ctx, &results); err != nil {
		log.Println("Error decoding alerts:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	var nextCursor *string
	if len(results) > params.Limit {
		results = results[:params.Limit]
		if lastID, ok := results[len(results)-1]["_id"].(primitive.ObjectID); ok {
			cursorStr := lastID.Hex()
			nextCursor = &cursorStr
		}
	}

	type AlertResponse struct {
		Timestamp            string                 `json:"timestamp"`
		ClientIP             string                 `json:"client_ip"`
		URI                  string                 `json:"uri"`
		AnomalyScore         float64                `json:"anomaly_score"`
		TriggeredRules       []string               `json:"triggered_rules"`
		AIStatus             string                 `json:"ai_status"`
		AIScore              *float64               `json:"ai_score"`
		AIConfidence         *float64               `json:"ai_confidence"`
		AIPriority           *string                `json:"ai_priority"`
		AIExplanation        map[string]interface{} `json:"ai_explanation"`
		AIModelVersion       *string                `json:"ai_model_version"`
		AIEntropy            *float64               `json:"ai_entropy"`
		AIConfidenceInterval *map[string]float64    `json:"ai_confidence_interval"`
	}

	alerts := make([]AlertResponse, 0, len(results))
	for _, r := range results {
		alert := AlertResponse{
			Timestamp:      r["timestamp"].(string),
			ClientIP:       r["client_ip"].(string),
			URI:            r["uri"].(string),
			TriggeredRules: []string{},
		}

		if score, ok := r["anomaly_score"].(float64); ok {
			alert.AnomalyScore = score
		}

		if rules, ok := r["triggered_rules"].(bson.A); ok {
			for _, r := range rules {
				alert.TriggeredRules = append(alert.TriggeredRules, r.(string))
			}
		}

		if status, ok := r["ai_status"].(string); ok {
			alert.AIStatus = status
		}
		if score, ok := r["ai_score"].(float64); ok {
			alert.AIScore = &score
		}
		if conf, ok := r["ai_confidence"].(float64); ok {
			alert.AIConfidence = &conf
		}
		if priority, ok := r["ai_priority"].(string); ok {
			alert.AIPriority = &priority
		}
		if expl, ok := r["ai_explanation"].(map[string]interface{}); ok {
			alert.AIExplanation = expl
		}
		if modelVer, ok := r["ai_model_version"].(string); ok {
			alert.AIModelVersion = &modelVer
		}
		if entropy, ok := r["ai_entropy"].(float64); ok {
			alert.AIEntropy = &entropy
		}
		if ci, ok := r["ai_confidence_interval"].(map[string]interface{}); ok {
			interval := make(map[string]float64)
			if low, ok := ci["low"].(float64); ok {
				interval["low"] = low
			}
			if high, ok := ci["high"].(float64); ok {
				interval["high"] = high
			}
			if len(interval) > 0 {
				alert.AIConfidenceInterval = &interval
			}
		}

		alerts = append(alerts, alert)
	}

	response := CursorResponse{
		Data:       alerts,
		NextCursor: nextCursor,
		Limit:      params.Limit,
	}

	c.JSON(http.StatusOK, response)
}

func GetStats(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Println("Error counting alerts:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var result bson.M
	err = collection.FindOne(ctx, bson.M{}, opts).Decode(&result)
	latestRule := "—"
	latestPriority := "—"
	if err == nil {
		if rules, ok := result["triggered_rules"].(bson.A); ok && len(rules) > 0 {
			if rule, ok := rules[0].(string); ok {
				latestRule = rule
			}
		}
		if priority, ok := result["ai_priority"].(string); ok && priority != "" {
			latestPriority = priority
		}
	}

	aiEnrichedCount, err := collection.CountDocuments(ctx, bson.M{"ai_status": "enriched"})
	if err != nil {
		log.Println("Error counting AI enriched documents:", err)
		aiEnrichedCount = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":      total,
		"latest_rule":       latestRule,
		"latest_priority":   latestPriority,
		"ai_enriched_count": aiEnrichedCount,
	})
}

func ClearLogs(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := collection.DeleteMany(ctx, bson.M{})
	if err != nil {
		log.Println("Error clearing logs:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": result.DeletedCount})
}

func HealthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.Client.Ping(ctx, nil)
	status := "ok"
	statusCode := http.StatusOK

	if err != nil {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, gin.H{
		"status":  status,
		"service": "review-api",
	})
}

func GetmonitorHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	services := map[string]string{
		"review-api": "ok",
	}

	if err := db.Client.Ping(ctx, nil); err != nil {
		services["review-api"] = "degraded"
	}

	services["log-collector"] = checkHTTPService("http://log-collector:8081/health", 3*time.Second)
	services["inference-engine"] = checkHTTPService("http://inference-engine:8083/health", 3*time.Second)
	services["proxy-waf"] = checkTCPService("proxy-waf", 8080, 3*time.Second)

	c.JSON(http.StatusOK, gin.H{
		"services":  services,
		"timestamp": time.Now().UTC(),
	})
}

func checkHTTPService(url string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "unknown"
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "down"
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "ok"
	}
	return "degraded"
}

func checkTCPService(host string, port int, timeout time.Duration) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "down"
	}
	conn.Close()
	return "ok"
}

func GetmonitorMetrics(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

	totalAlerts, _ := collection.CountDocuments(ctx, bson.M{})
	aiEnrichedCount, _ := collection.CountDocuments(ctx, bson.M{"ai_status": "enriched"})

	inferenceMetrics := getInferenceMetrics()
	systemMetrics := getSystemMetrics(ctx)
	window := parseMetricsWindow(c.Query("range"))
	windowRequests, windowErrors := requestStats.totals(window, time.Now().UTC())

	var errorRate float64
	if windowRequests > 0 {
		errorRate = float64(windowErrors) / float64(windowRequests)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":             totalAlerts,
		"ai_enriched_count":        aiEnrichedCount,
		"avg_inference_ms":         inferenceMetrics.avgLatencyMs,
		"p50_latency_ms":           inferenceMetrics.p50LatencyMs,
		"p95_latency_ms":           inferenceMetrics.p95LatencyMs,
		"p99_latency_ms":           inferenceMetrics.p99LatencyMs,
		"total_predictions":        inferenceMetrics.totalPredictions,
		"predictions_per_minute":   inferenceMetrics.predictionsPerMinute,
		"model_version":            inferenceMetrics.modelVersion,
		"inference_uptime_seconds": inferenceMetrics.uptimeSeconds,
		"requests_per_minute":      inferenceMetrics.predictionsPerMinute,
		"error_rate":               errorRate,
		"error_rate_window":        window.String(),
		"window_requests":          windowRequests,
		"window_errors":            windowErrors,
		"total_requests":           totalRequests.Load(),
		"total_errors":             totalErrors.Load(),
		"mongodb_connections":      systemMetrics.MongoDBConnections,
		"timestamp":                time.Now().UTC(),
		"system":                   systemMetrics,
	})
}

func parseMetricsWindow(raw string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "5m":
		return 5 * time.Minute
	case "15m":
		return 15 * time.Minute
	case "30m":
		return 30 * time.Minute
	case "6h":
		return 6 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "1h", "":
		return time.Hour
	default:
		return time.Hour
	}
}

type inferenceMetricsData struct {
	avgLatencyMs         float64
	p50LatencyMs         float64
	p95LatencyMs         float64
	p99LatencyMs         float64
	totalPredictions     int
	predictionsPerMinute float64
	modelVersion         string
	uptimeSeconds        float64
}

func getInferenceMetrics() inferenceMetricsData {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://inference-engine:8083/metrics", nil)
	if err != nil {
		return inferenceMetricsData{}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return inferenceMetricsData{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return inferenceMetricsData{}
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return inferenceMetricsData{}
	}

	metrics := inferenceMetricsData{}

	if v, ok := result["avg_inference_latency_ms"].(float64); ok {
		metrics.avgLatencyMs = v
	}
	if v, ok := result["p50_latency_ms"].(float64); ok {
		metrics.p50LatencyMs = v
	}
	if v, ok := result["p95_latency_ms"].(float64); ok {
		metrics.p95LatencyMs = v
	}
	if v, ok := result["p99_latency_ms"].(float64); ok {
		metrics.p99LatencyMs = v
	}
	if v, ok := result["total_predictions"].(float64); ok {
		metrics.totalPredictions = int(v)
	}
	if v, ok := result["predictions_per_minute"].(float64); ok {
		metrics.predictionsPerMinute = v
	}
	if v, ok := result["model_version"].(string); ok {
		metrics.modelVersion = v
	}
	if v, ok := result["uptime_seconds"].(float64); ok {
		metrics.uptimeSeconds = v
	}

	return metrics
}

type systemMetricsData struct {
	Hostname            string  `json:"hostname"`
	GoVersion           string  `json:"go_version"`
	UptimeSeconds       float64 `json:"uptime_seconds"`
	CpuPercent          float64 `json:"cpu_percent"`
	MemoryUsedMB        uint64  `json:"memory_used_mb"`
	MemoryTotalMB       uint64  `json:"memory_total_mb"`
	MemoryPercent       float64 `json:"memory_percent"`
	Goroutines          int     `json:"goroutines"`
	MongoDBConnections  int64   `json:"mongodb_connections"`
	MongoDBDatabaseSize int64   `json:"mongodb_database_size_bytes"`
	MongoDBAlertCount   int64   `json:"mongodb_alert_count"`
}

func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

var serviceStartTime = time.Now()

func getSystemMetrics(ctx context.Context) systemMetricsData {
	metrics := systemMetricsData{
		Hostname:      getHostname(),
		GoVersion:     runtime.Version(),
		UptimeSeconds: time.Since(serviceStartTime).Seconds(),
		Goroutines:    runtime.NumGoroutine(),
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.MemoryUsedMB = m.Alloc / (1024 * 1024)
	metrics.MemoryTotalMB = m.TotalAlloc / (1024 * 1024)
	if m.TotalAlloc > 0 {
		metrics.MemoryPercent = float64(m.Alloc) / float64(m.TotalAlloc) * 100
	}

	metrics.CpuPercent = getCPULoad()

	if db.Client != nil {
		dbName := "modintel"

		if err := db.Client.Ping(ctx, nil); err == nil {
			var serverStatus bson.M
			serverStatusCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			err = db.Client.Database("admin").RunCommand(serverStatusCtx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&serverStatus)
			if err == nil {
				if connections, ok := serverStatus["connections"].(bson.M); ok {
					switch current := connections["current"].(type) {
					case int32:
						metrics.MongoDBConnections = int64(current)
					case int64:
						metrics.MongoDBConnections = current
					case float64:
						metrics.MongoDBConnections = int64(current)
					}
				}
			}
		}

		alertColl := db.GetCollection(dbName, "alerts")
		count, err := alertColl.CountDocuments(ctx, bson.M{})
		if err == nil {
			metrics.MongoDBAlertCount = count
		}

		var dbStats bson.M
		dbStatsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = db.Client.Database(dbName).RunCommand(dbStatsCtx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&dbStats)
		if err == nil {
			if size, ok := toInt64(dbStats["storageSize"]); ok && size > 0 {
				metrics.MongoDBDatabaseSize = size
			} else if size, ok := toInt64(dbStats["dataSize"]); ok {
				metrics.MongoDBDatabaseSize = size
			}
		}
	}

	return metrics
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

func getCPULoad() float64 {
	return 0.0
}
