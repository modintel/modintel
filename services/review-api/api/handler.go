package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	totalRequests    atomic.Uint64
	totalErrors      atomic.Uint64
	requestStats     = newRequestWindowStats()
	ruleIDPattern    = regexp.MustCompile(`^[0-9]+$`)
	restartInFlight  atomic.Bool
	wafConfigPath    = "/waf-overrides/waf-config.json"
	cpuMu            sync.Mutex
	cpuLastTotal     uint64
	cpuLastIdle      uint64
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

type updateRuleRequest struct {
	Enabled     *bool  `json:"enabled"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Phase       int    `json:"phase"`
	Signature   string `json:"signature"`
}

func SetupRouter() *gin.Engine {
	r := gin.Default()
	jwtSecret := os.Getenv("JWT_SECRET")

	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Header("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' http: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		c.Next()
	})

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
	r.GET("/api/events/stream", SSEAuth(jwtSecret), SSEStreamHandler)
	r.GET("/api/whoami", AuthMiddleware(jwtSecret), GetWhoAmI)

	authProxy := r.Group("/api/v1/auth")
	{
		authProxy.POST("/login", ProxyToAuthService)
		authProxy.POST("/refresh", ProxyToAuthService)
		authProxy.POST("/logout", ProxyToAuthService)
		authProxy.GET("/sessions", ProxyToAuthService)
		authProxy.POST("/sessions/revoke", ProxyToAuthService)
		authProxy.POST("/sessions/revoke-all", ProxyToAuthService)
		authProxy.GET("/me", ProxyToAuthService)
		authProxy.PATCH("/profile", ProxyToAuthService)
	}

	api := r.Group("/api")
	api.Use(AuthMiddleware(jwtSecret))
	api.Use(AuthAuditLog())
	{
		api.GET("/rules", RequireRoles("admin", "analyst", "viewer"), GetRules)
		api.PUT("/rules/:id", RequireRoles("admin"), UpdateRuleStatus)
		api.POST("/rules", RequireRoles("admin"), CreateRule)
		api.DELETE("/rules/:id", RequireRoles("admin"), DeleteRule)
		api.GET("/rules/regex", RequireRoles("admin", "analyst", "viewer"), GetRegexRules)
		api.GET("/rules/regex/all", RequireRoles("admin", "analyst", "viewer"), GetRegexSignatures)
		api.GET("/alerts", RequireRoles("admin", "analyst", "viewer"), GetAlerts)
		api.GET("/alerts/review", RequireRoles("admin", "analyst"), GetReviewAlerts)
		api.GET("/admin/audit-logs", RequireRoles("admin"), func(c *gin.Context) {
			userStr := c.Query("user")
			actionStr := c.Query("action")
			resourceTypeStr := c.Query("resource_type")
			limitStr := c.DefaultQuery("limit", "50")
			offsetStr := c.DefaultQuery("offset", "0")
			startStr := c.Query("start")
			endStr := c.Query("end")

			limit, err := strconv.ParseInt(limitStr, 10, 64)
			if err != nil || limit <= 0 {
				limit = 50
			}

			offset, err := strconv.ParseInt(offsetStr, 10, 64)
			if err != nil || offset < 0 {
				offset = 0
			}

			filter := bson.M{}
			if userStr != "" {
				filter["$or"] = []bson.M{
					{"user_id": userStr},
					{"user_email": userStr},
				}
			}
			if actionStr != "" {
				filter["action"] = actionStr
			}
			if resourceTypeStr != "" {
				filter["resource_type"] = resourceTypeStr
			}

			if startStr != "" || endStr != "" {
				timeFilter := bson.M{}
				if startStr != "" {
					if t, err := time.Parse(time.RFC3339, startStr); err != nil {
						if t, err := time.Parse("2006-01-02T15:04", startStr); err == nil {
							timeFilter["$gte"] = t
						}
					} else {
						timeFilter["$gte"] = t
					}
				}
				if endStr != "" {
					if t, err := time.Parse(time.RFC3339, endStr); err != nil {
						if t, err := time.Parse("2006-01-02T15:04", endStr); err == nil {
							timeFilter["$lte"] = t
						}
					} else {
						timeFilter["$lte"] = t
					}
				}
				if len(timeFilter) > 0 {
					filter["timestamp"] = timeFilter
				}
			}

			collection := db.GetCollection("modintel", "audit_logs")
			ctx := context.Background()

			total, err := collection.CountDocuments(ctx, filter)
			if err != nil {
				total = 0
			}

			opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit).SetSkip(offset)
			cursor, err := collection.Find(ctx, filter, opts)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audit logs"})
				return
			}
			defer cursor.Close(ctx)

			var logs []AuditLog
			if err := cursor.All(ctx, &logs); err != nil {
				logs = []AuditLog{}
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"logs":    logs,
				"total":   total,
				"offset":  offset,
				"limit":   limit,
			})
		})
		api.PUT("/alerts/:id/review", RequireRoles("admin", "analyst"), ReviewAlert)
		api.GET("/logs", RequireRoles("admin", "analyst", "viewer"), GetLogs)
		api.GET("/stats", RequireRoles("admin", "analyst", "viewer"), GetStats)
		api.GET("/trend", RequireRoles("admin", "analyst", "viewer"), GetTrend)
		api.GET("/config", RequireRoles("admin", "analyst", "viewer"), GetConfig)
		api.GET("/waf/paranoia", RequireRoles("admin"), GetWAFParanoia)
		api.PUT("/waf/paranoia", RequireRoles("admin"), UpdateWAFParanoia)
		api.GET("/waf/layer2/threshold", RequireRoles("admin"), GetLayer2Threshold)
		api.PUT("/waf/layer2/threshold", RequireRoles("admin"), UpdateLayer2Threshold)
		api.GET("/monitor/health", RequireRoles("admin", "analyst", "viewer"), GetmonitorHealth)
		api.GET("/monitor/metrics", RequireRoles("admin", "analyst", "viewer"), GetmonitorMetrics)
		api.POST("/admin/audit/log", RequireRoles("admin"), IngestAuditLog)
		api.GET("/admin/audit/logs", RequireRoles("admin", "analyst", "viewer"), GetAuditLogsHandler)
		api.POST("/admin/storage/clear", RequireRoles("admin"), ClearStorageCollections)
		api.POST("/system/restart/proxy-waf", RequireRoles("admin"), RestartProxyWAF)
		api.DELETE("/logs", RequireRoles("admin", "analyst"), ClearLogs)
		api.GET("/datasets", RequireRoles("admin", "analyst", "viewer"), GetDatasets)
		api.GET("/datasets/sources", RequireRoles("admin", "analyst", "viewer"), GetDatasetSources)
		api.POST("/datasets/generate", RequireRoles("admin", "analyst"), GenerateDataset)
		api.POST("/datasets/merge", RequireRoles("admin", "analyst"), MergeDatasets)
		api.DELETE("/datasets/:id", RequireRoles("admin", "analyst"), DeleteDataset)
	}

	r.Static("/js", "/srv/dashboard/js")
	r.Static("/css", "/srv/dashboard/css")
	r.Static("/fonts", "/srv/dashboard/fonts")
	r.StaticFile("/favicon.svg", "/srv/dashboard/favicon.svg")

	r.GET("/signin.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/signin") })
	r.GET("/index.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/events") })
	r.GET("/rules.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/rules") })
	r.GET("/review.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/review") })
	r.GET("/training.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/training") })
	r.GET("/datasets.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/datasets") })
	r.GET("/reports.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/reports") })
	r.GET("/monitor.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/monitor") })
	r.GET("/settings.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/settings") })
	r.GET("/help.html", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/help") })

	r.GET("/", func(c *gin.Context) { c.File("/srv/dashboard/index.html") })
	r.GET("/signin", func(c *gin.Context) { c.File("/srv/dashboard/signin.html") })
	r.GET("/setup", func(c *gin.Context) { c.File("/srv/dashboard/setup.html") })
	r.GET("/accept-invite", func(c *gin.Context) { c.File("/srv/dashboard/accept-invite.html") })
	r.GET("/forgot-password", func(c *gin.Context) { c.File("/srv/dashboard/forgot-password.html") })
	r.GET("/reset-password", func(c *gin.Context) { c.File("/srv/dashboard/reset-password.html") })
	r.GET("/setup-2fa", func(c *gin.Context) { c.File("/srv/dashboard/setup-2fa.html") })
	r.GET("/login-2fa", func(c *gin.Context) { c.File("/srv/dashboard/login-2fa.html") })
	r.GET("/events", func(c *gin.Context) { c.File("/srv/dashboard/index.html") })
	r.GET("/rules", func(c *gin.Context) { c.File("/srv/dashboard/rules.html") })
	r.GET("/review", func(c *gin.Context) { c.File("/srv/dashboard/review.html") })
	r.GET("/training", func(c *gin.Context) { c.File("/srv/dashboard/training.html") })
	r.GET("/datasets", func(c *gin.Context) { c.File("/srv/dashboard/datasets.html") })
	r.GET("/reports", func(c *gin.Context) { c.File("/srv/dashboard/reports.html") })
	r.GET("/monitor", func(c *gin.Context) { c.File("/srv/dashboard/monitor.html") })
	r.GET("/settings", func(c *gin.Context) { c.File("/srv/dashboard/settings.html") })
	r.GET("/help", func(c *gin.Context) { c.File("/srv/dashboard/help.html") })
	r.GET("/audit-logs", func(c *gin.Context) { c.File("/srv/dashboard/audit-logs.html") })

	return r
}

type dockerContainerInfo struct {
	ID string `json:"Id"`
}

func RestartProxyWAF(c *gin.Context) {
	if !restartInFlight.CompareAndSwap(false, true) {
		c.JSON(http.StatusAccepted, gin.H{"success": true, "service": "proxy-waf", "status": "restart_already_queued"})
		LogAction(c, "waf_restart", "system", "proxy-waf", nil, "failure", "restart already in flight")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()

	containerID, err := dockerFindComposeServiceContainer(ctx, "proxy-waf")
	if err != nil {
		restartInFlight.Store(false)
		LogAction(c, "waf_restart", "system", "proxy-waf", nil, "failure", err.Error())
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

	LogAction(c, "waf_restart", "system", "proxy-waf", nil, "success", "")
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

	ruleType := strings.TrimSpace(c.Query("type"))
	category := strings.TrimSpace(c.Query("category"))
	search := strings.TrimSpace(c.Query("search"))
	paranoiaStr := c.Query("paranoia_level")

	params, err := parseOffsetParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")

	filter := bson.M{"archived": bson.M{"$ne": true}}

	if ruleType != "" {
		if ruleType != "crs" && ruleType != "custom" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "type must be 'crs' or 'custom'"})
			return
		}
		if ruleType == "crs" {
			filter["type"] = bson.M{"$in": []string{"crs", "crs-blocking", "crs-init"}}
		} else {
			filter["type"] = ruleType
		}
	}

	if category != "" {
		if strings.HasPrefix(category, "$") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category"})
			return
		}
		filter["category"] = category
	}

	if search != "" {
		escaped := regexp.QuoteMeta(search)
		filter["$or"] = []bson.M{
			{"id": bson.M{"$regex": escaped, "$options": "i"}},
			{"description": bson.M{"$regex": escaped, "$options": "i"}},
		}
	}

	if paranoiaStr != "" {
		pl, err := strconv.Atoi(paranoiaStr)
		if err == nil && pl >= 1 && pl <= 4 {
			filter["paranoia_level"] = pl
		}
	}

	totalCount, err := ruleColl.CountDocuments(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count rules"})
		return
	}

	totalPages := int((totalCount + int64(params.Limit) - 1) / int64(params.Limit))
	skip := (params.Page - 1) * params.Limit

	opts := options.Find().
		SetSort(bson.D{{Key: "id", Value: 1}}).
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit))

	cursor, err := ruleColl.Find(ctx, filter, opts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch rules"})
		return
	}
	defer cursor.Close(ctx)

	rules := make([]db.WAFRule, 0)
	if err := cursor.All(ctx, &rules); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode rules"})
		return
	}

	response := OffsetResponse{
		Data:       rules,
		Page:       params.Page,
		PageSize:   params.Limit,
		TotalCount: totalCount,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func GetRegexRules(c *gin.Context) {
	signaturesPath := os.Getenv("MODINTEL_SIGNATURES_FILE")
	if signaturesPath == "" {
		signaturesPath = "/app/signatures/modintel_regex.signatures"
	}

	data, err := os.ReadFile(signaturesPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read signatures file"})
		return
	}

	var signatures []map[string]interface{}
	if err := json.Unmarshal(data, &signatures); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse signatures"})
		return
	}

	type RegexCategory struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Severity string `json:"severity"`
		Patterns int    `json:"patterns"`
	}

	categories := make(map[string]RegexCategory)
	for _, sig := range signatures {
		enabled := true
		if e, ok := sig["enabled"]; ok {
			if b, ok := e.(bool); ok {
				enabled = b
			}
		}
		if !enabled {
			continue
		}

		cat := sig["category"].(string)
		patternCount := 0
		if p, ok := sig["patterns"].([]interface{}); ok {
			patternCount = len(p)
		}
		if existing, ok := categories[cat]; ok {
			existing.Patterns += patternCount
			categories[cat] = existing
		} else {
			categories[cat] = RegexCategory{
				Name:     sig["name"].(string),
				Category: cat,
				Severity: sig["severity"].(string),
				Patterns: patternCount,
			}
		}
	}

	result := make([]RegexCategory, 0, len(categories))
	for _, v := range categories {
		result = append(result, v)
	}

	c.JSON(http.StatusOK, result)
}

func GetRegexSignatures(c *gin.Context) {
	signaturesPath := os.Getenv("MODINTEL_SIGNATURES_FILE")
	if signaturesPath == "" {
		signaturesPath = "/app/signatures/modintel_regex.signatures"
	}

	data, err := os.ReadFile(signaturesPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read signatures file"})
		return
	}

	var signatures []map[string]interface{}
	if err := json.Unmarshal(data, &signatures); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse signatures"})
		return
	}

	type RegexSignature struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Category string `json:"category"`
		Severity string `json:"severity"`
		Enabled  bool   `json:"enabled"`
		Patterns int    `json:"patterns"`
	}

	result := make([]RegexSignature, 0, len(signatures))
	for _, sig := range signatures {
		id, _ := sig["id"].(string)
		if id == "" {
			continue
		}
		enabled := true
		if e, ok := sig["enabled"]; ok {
			if b, ok := e.(bool); ok {
				enabled = b
			}
		}
		name, _ := sig["name"].(string)
		category, _ := sig["category"].(string)
		severity, _ := sig["severity"].(string)
		patternCount := 0
		if p, ok := sig["patterns"].([]interface{}); ok {
			patternCount = len(p)
		}
		result = append(result, RegexSignature{
			ID:       id,
			Name:     name,
			Category: category,
			Severity: severity,
			Enabled:  enabled,
			Patterns: patternCount,
		})
	}

	c.JSON(http.StatusOK, result)
}

func UpdateRuleStatus(c *gin.Context) {
	ruleID := strings.TrimSpace(c.Param("id"))
	if ruleID == "" {
		LogAction(c, "rule_update", "rule", "", nil, "failure", "rule id is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule id is required"})
		return
	}

	if !ruleIDPattern.MatchString(ruleID) {
		LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "invalid rule id format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id format"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")
	var existingRule db.WAFRule
	err := ruleColl.FindOne(ctx, bson.M{"id": ruleID}).Decode(&existingRule)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "rule not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "database error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	var req updateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "invalid request payload")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	hasToggle := req.Enabled != nil
	hasMetadata := req.Category != "" || req.Description != "" || req.Severity != "" || req.Phase != 0
	hasSignature := req.Signature != ""

	if !hasToggle && !hasMetadata && !hasSignature {
		LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "no fields to update")
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	setFields := bson.M{"updated_at": time.Now().UTC()}

	if hasToggle {
		setFields["enabled"] = *req.Enabled
	}

	if hasMetadata || hasSignature {
		if existingRule.Type != "custom" {
			LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "cannot edit CRS rule")
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot edit CRS rule"})
			return
		}
		if req.Category != "" {
			if strings.HasPrefix(req.Category, "$") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category"})
				return
			}
			setFields["category"] = req.Category
		}
		if req.Description != "" {
			setFields["description"] = req.Description
		}
		if req.Severity != "" {
			validSeverities := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
			if !validSeverities[strings.ToUpper(req.Severity)] {
				c.JSON(http.StatusBadRequest, gin.H{"error": "severity must be CRITICAL, HIGH, MEDIUM, or LOW"})
				return
			}
			setFields["severity"] = strings.ToUpper(req.Severity)
		}
		if req.Phase != 0 {
			if req.Phase < 1 || req.Phase > 4 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "phase must be 1-4"})
				return
			}
			setFields["phase"] = req.Phase
		}
		if hasSignature {
			setFields["signature"] = sanitizeSignature(req.Signature)
		}
	}

	_, err = ruleColl.UpdateOne(
		ctx,
		bson.M{"id": ruleID},
		bson.M{"$set": setFields},
	)
	if err != nil {
		LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "failed updating rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed updating rule"})
		return
	}

	if hasToggle {
		if err := syncManagedWAFOverrides(ctx); err != nil {
			log.Printf("failed syncing managed overrides: %v", err)
			LogAction(c, "rule_update", "rule", ruleID, nil, "failure", "failed syncing waf overrides")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed syncing waf overrides"})
			return
		}
	}

	if hasSignature {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if regenErr := regenerateCustomRulesConf(bgCtx); regenErr != nil {
				log.Printf("failed regenerating custom rules conf: %v", regenErr)
				return
			}
			restartProxyWAFAsync()
		}()
	}

	LogAction(c, "rule_update", "rule", ruleID, map[string]interface{}{"enabled": req.Enabled, "type": existingRule.Type}, "success", "")
	c.JSON(http.StatusOK, gin.H{"success": true, "id": ruleID, "type": existingRule.Type})
}

func DeleteRule(c *gin.Context) {
	ruleID := strings.TrimSpace(c.Param("id"))
	if ruleID == "" {
		LogAction(c, "rule_delete", "rule", "", nil, "failure", "rule id is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule id is required"})
		return
	}

	if !ruleIDPattern.MatchString(ruleID) {
		LogAction(c, "rule_delete", "rule", ruleID, nil, "failure", "invalid rule id format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id format"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")
	var existingRule db.WAFRule
	err := ruleColl.FindOne(ctx, bson.M{"id": ruleID}).Decode(&existingRule)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			LogAction(c, "rule_delete", "rule", ruleID, nil, "failure", "rule not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		LogAction(c, "rule_delete", "rule", ruleID, nil, "failure", "database error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if existingRule.Type != "custom" {
		LogAction(c, "rule_delete", "rule", ruleID, nil, "failure", "cannot delete CRS rules")
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete CRS rules"})
		return
	}

	_, err = ruleColl.DeleteOne(ctx, bson.M{"id": ruleID})
	if err != nil {
		LogAction(c, "rule_delete", "rule", ruleID, nil, "failure", "failed deleting rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed deleting rule"})
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if regenErr := regenerateCustomRulesConf(bgCtx); regenErr != nil {
			log.Printf("failed regenerating custom rules conf: %v", regenErr)
			return
		}
		restartProxyWAFAsync()
	}()

	LogAction(c, "rule_delete", "rule", ruleID, nil, "success", "")
	c.JSON(http.StatusOK, gin.H{"success": true, "id": ruleID})
}

type createRuleRequest struct {
	ID          string `json:"id" bson:"id"`
	Type        string `json:"type" bson:"type"`
	Category    string `json:"category" bson:"category"`
	Description string `json:"description" bson:"description"`
	Severity    string `json:"severity" bson:"severity"`
	Phase       int    `json:"phase" bson:"phase"`
	Source      string `json:"source" bson:"source"`
	Signature   string `json:"signature" bson:"signature"`
}

func CreateRule(c *gin.Context) {
	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	if req.ID == "" || req.Category == "" || req.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id, category, and description are required"})
		return
	}

	if !ruleIDPattern.MatchString(req.ID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id must be numeric"})
		return
	}

	if strings.HasPrefix(req.Category, "$") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category"})
		return
	}

	validSeverities := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	if req.Severity != "" && !validSeverities[strings.ToUpper(req.Severity)] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "severity must be CRITICAL, HIGH, MEDIUM, or LOW"})
		return
	}

	if req.Phase < 1 || req.Phase > 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phase must be 1-4"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	ruleColl := db.GetCollection("modintel", "waf_rules")
	now := time.Now().UTC()

	rule := db.WAFRule{
		ID:          req.ID,
		Type:        "custom",
		Category:    req.Category,
		Description: req.Description,
		Severity:    strings.ToUpper(req.Severity),
		Phase:       req.Phase,
		Source:      "modintel-custom",
		Enabled:     true,
		Archived:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
		Signature:   sanitizeSignature(req.Signature),
	}

	_, err := ruleColl.InsertOne(ctx, rule)
	if err != nil {
		log.Printf("Failed to create rule: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rule"})
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if regenErr := regenerateCustomRulesConf(bgCtx); regenErr != nil {
			log.Printf("failed regenerating custom rules conf: %v", regenErr)
			return
		}
		restartProxyWAFAsync()
	}()

	LogAction(c, "rule_create", "rule", req.ID, map[string]interface{}{"category": req.Category}, "success", "")
	c.JSON(http.StatusCreated, gin.H{"success": true, "id": req.ID})
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

func getCustomRulesPath() string {
	p := strings.TrimSpace(os.Getenv("CUSTOM_RULES_PATH"))
	if p == "" {
		p = "/waf-overrides/custom_rules.conf"
	}
	return p
}

func regenerateCustomRulesConf(ctx context.Context) error {
	ruleColl := db.GetCollection("modintel", "waf_rules")

	cur, err := ruleColl.Find(ctx, bson.M{
		"source": "modintel-custom",
	})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)

	type customRule struct {
		ID        string `bson:"id"`
		Signature string `bson:"signature"`
		Enabled   bool   `bson:"enabled"`
	}
	rules := make([]customRule, 0)
	for cur.Next(ctx) {
		var rec customRule
		if decodeErr := cur.Decode(&rec); decodeErr != nil {
			continue
		}
		if rec.Signature == "" {
			continue
		}
		rules = append(rules, rec)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	buf := strings.Builder{}
	buf.WriteString("# Auto-generated by review-api. Do not edit manually.\n")
	buf.WriteString(fmt.Sprintf("# Generated at %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString("SecRuleEngine On\n\n")

	for _, r := range rules {
		line := sanitizeSignature(r.Signature)
		if line == "" {
			continue
		}
		if !r.Enabled {
			line = "# " + line
		}
		buf.WriteString(line + "\n")
	}

	customPath := filepath.Clean(getCustomRulesPath())
	if err := os.MkdirAll(filepath.Dir(customPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(customPath, []byte(buf.String()), 0o644)
}

func sanitizeSignature(sig string) string {
	sig = strings.TrimSpace(sig)
	sig = strings.ReplaceAll(sig, "\r\n", " ")
	sig = strings.ReplaceAll(sig, "\n", " ")
	sig = strings.ReplaceAll(sig, "\r", " ")
	return sig
}

func restartProxyWAFAsync() {
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		containerID, err := dockerFindComposeServiceContainer(bgCtx, "proxy-waf")
		if err != nil {
			log.Printf("failed to find proxy-waf container: %v", err)
			return
		}
		if err := dockerRestartContainer(bgCtx, containerID); err != nil {
			log.Printf("failed to restart proxy-waf: %v", err)
		}
	}()
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

type WAFParanoiaConfig struct {
	Paranoia             int     `json:"paranoia"`
	BlockingParanoia     int     `json:"blocking_paranoia"`
	AnomalyInbound       int     `json:"anomaly_inbound"`
	RuleEngine           string  `json:"rule_engine"`
	Layer2BlockThreshold float64 `json:"layer2_block_threshold"`
}

func GetWAFParanoia(c *gin.Context) {
	cfg := readParanoiaConfig()
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cfg})
}

type UpdateWAFParanoiaRequest struct {
	Paranoia         *int    `json:"paranoia"`
	BlockingParanoia *int    `json:"blocking_paranoia"`
	AnomalyInbound   *int    `json:"anomaly_inbound"`
	RuleEngine       *string `json:"rule_engine"`
}

func UpdateWAFParanoia(c *gin.Context) {
	var req UpdateWAFParanoiaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		LogAction(c, "waf_paranoia_update", "system", "waf", nil, "failure", "invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	cfg := readParanoiaConfig()

	if req.Paranoia != nil {
		if *req.Paranoia < 1 || *req.Paranoia > 4 {
			LogAction(c, "waf_paranoia_update", "system", "waf", map[string]interface{}{"paranoia": *req.Paranoia}, "failure", "paranoia must be 1-4")
			c.JSON(http.StatusBadRequest, gin.H{"error": "paranoia must be 1-4"})
			return
		}
		cfg.Paranoia = *req.Paranoia
	}

	if req.BlockingParanoia != nil {
		if *req.BlockingParanoia < 1 || *req.BlockingParanoia > 4 {
			LogAction(c, "waf_paranoia_update", "system", "waf", map[string]interface{}{"blocking_paranoia": *req.BlockingParanoia}, "failure", "blocking_paranoia must be 1-4")
			c.JSON(http.StatusBadRequest, gin.H{"error": "blocking_paranoia must be 1-4"})
			return
		}
		cfg.BlockingParanoia = *req.BlockingParanoia
	}

	if req.AnomalyInbound != nil {
		if *req.AnomalyInbound < 1 || *req.AnomalyInbound > 20 {
			LogAction(c, "waf_paranoia_update", "system", "waf", map[string]interface{}{"anomaly_inbound": *req.AnomalyInbound}, "failure", "anomaly_inbound must be 1-20")
			c.JSON(http.StatusBadRequest, gin.H{"error": "anomaly_inbound must be 1-20"})
			return
		}
		cfg.AnomalyInbound = *req.AnomalyInbound
	}

	if req.RuleEngine != nil {
		valid := *req.RuleEngine == "On" || *req.RuleEngine == "DetectionOnly"
		if !valid {
			LogAction(c, "waf_paranoia_update", "system", "waf", map[string]interface{}{"rule_engine": *req.RuleEngine}, "failure", "rule_engine must be 'On' or 'DetectionOnly'")
			c.JSON(http.StatusBadRequest, gin.H{"error": "rule_engine must be 'On' or 'DetectionOnly'"})
			return
		}
		cfg.RuleEngine = *req.RuleEngine
	}

	if err := writeParanoiaConfig(cfg); err != nil {
		LogAction(c, "waf_paranoia_update", "system", "waf", nil, "failure", "failed to save config")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		containerID, err := dockerFindComposeServiceContainer(ctx, "proxy-waf")
		if err != nil {
			log.Printf("failed to find proxy-waf container: %v", err)
			return
		}
		if err := dockerRestartContainer(ctx, containerID); err != nil {
			log.Printf("failed to restart proxy-waf: %v", err)
		}
	}()

	LogAction(c, "waf_paranoia_update", "system", "waf", map[string]interface{}{"paranoia": cfg.Paranoia, "blocking_paranoia": cfg.BlockingParanoia, "anomaly_inbound": cfg.AnomalyInbound, "rule_engine": cfg.RuleEngine, "layer2_block_threshold": cfg.Layer2BlockThreshold}, "success", "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cfg})
}

func GetLayer2Threshold(c *gin.Context) {
	cfg := readParanoiaConfig()
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"layer2_block_threshold": cfg.Layer2BlockThreshold,
	}})
}

type UpdateLayer2ThresholdRequest struct {
	Layer2BlockThreshold *float64 `json:"layer2_block_threshold"`
}

func UpdateLayer2Threshold(c *gin.Context) {
	var req UpdateLayer2ThresholdRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		LogAction(c, "waf_layer2_threshold_update", "system", "waf", nil, "failure", "invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Layer2BlockThreshold == nil {
		LogAction(c, "waf_layer2_threshold_update", "system", "waf", nil, "failure", "missing layer2_block_threshold")
		c.JSON(http.StatusBadRequest, gin.H{"error": "layer2_block_threshold is required"})
		return
	}

	threshold := *req.Layer2BlockThreshold
	if threshold < 0.85 || threshold > 1.0 {
		LogAction(c, "waf_layer2_threshold_update", "system", "waf", map[string]interface{}{"layer2_block_threshold": threshold}, "failure", "layer2_block_threshold must be between 0.85 and 1.0")
		c.JSON(http.StatusBadRequest, gin.H{"error": "layer2_block_threshold must be between 0.85 and 1.0"})
		return
	}

	cfg := readParanoiaConfig()
	cfg.Layer2BlockThreshold = threshold

	if err := writeParanoiaConfig(cfg); err != nil {
		LogAction(c, "waf_layer2_threshold_update", "system", "waf", nil, "failure", "failed to save config")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
		return
	}

	go func() { _ = notifyWafBlockerThresholdUpdate(threshold) }()

	LogAction(c, "waf_layer2_threshold_update", "system", "waf", map[string]interface{}{"layer2_block_threshold": threshold}, "success", "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"layer2_block_threshold": cfg.Layer2BlockThreshold,
	}})
}

func notifyWafBlockerThresholdUpdate(threshold float64) error {
	url := "http://waf-blocker:8086/api/waf/threshold"
	body := map[string]float64{"threshold": threshold}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("failed to marshal threshold update: %v", err)
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("failed to notify waf-blocker of threshold update: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("waf-blocker returned status %d for threshold update", resp.StatusCode)
		return fmt.Errorf("waf-blocker returned status %d", resp.StatusCode)
	}
	return nil
}

func SyncLayer2ThresholdToBlocker() {
	cfg := readParanoiaConfig()
	threshold := cfg.Layer2BlockThreshold
	if threshold < 0.01 {
		threshold = 0.94
	}

	go func() {
		maxRetries := 10
		for i := 0; i < maxRetries; i++ {
			err := notifyWafBlockerThresholdUpdate(threshold)
			if err == nil {
				log.Printf("Layer-2 threshold synced to %.2f on startup", threshold)
				return
			}
			log.Printf("Retry %d/%d: failed to sync threshold on startup: %v", i+1, maxRetries, err)
			time.Sleep(3 * time.Second)
		}
		log.Printf("Failed to sync threshold after %d retries; waf-blocker will use default until next update", maxRetries)
	}()
}

func readParanoiaConfig() WAFParanoiaConfig {
	cfg := WAFParanoiaConfig{Paranoia: 4, BlockingParanoia: 4, AnomalyInbound: 3, RuleEngine: "On", Layer2BlockThreshold: 0.94}
	data, err := os.ReadFile(wafConfigPath)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return WAFParanoiaConfig{Paranoia: 4, BlockingParanoia: 4, AnomalyInbound: 3, RuleEngine: "On", Layer2BlockThreshold: 0.94}
	}
	if cfg.Paranoia < 1 {
		cfg.Paranoia = 4
	}
	if cfg.BlockingParanoia < 1 {
		cfg.BlockingParanoia = 4
	}
	if cfg.AnomalyInbound < 1 {
		cfg.AnomalyInbound = 3
	}
	if cfg.RuleEngine == "" {
		cfg.RuleEngine = "On"
	}
	if cfg.Layer2BlockThreshold < 0.01 {
		cfg.Layer2BlockThreshold = 0.94
	}
	if cfg.Layer2BlockThreshold > 1.0 {
		cfg.Layer2BlockThreshold = 1.0
	}
	return cfg
}

func writeParanoiaConfig(cfg WAFParanoiaConfig) error {
	dir := filepath.Dir(wafConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(wafConfigPath, data, 0644); err != nil {
		return err
	}

	crsSetupPath := "/project/proxy-waf/crs-setup.conf"
	crsSetup := fmt.Sprintf(`# CRS Setup - Generated by ModIntel
# Paranoia and anomaly thresholds are controlled via the Settings page.

SecDefaultAction "phase:1,pass,log,tag:'coraza'"
SecDefaultAction "phase:2,pass,log,tag:'coraza'"

SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.paranoia_level=%d,\
   setvar:tx.blocking_paranoia_level=%d"

SecAction \
  "id:900110,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.inbound_anomaly_score_threshold=%d,\
   setvar:tx.outbound_anomaly_score_threshold=4"

SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.25.0',\
    setvar:tx.crs_setup_version=4250"
`, cfg.Paranoia, cfg.BlockingParanoia, cfg.AnomalyInbound)
	if err := os.WriteFile(crsSetupPath, []byte(crsSetup), 0644); err != nil {
		return err
	}

	return nil
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

func _parseAlertTimestamp(raw string) (time.Time, bool) {
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

	startStr := start.Format(time.RFC3339)
	endStr := now.Add(time.Minute).Format(time.RFC3339)

	filter := bson.M{
		"timestamp": bson.M{
			"$gte": startStr,
			"$lte": endStr,
		},
	}

	opts := options.Find().SetProjection(bson.M{"timestamp": 1})
	cursor, err := collection.Find(ctx, filter, opts)
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

		ts, ok := _parseAlertTimestamp(rawTS)
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

	cursorFilter, err := buildCursorFilter(params.Cursor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := cursorFilter
	if source := strings.TrimSpace(c.Query("source")); source != "" {
		filter["source"] = source
	}
	if priority := strings.TrimSpace(c.Query("priority")); priority != "" {
		parts := strings.Split(priority, ",")
		if len(parts) == 1 {
			filter["ai_priority"] = strings.ToUpper(parts[0])
		} else {
			upperParts := make([]interface{}, len(parts))
			for i, p := range parts {
				upperParts[i] = strings.ToUpper(strings.TrimSpace(p))
			}
			filter["ai_priority"] = bson.M{"$in": upperParts}
		}
	}
	if c.Query("exclude_score_0") == "true" {
		filter["anomaly_score"] = bson.M{"$ne": 0}
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "_id", Value: -1}}).
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
			"status":                 1,
			"source":                 1,
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
		Source               string                 `json:"source"`
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
		if src, ok := r["source"].(string); ok {
			alert.Source = src
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
		SetSort(bson.D{{Key: "_id", Value: -1}}).
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$facet", Value: bson.M{
			"total": bson.A{
				bson.D{{Key: "$count", Value: "count"}},
			},
			"coraza": bson.A{
				bson.D{{Key: "$match", Value: bson.M{"source": bson.M{"$in": bson.A{"coraza", "waf_blocked"}}}}},
				bson.D{{Key: "$count", Value: "count"}},
			},
			"ml_miss": bson.A{
				bson.D{{Key: "$match", Value: bson.M{"source": "ml_miss_detector"}}},
				bson.D{{Key: "$count", Value: "count"}},
			},
			"ai_enriched": bson.A{
				bson.D{{Key: "$match", Value: bson.M{"ai_status": "enriched"}}},
				bson.D{{Key: "$count", Value: "count"}},
			},
			"blocked": bson.A{
				bson.D{{Key: "$match", Value: bson.M{"anomaly_score": bson.M{"$gte": 5}}}},
				bson.D{{Key: "$count", Value: "count"}},
			},
			"latest_priority": bson.A{
				bson.D{{Key: "$match", Value: bson.M{"ai_priority": bson.M{"$type": "string"}}}},
				bson.D{{Key: "$sort", Value: bson.D{{Key: "_id", Value: -1}}}},
				bson.D{{Key: "$limit", Value: 1}},
				bson.D{{Key: "$project", Value: bson.M{"ai_priority": 1, "_id": 0}}},
			},
		}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		log.Println("Error aggregating stats:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		log.Println("Error decoding stats:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	var total, corazaCount, mlMissCount, aiEnrichedCount, blockedCount int64
	latestPriority := "—"

	if len(results) > 0 {
		faceted := results[0]

		extractCount := func(key string) int64 {
			arr, ok := faceted[key].(bson.A)
			if !ok || len(arr) == 0 {
				return 0
			}
			doc, ok := arr[0].(bson.M)
			if !ok {
				return 0
			}
			switch v := doc["count"].(type) {
			case int32:
				return int64(v)
			case int64:
				return v
			case float64:
				return int64(v)
			default:
				return 0
			}
		}

		total = extractCount("total")
		corazaCount = extractCount("coraza")
		mlMissCount = extractCount("ml_miss")
		aiEnrichedCount = extractCount("ai_enriched")
		blockedCount = extractCount("blocked")

		if priorityArr, ok := faceted["latest_priority"].(bson.A); ok && len(priorityArr) > 0 {
			if priorityDoc, ok := priorityArr[0].(bson.M); ok {
				if p, ok := priorityDoc["ai_priority"].(string); ok && p != "" {
					latestPriority = p
				}
			}
		}
	}

	var blockedPct float64
	if total > 0 {
		blockedPct = float64(blockedCount) / float64(total) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":       total,
		"latest_priority":    latestPriority,
		"ai_enriched_count":  aiEnrichedCount,
		"coraza_count":       corazaCount,
		"ml_miss_count":      mlMissCount,
		"blocked_count":      blockedCount,
		"blocked_percentage": blockedPct,
	})
}

func ClearLogs(c *gin.Context) {
	collection := db.GetCollection("modintel", "alerts")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := collection.DeleteMany(ctx, bson.M{})
	if err != nil {
		log.Println("Error clearing logs:", err)
		LogAction(c, "logs_clear", "alerts", "*", nil, "failure", "error clearing logs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	LogAction(c, "logs_clear", "alerts", "*", map[string]interface{}{"deleted": result.DeletedCount}, "success", "")
	c.JSON(http.StatusOK, gin.H{"deleted": result.DeletedCount})
}

type storageClearRequest struct {
	Collections []string `json:"collections"`
}

type auditIngestRequest struct {
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Details      map[string]interface{} `json:"details"`
	Outcome      string                 `json:"outcome"`
	ErrorMessage string                 `json:"error_message"`
	UserID       string                 `json:"user_id"`
	UserEmail    string                 `json:"user_email"`
	UserRole     string                 `json:"user_role"`
}

func IngestAuditLog(c *gin.Context) {
	var payload auditIngestRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	payload.Action = normalizeAuditAction(payload.Action)
	payload.ResourceType = strings.TrimSpace(payload.ResourceType)
	payload.ResourceID = strings.TrimSpace(payload.ResourceID)
	payload.Outcome = strings.ToLower(strings.TrimSpace(payload.Outcome))
	payload.ErrorMessage = strings.TrimSpace(payload.ErrorMessage)
	payload.UserID = strings.TrimSpace(payload.UserID)
	payload.UserEmail = strings.TrimSpace(payload.UserEmail)
	payload.UserRole = strings.TrimSpace(payload.UserRole)

	if payload.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action is required"})
		return
	}
	if !isAllowedAuditAction(payload.Action) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported action"})
		return
	}
	if payload.ResourceType == "" {
		payload.ResourceType = "system"
	}
	if payload.Outcome == "" {
		payload.Outcome = "success"
	}
	if payload.Outcome != "success" && payload.Outcome != "failure" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "outcome must be success or failure"})
		return
	}

	if claimsAny, exists := c.Get("access_claims"); exists {
		if claims, ok := claimsAny.(*AccessClaims); ok && claims != nil {
			if payload.UserID == "" {
				payload.UserID = strings.TrimSpace(claims.UserID)
			}
			if payload.UserEmail == "" {
				payload.UserEmail = strings.TrimSpace(claims.Email)
			}
			if payload.UserRole == "" {
				payload.UserRole = strings.TrimSpace(claims.Role)
			}
		}
	}

	logEntry := AuditLog{
		UserID:       payload.UserID,
		UserEmail:    payload.UserEmail,
		UserRole:     payload.UserRole,
		Action:       payload.Action,
		ResourceType: payload.ResourceType,
		ResourceID:   payload.ResourceID,
		Details:      payload.Details,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Outcome:      payload.Outcome,
		ErrorMessage: payload.ErrorMessage,
	}

	LogAudit(logEntry)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func GetAuditLogsHandler(c *gin.Context) {
	filter := bson.M{}

	if userID := c.Query("user_id"); userID != "" {
		filter["user_id"] = userID
	}
	if action := c.Query("action"); action != "" {
		filter["action"] = action
	}
	if resourceType := c.Query("resource_type"); resourceType != "" {
		filter["resource_type"] = resourceType
	}
	if start := c.Query("start"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			filter["timestamp"] = bson.M{"$gte": t}
		}
	}
	if end := c.Query("end"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			if existing, ok := filter["timestamp"].(bson.M); ok {
				filter["timestamp"] = bson.M{"$gte": existing["$gte"], "$lte": t}
			} else {
				filter["timestamp"] = bson.M{"$lte": t}
			}
		}
	}

	limit := int64(100)
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = int64(parsed)
		}
	}

	sort := bson.D{{Key: "timestamp", Value: -1}}

	logs, err := GetAuditLogs(filter, limit, sort)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query audit logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

func normalizeAuditAction(action string) string {
	value := strings.ToLower(strings.TrimSpace(action))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func isAllowedAuditAction(action string) bool {
	switch action {
	case "auth_login",
		"auth_logout",
		"session_revoke",
		"session_revoke_all",
		"profile_update",
		"user_create",
		"user_invite",
		"user_update",
		"user_deactivate",
		"alert_review",
		"alert_review_undo",
		"rule_enable",
		"rule_disable",
		"waf_paranoia_update",
		"rule_toggle",
		"logs_clear",
		"storage_clear",
		"dataset_generate",
		"dataset_merge",
		"dataset_delete",
		"dataset_cut",
		"dataset_export",
		"training_start",
		"training_activate",
		"training_delete_version",
		"waf_restart":
		return true
	default:
		return false
	}
}

func ClearStorageCollections(c *gin.Context) {
	var payload storageClearRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	allowed := map[string]struct{}{
		"alerts":   {},
		"datasets": {},
	}

	collections := make([]string, 0, len(payload.Collections))
	seen := map[string]struct{}{}
	for _, name := range payload.Collections {
		if _, ok := allowed[name]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid collection: " + name})
			return
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		collections = append(collections, name)
	}

	if len(collections) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no collections selected"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	deleted := map[string]int64{}
	for _, name := range collections {
		collection := db.GetCollection("modintel", name)
		result, err := collection.DeleteMany(ctx, bson.M{})
		if err != nil {
			log.Printf("Error clearing collection %s: %v", name, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear " + name})
			return
		}
		deleted[name] = result.DeletedCount
	}

	LogAction(c, "storage_clear", "system", "database", map[string]interface{}{"collections": collections, "deleted": deleted}, "success", "")

	c.JSON(http.StatusOK, gin.H{"success": true, "deleted": deleted})
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

	var mu sync.Mutex
	var wg sync.WaitGroup

	if err := db.Client.Ping(ctx, nil); err != nil {
		services["review-api"] = "degraded"
	}

	wg.Add(4)
	go func() {
		defer wg.Done()
		s := checkHTTPService("http://log-collector:8081/health", 3*time.Second)
		mu.Lock()
		services["log-collector"] = s
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		s := checkHTTPService("http://inference-engine:8083/health", 3*time.Second)
		mu.Lock()
		services["inference-engine"] = s
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		s := checkTCPService("proxy-waf", 8080, 3*time.Second)
		mu.Lock()
		services["proxy-waf"] = s
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		s := checkHTTPService("http://auth-service:8084/health", 3*time.Second)
		mu.Lock()
		services["auth-service"] = s
		mu.Unlock()
	}()
	wg.Wait()

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

	metricsCollection := db.GetCollection("modintel", "metrics")
	alertColl := db.GetCollection("modintel", "alerts")
	rangeType := c.DefaultQuery("range", "1h")

	timeField := "time_1h"
	switch rangeType {
	case "6h":
		timeField = "time_6h"
	case "24h":
		timeField = "time_24h"
	case "7d":
		timeField = "time_7d"
	}

	window := parseMetricsWindow(rangeType)
	startTime := time.Now().UTC().Add(-window)

	var bucketCount int
	switch rangeType {
	case "1h":
		bucketCount = 60
	case "6h":
		bucketCount = 72
	case "24h":
		bucketCount = 96
	case "7d":
		bucketCount = 168
	default:
		bucketCount = 60
	}
	bucketSize := window / time.Duration(bucketCount)

	values := make([]float64, bucketCount)
	errValues := make([]float64, bucketCount)
	predValues := make([]float64, bucketCount)
	counts := make([]int, bucketCount)

	filter := bson.M{"timestamp": bson.M{"$gte": startTime}}
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}}).SetProjection(bson.M{
		"timestamp": 1, "requests_per_minute": 1, "errors_per_minute": 1, "predictions_per_minute": 1,
	})

	cursor, err := metricsCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("Error fetching metrics time series: %v", err)
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var doc struct {
			Timestamp  time.Time `bson:"timestamp"`
			ReqPerMin  float64   `bson:"requests_per_minute"`
			ErrPerMin  float64   `bson:"errors_per_minute"`
			PredPerMin float64   `bson:"predictions_per_minute"`
		}
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		elapsed := doc.Timestamp.Sub(startTime)
		idx := int(elapsed / bucketSize)
		if idx >= 0 && idx < bucketCount {
			values[idx] += doc.ReqPerMin
			errValues[idx] += doc.ErrPerMin
			predValues[idx] += doc.PredPerMin
			counts[idx]++
		}
	}

	timeSeries := make([]map[string]interface{}, 0, bucketCount)
	for i := 0; i < bucketCount; i++ {
		ts := startTime.Add(time.Duration(i) * bucketSize)
		reqVal := values[i]
		errVal := errValues[i]
		predVal := predValues[i]
		if counts[i] > 0 {
			reqVal /= float64(counts[i])
			errVal /= float64(counts[i])
			predVal /= float64(counts[i])
		}
		timeSeries = append(timeSeries, map[string]interface{}{
			"timestamp":              ts,
			"requests_per_minute":    reqVal,
			"errors_per_minute":      errVal,
			"predictions_per_minute": predVal,
		})
	}

	totalAlerts, _ := alertColl.CountDocuments(ctx, bson.M{})
	aiEnrichedCount, _ := alertColl.CountDocuments(ctx, bson.M{"ai_status": "enriched"})
	mlMissCount, _ := alertColl.CountDocuments(ctx, bson.M{"source": "ml_miss_detector"})

	inferenceMetrics := GetInferenceMetrics()
	systemMetrics := getSystemMetrics(ctx)
	window_requests, window_errors := requestStats.totals(window, time.Now().UTC())
	wafSnapshot, hasWAF := GetWAFTrafficSnapshot()

	var errorRate float64
	if window_requests > 0 {
		errorRate = float64(window_errors) / float64(window_requests)
	}

	response := gin.H{
		timeField:                  timeSeries,
		"range":                    rangeType,
		"total_alerts":             totalAlerts,
		"ai_enriched_count":        aiEnrichedCount,
		"ml_miss_count":            mlMissCount,
		"avg_inference_ms":         inferenceMetrics.AvgLatencyMs,
		"p50_latency_ms":           inferenceMetrics.P50LatencyMs,
		"p95_latency_ms":           inferenceMetrics.P95LatencyMs,
		"p99_latency_ms":           inferenceMetrics.P99LatencyMs,
		"total_predictions":        inferenceMetrics.TotalPredictions,
		"predictions_per_minute":   inferenceMetrics.PredictionsPerMinute,
		"model_version":            inferenceMetrics.ModelVersion,
		"inference_uptime_seconds": inferenceMetrics.UptimeSeconds,
		"requests_per_minute":      GetRequestsPerMin(),
		"error_rate":               errorRate,
		"error_rate_window":        window.String(),
		"window_requests":          window_requests,
		"window_errors":            window_errors,
		"total_requests":           totalRequests.Load(),
		"total_errors":             totalErrors.Load(),
		"mongodb_connections":      systemMetrics.MongoDBConnections,
		"timestamp":                time.Now().UTC(),
		"system":                   systemMetrics,
	}
	if hasWAF {
		response["requests_per_minute"] = wafSnapshot.RequestsPerMin
		response["waf_blocked_per_minute"] = wafSnapshot.BlockedPerMin
		response["waf_allowed_per_minute"] = wafSnapshot.AllowedPerMin
	}

	c.JSON(http.StatusOK, response)
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
	AvgLatencyMs         float64 `json:"avg_inference_ms"`
	P50LatencyMs         float64 `json:"p50_latency_ms"`
	P95LatencyMs         float64 `json:"p95_latency_ms"`
	P99LatencyMs         float64 `json:"p99_latency_ms"`
	TotalPredictions     int     `json:"total_predictions"`
	PredictionsPerMinute float64 `json:"predictions_per_minute"`
	ModelVersion         string  `json:"model_version"`
	UptimeSeconds        float64 `json:"inference_uptime_seconds"`
}

type wafTrafficSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	RequestsPerMin float64   `json:"requests_per_minute"`
	BlockedPerMin  float64   `json:"blocked_per_minute"`
	AllowedPerMin  float64   `json:"allowed_per_minute"`
}

func GetInferenceMetrics() inferenceMetricsData {
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
		metrics.AvgLatencyMs = v
	}
	if v, ok := result["p50_latency_ms"].(float64); ok {
		metrics.P50LatencyMs = v
	}
	if v, ok := result["p95_latency_ms"].(float64); ok {
		metrics.P95LatencyMs = v
	}
	if v, ok := result["p99_latency_ms"].(float64); ok {
		metrics.P99LatencyMs = v
	}
	if v, ok := result["total_predictions"].(float64); ok {
		metrics.TotalPredictions = int(v)
	}
	if v, ok := result["predictions_per_minute"].(float64); ok {
		metrics.PredictionsPerMinute = v
	}
	if v, ok := result["model_version"].(string); ok {
		metrics.ModelVersion = v
	} else if v, ok := result["model_version"].(float64); ok {
		metrics.ModelVersion = fmt.Sprintf("v%.0f", v)
	}
	if v, ok := result["uptime_seconds"].(float64); ok {
		metrics.UptimeSeconds = v
	}

	return metrics
}

type systemMetricsData struct {
	Hostname                 string  `json:"hostname"`
	GoVersion                string  `json:"go_version"`
	UptimeSeconds            float64 `json:"uptime_seconds"`
	CpuPercent               float64 `json:"cpu_percent"`
	MemoryUsedMB             uint64  `json:"memory_used_mb"`
	MemoryTotalMB            uint64  `json:"memory_total_mb"`
	MemoryPercent            float64 `json:"memory_percent"`
	Goroutines               float64 `json:"goroutines"`
	MongoDBConnections       int64   `json:"mongodb_connections"`
	MongoDBDatabaseSizeBytes int64   `json:"mongodb_database_size_bytes"`
	MongoDBAlertCount        int64   `json:"mongodb_alert_count"`
	TotalAlerts              int64   `json:"total_alerts"`
	AIEnrichedCount          int64   `json:"ai_enriched_count"`
	MLMissCount              int64   `json:"ml_miss_count"`
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

func getSystemTotalMemoryMB() uint64 {
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						return kb / 1024
					}
				}
			}
		}
	}
	return 0
}

func getSystemUsedMemoryMB() uint64 {
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memFree, buffers, cached uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					continue
				}
				switch {
				case strings.HasPrefix(line, "MemTotal:"):
					memTotal = val
				case strings.HasPrefix(line, "MemFree:"):
					memFree = val
				case strings.HasPrefix(line, "Buffers:"):
					buffers = val
				case strings.HasPrefix(line, "Cached:"):
					cached = val
				}
			}
		}
		if memTotal > 0 {
			used := memTotal - memFree - buffers - cached
			return used / 1024
		}
	}
	return 0
}

func getSystemLoadAverage() float64 {
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			if load, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return load
			}
		}
	}
	return 0.0
}

func getSystemMetrics(ctx context.Context) systemMetricsData {
	metrics := systemMetricsData{
		Hostname:      getHostname(),
		GoVersion:     runtime.Version(),
		UptimeSeconds: time.Since(serviceStartTime).Seconds(),
		Goroutines:    getSystemLoadAverage(),
	}

	sysTotalMB := getSystemTotalMemoryMB()
	sysUsedMB := getSystemUsedMemoryMB()
	if sysTotalMB > 0 {
		metrics.MemoryTotalMB = sysTotalMB
		metrics.MemoryUsedMB = sysUsedMB
		metrics.MemoryPercent = float64(sysUsedMB) / float64(sysTotalMB) * 100
	} else {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.MemoryUsedMB = m.Sys / (1024 * 1024)
		metrics.MemoryTotalMB = m.Sys / (1024 * 1024)
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
				metrics.MongoDBDatabaseSizeBytes = size
			} else if size, ok := toInt64(dbStats["dataSize"]); ok {
				metrics.MongoDBDatabaseSizeBytes = size
			}
		}
	}

	alertColl := db.GetCollection("modintel", "alerts")
	alertsCount, _ := alertColl.CountDocuments(ctx, bson.M{})
	metrics.TotalAlerts = alertsCount

	aiEnrichedCount, _ := alertColl.CountDocuments(ctx, bson.M{"ai_status": "enriched"})
	metrics.AIEnrichedCount = aiEnrichedCount

	mlMissCount, _ := alertColl.CountDocuments(ctx, bson.M{"source": "ml_miss_detector"})
	metrics.MLMissCount = mlMissCount

	return metrics
}

func ReviewAlert(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
		return
	}

	var body struct {
		HumanLabel string `json:"human_label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.HumanLabel != "true_positive" && body.HumanLabel != "false_positive" && body.HumanLabel != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "human_label must be true_positive, false_positive, or empty to undo"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

	if body.HumanLabel == "" {
		undo := bson.M{
			"$set":   bson.M{"status": "generated"},
			"$unset": bson.M{"human_label": "", "reviewed_by": "", "reviewed_at": ""},
		}
		result, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, undo)
		if err != nil {
			log.Printf("Error undoing alert review: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to undo review"})
			return
		}
		if result.MatchedCount == 0 {
			LogAction(c, "alert_review_undo", "alert", id, nil, "failure", "alert not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
			return
		}
		LogAction(c, "alert_review_undo", "alert", id, nil, "success", "")
		c.JSON(http.StatusOK, gin.H{"success": true, "status": "generated", "human_label": nil})
		return
	}

	username := "unknown"
	if claimsAny, exists := c.Get("access_claims"); exists {
		if claims, ok := claimsAny.(*AccessClaims); ok {
			if strings.TrimSpace(claims.Email) != "" {
				username = claims.Email
			}
		}
	}

	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"human_label": body.HumanLabel,
			"status":      "reviewed",
			"reviewed_by": username,
			"reviewed_at": now,
		},
	}
	result, err := collection.UpdateOne(ctx, bson.M{"_id": oid}, update)
	if err != nil {
		log.Printf("Error updating alert review: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
		return
	}

	action := "alert_review"
	if body.HumanLabel == "" {
		action = "alert_review_undo"
	}
	LogAction(c, action, "alert", id, map[string]interface{}{"label": body.HumanLabel}, "success", "")

	c.JSON(http.StatusOK, gin.H{"success": true, "status": "reviewed", "human_label": body.HumanLabel})
}

func GetReviewAlerts(c *gin.Context) {
	status := c.DefaultQuery("status", "generated")
	priority := c.DefaultQuery("priority", "")
	source := c.DefaultQuery("source", "")
	humanLabel := c.DefaultQuery("human_label", "")
	limitStr := c.DefaultQuery("limit", "50")
	cursorStr := c.Query("cursor")
	sortOrder := c.DefaultQuery("sort", "asc")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 50
	}

	sortAsc := sortOrder != "desc"
	cmpOp := "$gt"
	sortVal := 1
	if !sortAsc {
		cmpOp = "$lt"
		sortVal = -1
	}

	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}
	if priority != "" {
		filter["ai_priority"] = priority
	}
	if source != "" {
		filter["source"] = source
	}
	if humanLabel != "" {
		filter["human_label"] = humanLabel
	}
	if cursorStr != "" {
		oid, err := primitive.ObjectIDFromHex(cursorStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cursor"})
			return
		}
		filter["_id"] = bson.M{cmpOp: oid}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: sortVal}}).SetLimit(int64(limit + 1))

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("Error fetching review alerts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alerts"})
		return
	}
	defer cursor.Close(ctx)

	var items []bson.M
	if err := cursor.All(ctx, &items); err != nil {
		log.Printf("Error decoding review alerts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode alerts"})
		return
	}

	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}

	nextCursor := ""
	if hasMore && len(items) > 0 {
		if id, ok := items[len(items)-1]["_id"].(primitive.ObjectID); ok {
			nextCursor = id.Hex()
		}
	}

	total, _ := collection.CountDocuments(context.Background(), filter)

	c.JSON(http.StatusOK, gin.H{
		"items":       items,
		"next_cursor": nextCursor,
		"has_more":    hasMore,
		"total":       total,
	})
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

func GetTotalRequests() uint64 {
	return totalRequests.Load()
}

func GetTotalErrors() uint64 {
	return totalErrors.Load()
}

var LastRequestsPerMin float64

func GetRequestsPerMin() float64 {
	return LastRequestsPerMin
}

func GetWAFTrafficSnapshot() (wafTrafficSnapshot, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://log-collector:8081/api/waf/traffic", nil)
	if err != nil {
		return wafTrafficSnapshot{}, false
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return wafTrafficSnapshot{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return wafTrafficSnapshot{}, false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return wafTrafficSnapshot{}, false
	}

	var snapshot wafTrafficSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return wafTrafficSnapshot{}, false
	}

	return snapshot, true
}

func GetSystemMetrics(ctx context.Context) systemMetricsData {
	return getSystemMetrics(ctx)
}

func getCPULoad() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}

	var total, idle uint64
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0.0
		}
		for i := 1; i < len(fields); i++ {
			val, _ := strconv.ParseUint(fields[i], 10, 64)
			total += val
			if i == 4 {
				idle = val
			}
		}
		break
	}

	if total == 0 {
		return 0.0
	}

	cpuMu.Lock()
	defer cpuMu.Unlock()

	if cpuLastTotal > 0 {
		dTotal := total - cpuLastTotal
		dIdle := idle - cpuLastIdle
		if dTotal > 0 {
			cpuLastTotal = total
			cpuLastIdle = idle
			return (1.0 - float64(dIdle)/float64(dTotal)) * 100.0
		}
	}

	cpuLastTotal = total
	cpuLastIdle = idle
	return 0.0
}

func GetDatasets(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "datasets")
	cursor, err := collection.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch datasets"})
		return
	}
	defer cursor.Close(ctx)

	var items []bson.M
	if err := cursor.All(ctx, &items); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode datasets"})
		return
	}

	for i := range items {
		if oid, ok := items[i]["_id"].(primitive.ObjectID); ok {
			items[i]["_id"] = oid.Hex()
		}

		if pct, ok := items[i]["attack_pct"]; ok {
			var val float64
			if f, ok := pct.(float64); ok {
				val = f
			} else if i, ok := pct.(int32); ok {
				val = float64(i)
			} else if i, ok := pct.(int); ok {
				val = float64(i)
			}
			items[i]["attack_pct"] = float64(int(val*10+0.5)) / 10
		}

		if created, ok := items[i]["created_at"]; ok {
			if t, ok := created.(time.Time); ok {
				items[i]["created_at"] = t.UTC().Format("2006-01-02")
			} else if dt, ok := created.(primitive.DateTime); ok {
				items[i]["created_at"] = dt.Time().UTC().Format("2006-01-02")
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

func GetDatasetSources(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "alerts")

	sources := []struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		Regex string `json:"regex"`
	}{
		{Key: "sqli", Label: "SQL Injection", Regex: "942"},
		{Key: "xss", Label: "XSS", Regex: "941"},
		{Key: "cmdi", Label: "Command Injection", Regex: "932"},
		{Key: "lfi", Label: "LFI/Traversal", Regex: "930"},
		{Key: "rfi", Label: "RFI", Regex: "931"},
		{Key: "normal", Label: "Normal Traffic", Regex: ""},
	}

	var items []bson.M
	for _, src := range sources {
		filter := bson.M{}
		if src.Regex != "" {
			filter["triggered_rules"] = bson.M{"$elemMatch": bson.M{"$regex": "^" + src.Regex}}
		} else {
			filter["triggered_rules"] = bson.M{"$size": 0}
		}
		count, _ := collection.CountDocuments(ctx, filter)
		items = append(items, bson.M{
			"key":     src.Key,
			"name":    src.Label + " Samples",
			"samples": count,
			"attackPct": func() int {
				if count == 0 {
					return 0
				}
				return 80 + int(count%21)
			}(),
		})
	}

	c.JSON(http.StatusOK, gin.H{"sources": items})
}

type GenerateDatasetRequest struct {
	AttackType  string `json:"attack_type"`
	SampleCount int    `json:"sample_count"`
}

func GenerateDataset(c *gin.Context) {
	var req GenerateDatasetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		LogAction(c, "dataset_generate", "dataset", "", nil, "failure", "invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	attackLabels := map[string]string{
		"sqli": "SQLi",
		"xss":  "XSS",
		"cmdi": "CMDi",
		"lfi":  "LFI",
		"rfi":  "RFI",
		"all":  "Mixed",
	}

	label := attackLabels[req.AttackType]
	if label == "" {
		label = "Mixed"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "datasets")
	doc := bson.M{
		"name":    fmt.Sprintf("%s_%s_%d", req.AttackType, time.Now().Format("20060102"), rand.Intn(1000)),
		"type":    label,
		"samples": req.SampleCount,
		"attack_pct": func() int {
			if req.AttackType == "all" {
				return 50
			}
			return 100
		}(),
		"created_at": time.Now().Format("2006-01-02"),
		"status":     "ready",
	}

	result, err := collection.InsertOne(ctx, doc)
	if err != nil {
		LogAction(c, "dataset_generate", "dataset", "", map[string]interface{}{"attack_type": req.AttackType, "samples": req.SampleCount}, "failure", "failed to create dataset")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dataset"})
		return
	}

	LogAction(c, "dataset_generate", "dataset", fmt.Sprintf("%v", result.InsertedID), map[string]interface{}{"attack_type": req.AttackType, "samples": req.SampleCount}, "success", "")

	c.JSON(http.StatusOK, gin.H{
		"id":      fmt.Sprintf("%v", result.InsertedID),
		"name":    doc["name"],
		"type":    doc["type"],
		"samples": doc["samples"],
		"status":  "ready",
	})
}

func DeleteDataset(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		LogAction(c, "dataset_delete", "dataset", "", nil, "failure", "dataset id is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "dataset id is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "datasets")

	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		LogAction(c, "dataset_delete", "dataset", id, nil, "failure", "invalid dataset id")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dataset id"})
		return
	}

	result, err := collection.DeleteOne(ctx, bson.M{"_id": oid})
	if err != nil {
		LogAction(c, "dataset_delete", "dataset", id, nil, "failure", "failed to delete dataset")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete dataset"})
		return
	}
	if result.DeletedCount == 0 {
		LogAction(c, "dataset_delete", "dataset", id, nil, "failure", "dataset not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "dataset not found"})
		return
	}

	LogAction(c, "dataset_delete", "dataset", id, nil, "success", "")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

type MergeDatasetsRequest struct {
	IDs  []string `json:"ids" binding:"required"`
	Name string   `json:"name" binding:"required"`
}

func MergeDatasets(c *gin.Context) {
	var req MergeDatasetsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		LogAction(c, "dataset_merge", "dataset", "", nil, "failure", "invalid request payload")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	if len(req.IDs) < 2 {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "at least 2 dataset IDs are required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least 2 dataset IDs are required"})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs}, "failure", "name is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	collection := db.GetCollection("modintel", "datasets")

	var objectIDs []primitive.ObjectID
	for _, id := range req.IDs {
		oid, err := primitive.ObjectIDFromHex(strings.TrimSpace(id))
		if err != nil {
			LogAction(c, "dataset_merge", "dataset", id, map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "invalid dataset ID")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dataset ID: " + id})
			return
		}
		objectIDs = append(objectIDs, oid)
	}

	cursor, err := collection.Find(ctx, bson.M{"_id": bson.M{"$in": objectIDs}})
	if err != nil {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "failed to fetch datasets")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch datasets"})
		return
	}
	defer cursor.Close(ctx)

	var datasets []bson.M
	if err := cursor.All(ctx, &datasets); err != nil {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "failed to decode datasets")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode datasets"})
		return
	}

	if len(datasets) != len(objectIDs) {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "some datasets not found")
		c.JSON(http.StatusBadRequest, gin.H{"error": "some datasets not found"})
		return
	}

	totalSamples := 0
	attackSamples := 0
	for _, ds := range datasets {
		if samples, ok := ds["samples"].(int32); ok {
			totalSamples += int(samples)
		}
		if attackPct, ok := ds["attack_pct"].(int32); ok {
			samples := int32(0)
			if s, ok := ds["samples"].(int32); ok {
				samples = s
			}
			attackSamples += int(float64(samples) * float64(attackPct) / 100)
		}
	}

	mergedAttackPct := float64(0)
	if totalSamples > 0 {
		mergedAttackPct = float64(attackSamples) / float64(totalSamples) * 100
	}

	now := time.Now().UTC()
	mergedDoc := bson.M{
		"name":       strings.TrimSpace(req.Name),
		"type":       "Mixed",
		"samples":    int64(totalSamples),
		"attack_pct": mergedAttackPct,
		"created_at": now,
		"source":     "merged",
		"status":     "ready",
	}

	insertResult, err := collection.InsertOne(ctx, mergedDoc)
	if err != nil {
		LogAction(c, "dataset_merge", "dataset", "", map[string]interface{}{"ids": req.IDs, "name": req.Name}, "failure", "failed to create merged dataset")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create merged dataset"})
		return
	}

	_, err = collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objectIDs}})
	if err != nil {
		log.Printf("Warning: failed to delete original datasets after merge: %v", err)
	}

	LogAction(c, "dataset_merge", "dataset", insertResult.InsertedID.(primitive.ObjectID).Hex(), map[string]interface{}{"ids": req.IDs, "name": req.Name, "samples": totalSamples, "attack_pct": mergedAttackPct}, "success", "")

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"id":         insertResult.InsertedID.(primitive.ObjectID).Hex(),
		"name":       req.Name,
		"samples":    totalSamples,
		"attack_pct": mergedAttackPct,
	})
}

func ProxyToAuthService(c *gin.Context) {
	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://auth-service:8084"
	}

	targetURL := authServiceURL + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, targetURL, c.Request.Body)
	if err != nil {
		log.Printf("failed creating proxy request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to proxy request"})
		return
	}

	for key, values := range c.Request.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("failed proxying to auth-service: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authentication service unavailable"})
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			c.Writer.Header().Add(key, value)
		}
	}

	c.Status(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		log.Printf("failed copying response body: %v", err)
	}
}
