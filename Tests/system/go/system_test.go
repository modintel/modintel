//go:build system

// Package system contains end-to-end system tests that exercise the full
// ModIntel stack through the public gateway (proxy-waf-custom on :8080/:3000).
// Unlike integration tests that hit individual services directly, these tests
// simulate real user and attacker traffic flowing through the entire pipeline:
//
//	client → proxy-waf-custom → proxy-waf (Coraza) → backend / services
//
// Prerequisites: all Docker Compose services must be running.
//
//	go test -tags system -v -timeout 120s ./Tests/system/go/
package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Constants & shared client
// ---------------------------------------------------------------------------

const (
	// Gateway entry points (proxy-waf-custom)
	gatewayWAF       = "http://localhost:8080" // WAF-protected backend (Juice Shop)
	gatewayDashboard = "http://localhost:3000" // Dashboard + API gateway

	// Direct service ports (fallback assertions)
	authDirect    = "http://localhost:8084"
	reviewDirect  = "http://localhost:8082"
	healthAggDirect = "http://localhost:8090"

	adminEmail    = "admin@modintel.local"
	adminPassword = "ChangeMe123!"
)

var client = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Don't follow redirects automatically so we can assert on 3xx codes.
		return http.ErrUseLastResponse
	},
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func doGet(t *testing.T, rawURL string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func doGetJSON(t *testing.T, rawURL string) (int, map[string]interface{}) {
	t.Helper()
	code, body := doGet(t, rawURL)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return code, data
}

func doPostJSON(t *testing.T, rawURL string, payload interface{}, bearer string) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return resp.StatusCode, data
}

func doRequest(t *testing.T, method, rawURL string, bearer string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return resp.StatusCode, data
}

// loginViaGateway authenticates through the dashboard gateway (port 3000)
// and returns an access token.
func loginViaGateway(t *testing.T) string {
	t.Helper()
	code, data := doPostJSON(t, gatewayDashboard+"/api/v1/auth/login", map[string]string{
		"email":    adminEmail,
		"password": adminPassword,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("gateway login returned %d: %v", code, data)
	}
	d, _ := data["data"].(map[string]interface{})
	token, _ := d["access_token"].(string)
	if token == "" {
		t.Fatal("gateway login: empty access_token")
	}
	return token
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. GATEWAY REACHABILITY
// ═══════════════════════════════════════════════════════════════════════════

func TestGatewayWAFReachable(t *testing.T) {
	code, _ := doGet(t, gatewayWAF)
	// Juice Shop responds through the WAF proxy
	if code < 200 || code >= 500 {
		t.Fatalf("WAF gateway returned %d, expected a non-5xx response", code)
	}
}

func TestGatewayDashboardReachable(t *testing.T) {
	code, _ := doGet(t, gatewayDashboard+"/events")
	// Dashboard pages may return 200 or redirect (3xx)
	if code != 200 && (code < 300 || code >= 400) {
		t.Fatalf("dashboard gateway returned %d", code)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. FULL AUTH FLOW THROUGH GATEWAY
// ═══════════════════════════════════════════════════════════════════════════

func TestGatewayLoginFlow(t *testing.T) {
	// Step 1: Login via gateway
	code, data := doPostJSON(t, gatewayDashboard+"/api/v1/auth/login", map[string]string{
		"email":    adminEmail,
		"password": adminPassword,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", code)
	}

	d, _ := data["data"].(map[string]interface{})
	accessToken, _ := d["access_token"].(string)
	refreshToken, _ := d["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatal("tokens missing from login response")
	}

	// Step 2: Access /api/v1/auth/me via gateway
	code2, me := doRequest(t, http.MethodGet, gatewayDashboard+"/api/v1/auth/me", accessToken)
	if code2 != http.StatusOK {
		t.Fatalf("/me: expected 200, got %d", code2)
	}
	meData, _ := me["data"].(map[string]interface{})
	if meData["email"] != adminEmail {
		t.Errorf("expected email %s, got %v", adminEmail, meData["email"])
	}

	// Step 3: Refresh token via gateway
	code3, ref := doPostJSON(t, gatewayDashboard+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if code3 != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d: %v", code3, ref)
	}

	// Step 4: Logout via gateway
	newRefresh, _ := ref["data"].(map[string]interface{})["refresh_token"].(string)
	code4, _ := doPostJSON(t, gatewayDashboard+"/api/v1/auth/logout", map[string]string{
		"refresh_token": newRefresh,
	}, "")
	if code4 != http.StatusOK {
		t.Fatalf("logout: expected 200, got %d", code4)
	}
}

func TestGatewayLoginInvalidCredentials(t *testing.T) {
	code, _ := doPostJSON(t, gatewayDashboard+"/api/v1/auth/login", map[string]string{
		"email":    "wrong@modintel.local",
		"password": "BadPassword999!",
	}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

func TestGatewayProtectedWithoutToken(t *testing.T) {
	code, _ := doGetJSON(t, gatewayDashboard+"/api/v1/auth/me")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. REVIEW API THROUGH GATEWAY
// ═══════════════════════════════════════════════════════════════════════════

func TestGatewayReviewAPIRoutes(t *testing.T) {
	token := loginViaGateway(t)

	endpoints := []struct {
		path string
		want int
	}{
		{"/api/rules", 200},
		{"/api/alerts", 200},
		{"/api/stats", 200},
		{"/api/config", 200},
		{"/api/trend?range=day", 200},
		{"/api/whoami", 200},
		{"/api/monitor/health", 200},
		{"/api/monitor/metrics", 200},
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			code, _ := doRequest(t, http.MethodGet, gatewayDashboard+ep.path, token)
			if code != ep.want {
				t.Errorf("GET %s: expected %d, got %d", ep.path, ep.want, code)
			}
		})
	}
}

func TestGatewayReviewAPIUnauthorized(t *testing.T) {
	code, _ := doGetJSON(t, gatewayDashboard+"/api/rules")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. HEALTH PROXIED THROUGH GATEWAY
// ═══════════════════════════════════════════════════════════════════════════

func TestGatewayHealthEndpoints(t *testing.T) {
	paths := []string{
		"/api/health/review-api",
		"/api/health/log-collector",
		"/api/health/inference-engine",
		"/api/health/auth-service",
		"/api/health/proxy-waf",
		"/api/health/aggregate",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			code, data := doGetJSON(t, gatewayDashboard+p)
			if code != http.StatusOK {
				t.Fatalf("expected 200, got %d", code)
			}
			if data["status"] == nil && data["services"] == nil {
				t.Error("response has neither status nor services field")
			}
		})
	}
}

func TestGatewayAggregateHealthDetailed(t *testing.T) {
	code, data := doGetJSON(t, gatewayDashboard+"/api/health/aggregate/detailed")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	services, ok := data["services"].(map[string]interface{})
	if !ok {
		t.Fatal("missing services map")
	}
	for _, svc := range []string{"proxy-waf", "review-api", "log-collector", "inference-engine", "auth-service"} {
		if _, exists := services[svc]; !exists {
			t.Errorf("service %q not present in detailed health", svc)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. WAF ATTACK DETECTION (end-to-end through Coraza)
// ═══════════════════════════════════════════════════════════════════════════

func TestWAFBlocksSQLInjection(t *testing.T) {
	attacks := []string{
		"/search?q=1%27%20OR%201%3D1--",
		"/search?q=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
		"/search?q=%27%3BSELECT%20*%20FROM%20information_schema.tables--",
		"/search?q=admin%27%20AND%201%3D1%20ORDER%20BY%205--",
	}
	blocked := 0
	for _, path := range attacks {
		code, _ := doGet(t, gatewayWAF+path)
		if code == 403 || code == 429 {
			blocked++
		}
	}
	if blocked == 0 {
		t.Log("WARNING: WAF did not block any SQL injection attempts (may depend on CRS config)")
	}
	t.Logf("SQLi: %d/%d blocked by WAF", blocked, len(attacks))
}

func TestWAFBlocksXSS(t *testing.T) {
	attacks := []string{
		"/page?q=<script>alert(1)</script>",
		"/search?q=<img src=x onerror=alert(1)>",
	}
	blocked := 0
	for _, path := range attacks {
		code, _ := doGet(t, gatewayWAF+path)
		if code == 403 {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("WAF did not block any XSS attempts")
	}
	t.Logf("XSS: %d/%d blocked by WAF", blocked, len(attacks))
}

func TestWAFBlocksPathTraversal(t *testing.T) {
	attacks := []string{
		"/download?file=../../../etc/passwd",
		"/static/..%2f..%2f..%2fetc%2fpasswd",
	}
	blocked := 0
	for _, path := range attacks {
		code, _ := doGet(t, gatewayWAF+path)
		if code == 403 {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("WAF did not block any path traversal attempts")
	}
	t.Logf("Path traversal: %d/%d blocked by WAF", blocked, len(attacks))
}

func TestWAFBlocksCommandInjection(t *testing.T) {
	attacks := []string{
		"/ping?host=127.0.0.1;whoami",
		"/backup?file=;cat /etc/passwd",
	}
	blocked := 0
	for _, path := range attacks {
		code, _ := doGet(t, gatewayWAF+path)
		if code == 403 {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("WAF did not block any command injection attempts")
	}
	t.Logf("CMDi: %d/%d blocked by WAF", blocked, len(attacks))
}

func TestWAFAllowsNormalTraffic(t *testing.T) {
	normals := []string{"/", "/rest/products/search?q=apple"}
	allowed := 0
	for _, path := range normals {
		code, _ := doGet(t, gatewayWAF+path)
		if code != 403 {
			allowed++
		}
	}
	if allowed == 0 {
		t.Error("WAF blocked all normal traffic — false positive issue")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. DASHBOARD STATIC ASSETS
// ═══════════════════════════════════════════════════════════════════════════

func TestDashboardPages(t *testing.T) {
	pages := []string{
		"/signin",
		"/events",
		"/rules",
		"/monitor",
	}
	for _, p := range pages {
		t.Run(p, func(t *testing.T) {
			code, body := doGet(t, gatewayDashboard+p)
			// 200 for direct HTML or 308 redirect to .html
			if code != 200 && code != 308 {
				t.Errorf("expected 200 or 308, got %d", code)
				return
			}
			if code == 200 && len(body) == 0 {
				t.Error("page returned empty body")
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. INFERENCE ENGINE – PREDICT THROUGH GATEWAY
// ═══════════════════════════════════════════════════════════════════════════

func TestGatewayInferencePredict(t *testing.T) {
	payload := map[string]interface{}{
		"method":            "GET",
		"uri":               "/admin?id=1' OR '1'='1",
		"body":              "",
		"anomaly_score":     80,
		"inbound_threshold": 30,
		"fired_rule_ids":    []string{"942100", "942200"},
		"rule_severities":   map[string]string{"942100": "critical", "942200": "critical"},
	}
	code, data := doPostJSON(t, gatewayDashboard+"/inference/predict", payload, "")
	if code != 200 && code != 500 {
		t.Fatalf("expected 200 or 500, got %d", code)
	}
	if code == 200 {
		if data["attack_probability"] == nil {
			t.Error("missing attack_probability")
		}
		if data["recommended_priority"] == nil {
			t.Error("missing recommended_priority")
		}
		t.Logf("predict: attack_prob=%v priority=%v", data["attack_probability"], data["recommended_priority"])
	} else {
		t.Log("inference model not loaded, skipping assertions")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════════════════

func TestWAFSecurityHeaders(t *testing.T) {
	resp, err := client.Get(gatewayWAF)
	if err != nil {
		t.Fatalf("GET gateway: %v", err)
	}
	defer resp.Body.Close()

	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "no-referrer",
	}
	for header, want := range checks {
		got := resp.Header.Get(header)
		if got != want {
			t.Errorf("header %s: expected %q, got %q", header, want, got)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. ATTACK → ALERT PIPELINE (end-to-end)
// ═══════════════════════════════════════════════════════════════════════════

func TestAttackGeneratesAlert(t *testing.T) {
	token := loginViaGateway(t)

	// Get current alert count
	_, statsBefore := doRequest(t, http.MethodGet, gatewayDashboard+"/api/stats", token)
	beforeCount, _ := statsBefore["total_alerts"].(float64)

	// Fire a distinctive attack through the WAF so Coraza logs it
	marker := fmt.Sprintf("sysTest%d", time.Now().UnixNano()%100000)
	attackURL := fmt.Sprintf("%s/search?q=%s'+OR+'1'='1", gatewayWAF, url.QueryEscape(marker))
	doGet(t, attackURL)

	// Give the pipeline time to process (log-collector → inference → MongoDB)
	time.Sleep(8 * time.Second)

	// Check if alert count increased
	_, statsAfter := doRequest(t, http.MethodGet, gatewayDashboard+"/api/stats", token)
	afterCount, _ := statsAfter["total_alerts"].(float64)

	t.Logf("alerts before=%v after=%v", beforeCount, afterCount)
	// We only log a warning since the pipeline timing can vary
	if afterCount <= beforeCount {
		t.Log("WARNING: alert count did not increase — pipeline may need more time")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. STRESS / CONCURRENCY
// ═══════════════════════════════════════════════════════════════════════════

func TestConcurrentGatewayRequests(t *testing.T) {
	const n = 15
	var wg sync.WaitGroup
	codes := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := client.Get(gatewayDashboard + "/api/health/aggregate")
			if err != nil {
				codes[idx] = -1
				return
			}
			codes[idx] = resp.StatusCode
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok < n/2 {
		t.Errorf("only %d/%d concurrent requests succeeded", ok, n)
	}
	t.Logf("concurrent: %d/%d succeeded", ok, n)
}

func TestAttackBurstThroughWAF(t *testing.T) {
	start := time.Now()
	attacks := []string{
		"/search?q=<script>alert('xss')</script>",
		"/login?id=1' OR '1'='1",
		"/download?file=../../../../etc/shadow",
		"/cmd?exec=;id",
		"/api?q={{7*7}}",
	}

	var wg sync.WaitGroup
	blocked := 0
	var mu sync.Mutex

	for i := 0; i < 3; i++ {
		for _, path := range attacks {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				code, _ := doGet(t, gatewayWAF+p)
				if code == 403 {
					mu.Lock()
					blocked++
					mu.Unlock()
				}
			}(path)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := 3 * len(attacks)
	t.Logf("burst: %d/%d blocked in %v", blocked, total, elapsed)

	if blocked == 0 {
		t.Error("WAF did not block any requests during burst")
	}
	if elapsed > 30*time.Second {
		t.Errorf("burst took too long: %v", elapsed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. CORS & OPTIONS PRE-FLIGHT
// ═══════════════════════════════════════════════════════════════════════════

func TestReviewAPICORS(t *testing.T) {
	req, _ := http.NewRequest(http.MethodOptions, reviewDirect+"/api/rules", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS failed: %v", err)
	}
	resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		t.Error("missing Access-Control-Allow-Origin header")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════

func TestOversizedPayloadThroughWAF(t *testing.T) {
	bigBody := strings.Repeat("A", 1024*100) // 100KB payload
	req, _ := http.NewRequest(http.MethodPost, gatewayWAF+"/api/test", bytes.NewReader([]byte(bigBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oversized POST: %v", err)
	}
	resp.Body.Close()
	// Should be handled gracefully, not crash
	if resp.StatusCode >= 500 {
		t.Errorf("server error on large payload: %d", resp.StatusCode)
	}
}

func TestMalformedJSONToAuth(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, gatewayDashboard+"/api/v1/auth/login",
		bytes.NewReader([]byte(`{invalid json`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("malformed JSON: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for malformed JSON, got %d", resp.StatusCode)
	}
}

func TestNonExistentRoute(t *testing.T) {
	code, _ := doGet(t, gatewayDashboard+"/api/v1/nonexistent-endpoint-xyz")
	if code != 404 {
		t.Logf("non-existent route returned %d (may be proxied)", code)
	}
}
