//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const (
	authBase       = "http://localhost:8084"
	reviewBase     = "http://localhost:8082"
	healthAggBase  = "http://localhost:8090"
	inferenceBase  = "http://localhost:8083"
	logCollBase    = "http://localhost:8081"
	proxyWAFAddr   = "localhost:8080"

	adminEmail    = "admin@modintel.local"
	adminPassword = "ChangeMe123!"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func getJSON(t *testing.T, url string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return resp.StatusCode, data
}

func postJSON(t *testing.T, url string, payload interface{}, token string) (int, map[string]interface{}) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return resp.StatusCode, data
}

func getWithAuth(t *testing.T, url, token string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return resp.StatusCode, data
}

// adminLogin logs in as the bootstrap admin and returns the access + refresh tokens.
func adminLogin(t *testing.T) (accessToken, refreshToken string) {
	t.Helper()
	code, data := postJSON(t, authBase+"/api/v1/auth/login", map[string]string{
		"email":    adminEmail,
		"password": adminPassword,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("admin login returned %d: %v", code, data)
	}
	d, _ := data["data"].(map[string]interface{})
	accessToken, _ = d["access_token"].(string)
	refreshToken, _ = d["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatal("login succeeded but tokens are empty")
	}
	return
}

// ---------------------------------------------------------------------------
// 1. Health-Check Tests
// ---------------------------------------------------------------------------

func TestHealthAuthService(t *testing.T) {
	code, data := getJSON(t, authBase+"/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if data["status"] != "ok" {
		t.Errorf("expected status ok, got %v", data["status"])
	}
}

func TestHealthReviewAPI(t *testing.T) {
	code, _ := getJSON(t, reviewBase+"/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestHealthAggregator(t *testing.T) {
	code, data := getJSON(t, healthAggBase+"/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if data["status"] != "ok" {
		t.Errorf("expected status ok, got %v", data["status"])
	}
}

func TestHealthInferenceEngine(t *testing.T) {
	code, _ := getJSON(t, inferenceBase+"/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestHealthLogCollector(t *testing.T) {
	code, _ := getJSON(t, logCollBase+"/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestProxyWAFTCPReachable(t *testing.T) {
	conn, err := net.DialTimeout("tcp", proxyWAFAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("proxy-waf not reachable on %s: %v", proxyWAFAddr, err)
	}
	conn.Close()
}

// ---------------------------------------------------------------------------
// 2. Auth Service – Login Flow
// ---------------------------------------------------------------------------

func TestLoginSuccess(t *testing.T) {
	code, data := postJSON(t, authBase+"/api/v1/auth/login", map[string]string{
		"email":    adminEmail,
		"password": adminPassword,
	}, "")

	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, data)
	}
	d, _ := data["data"].(map[string]interface{})
	if d["access_token"] == nil || d["refresh_token"] == nil {
		t.Error("tokens missing from login response")
	}
	if d["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", d["token_type"])
	}
	user, _ := d["user"].(map[string]interface{})
	if user["email"] != adminEmail {
		t.Errorf("expected email %s, got %v", adminEmail, user["email"])
	}
	if user["role"] != "admin" {
		t.Errorf("expected role admin, got %v", user["role"])
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	code, _ := postJSON(t, authBase+"/api/v1/auth/login", map[string]string{
		"email":    "wrong@modintel.local",
		"password": "WrongPassword999!",
	}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

func TestLoginMissingFields(t *testing.T) {
	code, _ := postJSON(t, authBase+"/api/v1/auth/login", map[string]string{
		"email": adminEmail,
	}, "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestLoginInvalidEmail(t *testing.T) {
	code, _ := postJSON(t, authBase+"/api/v1/auth/login", map[string]string{
		"email":    "not-an-email",
		"password": "SomePass123!",
	}, "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 3. Auth Service – Token Refresh
// ---------------------------------------------------------------------------

func TestTokenRefresh(t *testing.T) {
	_, refreshToken := adminLogin(t)

	code, data := postJSON(t, authBase+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, data)
	}
	d, _ := data["data"].(map[string]interface{})
	if d["access_token"] == nil || d["refresh_token"] == nil {
		t.Error("new tokens missing from refresh response")
	}
}

func TestTokenRefreshInvalid(t *testing.T) {
	code, _ := postJSON(t, authBase+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": "invalid.token.here",
	}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 4. Auth Service – Protected Endpoints
// ---------------------------------------------------------------------------

func TestMeEndpoint(t *testing.T) {
	token, _ := adminLogin(t)

	code, data := getWithAuth(t, authBase+"/api/v1/auth/me", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	d, _ := data["data"].(map[string]interface{})
	if d["email"] != adminEmail {
		t.Errorf("expected %s, got %v", adminEmail, d["email"])
	}
}

func TestMeWithoutToken(t *testing.T) {
	code, _ := getJSON(t, authBase+"/api/v1/auth/me")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

func TestLogout(t *testing.T) {
	_, refreshToken := adminLogin(t)

	code, data := postJSON(t, authBase+"/api/v1/auth/logout", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, data)
	}

	// Refreshing with the revoked token should fail.
	code2, _ := postJSON(t, authBase+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if code2 != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", code2)
	}
}

// ---------------------------------------------------------------------------
// 5. Review API – Authenticated Endpoints
// ---------------------------------------------------------------------------

func TestReviewAPIRules(t *testing.T) {
	token, _ := adminLogin(t)

	code, data := getWithAuth(t, reviewBase+"/api/rules", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if data["data"] == nil {
		t.Error("rules response missing data field")
	}
}

func TestReviewAPIAlerts(t *testing.T) {
	token, _ := adminLogin(t)

	code, _ := getWithAuth(t, reviewBase+"/api/alerts", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestReviewAPIStats(t *testing.T) {
	token, _ := adminLogin(t)

	code, _ := getWithAuth(t, reviewBase+"/api/stats", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestReviewAPITrend(t *testing.T) {
	token, _ := adminLogin(t)

	for _, r := range []string{"day", "week", "month"} {
		t.Run(r, func(t *testing.T) {
			code, data := getWithAuth(t, fmt.Sprintf("%s/api/trend?range=%s", reviewBase, r), token)
			if code != http.StatusOK {
				t.Fatalf("expected 200, got %d", code)
			}
			if data["labels"] == nil || data["values"] == nil {
				t.Error("trend response missing labels/values")
			}
		})
	}
}

func TestReviewAPIConfig(t *testing.T) {
	token, _ := adminLogin(t)

	code, data := getWithAuth(t, reviewBase+"/api/config", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if data["waf_engine"] == nil {
		t.Error("config response missing waf_engine")
	}
}

func TestReviewAPIWhoAmI(t *testing.T) {
	token, _ := adminLogin(t)

	code, data := getWithAuth(t, reviewBase+"/api/whoami", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	d, _ := data["data"].(map[string]interface{})
	if d["email"] != adminEmail {
		t.Errorf("expected email %s, got %v", adminEmail, d["email"])
	}
}

func TestReviewAPIUnauthorized(t *testing.T) {
	code, _ := getJSON(t, reviewBase+"/api/rules")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// 6. Health Aggregator – Aggregate Endpoints
// ---------------------------------------------------------------------------

func TestAggregateHealth(t *testing.T) {
	code, data := getJSON(t, healthAggBase+"/aggregate/health")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	services, ok := data["services"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing services map")
	}
	expected := []string{"proxy-waf", "review-api", "log-collector", "inference-engine", "auth-service"}
	for _, svc := range expected {
		if _, exists := services[svc]; !exists {
			t.Errorf("service %q not found in aggregate health", svc)
		}
	}
}

func TestAggregateHealthDetailed(t *testing.T) {
	code, data := getJSON(t, healthAggBase+"/aggregate/health/detailed")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if data["services"] == nil {
		t.Error("detailed response missing services")
	}
	if data["timestamp"] == nil {
		t.Error("detailed response missing timestamp")
	}
}

// ---------------------------------------------------------------------------
// 7. Inference Engine – Predict Endpoint
// ---------------------------------------------------------------------------

func TestPredictEndpoint(t *testing.T) {
	payload := map[string]interface{}{
		"method":            "POST",
		"uri":               "/login.php?id=1' OR '1'='1",
		"body":              "username=admin&password=123",
		"anomaly_score":     65,
		"inbound_threshold": 30,
		"fired_rule_ids":    []string{"942100"},
		"rule_severities":   map[string]string{"942100": "critical"},
	}
	code, data := postJSON(t, inferenceBase+"/predict", payload, "")
	// 200 = model loaded, 500 = model not loaded (both acceptable in CI)
	if code != http.StatusOK && code != http.StatusInternalServerError {
		t.Fatalf("expected 200 or 500, got %d", code)
	}
	if code == http.StatusOK {
		if data["attack_probability"] == nil {
			t.Error("predict response missing attack_probability")
		}
		if data["recommended_priority"] == nil {
			t.Error("predict response missing recommended_priority")
		}
	}
}

// ---------------------------------------------------------------------------
// 8. Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentHealthChecks(t *testing.T) {
	const n = 10
	var wg sync.WaitGroup
	results := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := httpClient.Get(healthAggBase + "/aggregate/health")
			if err != nil {
				results[idx] = -1
				return
			}
			results[idx] = resp.StatusCode
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, code := range results {
		if code == http.StatusOK {
			ok++
		}
	}
	if ok < n/2 {
		t.Errorf("only %d/%d concurrent requests succeeded", ok, n)
	}
}

// ---------------------------------------------------------------------------
// 9. Review API – Metrics & Monitor
// ---------------------------------------------------------------------------

func TestReviewAPIMetrics(t *testing.T) {
	resp, err := httpClient.Get(reviewBase + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestReviewAPIMonitorHealth(t *testing.T) {
	token, _ := adminLogin(t)

	code, _ := getWithAuth(t, reviewBase+"/api/monitor/health", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestReviewAPIMonitorMetrics(t *testing.T) {
	token, _ := adminLogin(t)

	code, _ := getWithAuth(t, reviewBase+"/api/monitor/metrics", token)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}
