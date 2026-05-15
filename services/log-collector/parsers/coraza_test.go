package parsers

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseCorazaLog(t *testing.T) {
	rawLog := map[string]interface{}{
		"transaction": map[string]interface{}{
			"timestamp": "2026/05/15 10:30:45",
			"client_ip": "192.168.1.15",
			"request": map[string]interface{}{
				"uri":    "/login?user=admin&id=1",
				"method": "POST",
				"body":   "{\"username\":\"admin\"}",
				"headers": map[string]interface{}{
					"Content-Type": "application/json",
					"User-Agent":   "Mozilla/5.0",
				},
			},
		},
		"messages": []interface{}{
			map[string]interface{}{
				"message": "SQL Injection Attack Detected",
				"data": map[string]interface{}{
					"id":       float64(942100),
					"severity": "CRITICAL",
				},
			},
			map[string]interface{}{
				"message": "Inbound Anomaly Score Exceeded (Total Score: 7)",
				"data": map[string]interface{}{
					"id":       float64(949110),
					"severity": "ERROR",
				},
			},
		},
	}

	rawBytes, err := json.Marshal(rawLog)
	if err != nil {
		t.Fatalf("failed to marshal test log: %v", err)
	}

	doc, err := ParseCorazaLog(rawBytes)
	if err != nil {
		t.Fatalf("ParseCorazaLog returned error: %v", err)
	}

	// Timestamp
	expectedTime, _ := time.Parse("2006/01/02 15:04:05", "2026/05/15 10:30:45")
	expectedTimestamp := expectedTime.UTC().Format(time.RFC3339)

	if doc.Timestamp != expectedTimestamp {
		t.Errorf("expected timestamp %s, got %s", expectedTimestamp, doc.Timestamp)
	}

	// Client IP
	if doc.ClientIP != "192.168.1.15" {
		t.Errorf("expected client IP 192.168.1.15, got %s", doc.ClientIP)
	}

	// URI
	if doc.URI != "/login?user=admin&id=1" {
		t.Errorf("unexpected URI: %s", doc.URI)
	}

	// Method
	if doc.Method != "POST" {
		t.Errorf("expected method POST, got %s", doc.Method)
	}

	// Body
	if doc.Body != "{\"username\":\"admin\"}" {
		t.Errorf("unexpected body: %s", doc.Body)
	}

	// Body length
	if doc.BodyLength != len("{\"username\":\"admin\"}") {
		t.Errorf("unexpected body length: %d", doc.BodyLength)
	}

	// Header count
	if doc.HeaderCount != 2 {
		t.Errorf("expected header count 2, got %d", doc.HeaderCount)
	}

	// Triggered rules
	expectedRules := []string{"942100", "949110"}

	if len(doc.TriggeredRules) != len(expectedRules) {
		t.Fatalf("expected %d triggered rules, got %d",
			len(expectedRules), len(doc.TriggeredRules))
	}

	for i, rule := range expectedRules {
		if doc.TriggeredRules[i] != rule {
			t.Errorf("expected rule %s, got %s",
				rule, doc.TriggeredRules[i])
		}
	}

	// Anomaly score
	if doc.AnomalyScore != 7 {
		t.Errorf("expected anomaly score 7, got %f", doc.AnomalyScore)
	}

	// Query params
	if doc.QueryParams["user"] != "admin" {
		t.Errorf("expected query param user=admin")
	}

	if doc.QueryParams["id"] != "1" {
		t.Errorf("expected query param id=1")
	}

	// Rule details
	if len(doc.RuleDetails) != 2 {
		t.Fatalf("expected 2 rule details, got %d", len(doc.RuleDetails))
	}

	if doc.RuleDetails[0].RuleID != "942100" {
		t.Errorf("unexpected first rule detail ID")
	}

	if doc.RuleDetails[0].Severity != "CRITICAL" {
		t.Errorf("unexpected severity")
	}

	// Status
	if doc.Status != "generated" {
		t.Errorf("expected status generated, got %s", doc.Status)
	}

	// AI Status
	if doc.AIStatus != "unavailable" {
		t.Errorf("expected AI status unavailable, got %s", doc.AIStatus)
	}

	// Request fingerprint
	if doc.RequestFingerprint == "" {
		t.Error("expected request fingerprint to be generated")
	}

	// Fingerprint version
	if doc.RequestFingerprintVersion != "rfp-v1" {
		t.Errorf("expected fingerprint version rfp-v1, got %s",
			doc.RequestFingerprintVersion)
	}

	// Time bucket
	if doc.TimeBucket == "" {
		t.Error("expected time bucket to be generated")
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/LOGIN/Admin", "/login/admin"},
		{"///api///v1///", "/api/v1"},
	}

	for _, tt := range tests {
		result := normalizePath(tt.input)

		if result != tt.expected {
			t.Errorf("normalizePath(%q) = %q; expected %q",
				tt.input, result, tt.expected)
		}
	}
}

func TestIPv4Bucket(t *testing.T) {
	result := ipv4Bucket("192.168.1.44")
	expected := "192.168.1.0/24"

	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestSHA256Hex(t *testing.T) {
	result := sha256Hex("test")

	if len(result) != 64 {
		t.Errorf("expected sha256 hash length 64, got %d", len(result))
	}
}

