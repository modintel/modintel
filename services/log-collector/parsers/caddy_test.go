package parsers

import (
	"testing"
)

func TestParseCaddyAccessLog(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		wantStatus  int
		wantMethod  string
		wantURI     string
		wantBlocked bool
	}{
		{
			name: "Normal GET request",
			jsonData: `{
				"level":"info",
				"ts":1712345678.123,
				"request":{"method":"GET","uri":"/index.html","client_ip":"192.168.1.100"},
				"status":200
			}`,
			wantStatus:  200,
			wantMethod:  "GET",
			wantURI:     "/index.html",
			wantBlocked: false,
		},
		{
			name: "Blocked WAF request",
			jsonData: `{
				"level":"info",
				"ts":1712345678.123,
				"request":{"method":"POST","uri":"/login.php?id=1' OR 1=1","client_ip":"10.0.0.5"},
				"status":403
			}`,
			wantStatus:  403,
			wantMethod:  "POST",
			wantURI:     "/login.php?id=1' OR 1=1",
			wantBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseCaddyAccessLog([]byte(tt.jsonData))
			if err != nil {
				t.Fatalf("ParseCaddyAccessLog failed: %v", err)
			}

			if doc.HTTPStatus != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, doc.HTTPStatus)
			}
			if doc.Method != tt.wantMethod {
				t.Errorf("Expected method %s, got %s", tt.wantMethod, doc.Method)
			}
			if doc.URI != tt.wantURI {
				t.Errorf("Expected URI %s, got %s", tt.wantURI, doc.URI)
			}

			if IsBlockedByWAF(doc.HTTPStatus) != tt.wantBlocked {
				t.Errorf("IsBlockedByWAF mismatch for status %d", doc.HTTPStatus)
			}
		})
	}
}

func TestIsBlockedByWAF(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{403, true},
		{406, true},
		{500, true},
		{200, false},
		{404, false},
		{301, false},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.status)), func(t *testing.T) {
			if got := IsBlockedByWAF(tt.status); got != tt.want {
				t.Errorf("IsBlockedByWAF(%d) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestFlattenHeaders(t *testing.T) {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0", "Other"},
		"X-Custom":     {},
	}

	flattened := flattenHeaders(headers)

	if flattened["Content-Type"] != "application/json" {
		t.Error("Content-Type not flattened correctly")
	}
	if flattened["User-Agent"] != "Mozilla/5.0" {
		t.Error("User-Agent should take first value")
	}
	if _, exists := flattened["X-Custom"]; exists {
		t.Error("Empty header slice should not be included")
	}
}

func TestExtractFirstJsonValue(t *testing.T) {
	data := []byte(`{"level":"info","captured_body":"SELECT * FROM users","request_body":"test=data"}`)

	body := extractFirstJsonValue(data, "captured_body")
	if body != "SELECT * FROM users" {
		t.Errorf("Expected captured_body value, got: %s", body)
	}

	body2 := extractFirstJsonValue(data, "request_body")
	if body2 != "test=data" {
		t.Errorf("Expected request_body value, got: %s", body2)
	}
}

func TestFindJsonStringEnd(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{`"hello"`, 7},
		{`"hello\"world"`, 14},
		{`normal text`, 0},
		{`""`, 2},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := findJsonStringEnd([]byte(tt.input))
			if got != tt.expected {
				t.Errorf("findJsonStringEnd(%s) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}