package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParseCursorParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    map[string]string
		expectedLimit  int
		expectedCursor string
		expectError    bool
	}{
		{"Default values", map[string]string{}, 50, "", false},
		{"Custom limit", map[string]string{"limit": "25"}, 25, "", false},
		{"With cursor", map[string]string{"cursor": "507f1f77bcf86cd799439011", "limit": "100"}, 100, "507f1f77bcf86cd799439011", false},
		{"Invalid limit too high", map[string]string{"limit": "600"}, 0, "", true},
		{"Invalid limit negative", map[string]string{"limit": "-5"}, 0, "", true},
		{"Invalid limit not number", map[string]string{"limit": "abc"}, 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup gin context with query params
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Add(key, value)
			}
			req.URL.RawQuery = q.Encode()
			c.Request = req

			params, err := parseCursorParams(c)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if params.Limit != tt.expectedLimit {
				t.Errorf("Expected limit %d, got %d", tt.expectedLimit, params.Limit)
			}
			if params.Cursor != tt.expectedCursor {
				t.Errorf("Expected cursor '%s', got '%s'", tt.expectedCursor, params.Cursor)
			}
		})
	}
}

func TestParseOffsetParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		queryParams   map[string]string
		expectedPage  int
		expectedLimit int
		expectError   bool
	}{
		{"Default values", map[string]string{}, 1, 50, false},
		{"Custom page and limit", map[string]string{"page": "3", "limit": "30"}, 3, 30, false},
		{"Invalid page", map[string]string{"page": "0"}, 0, 0, true},
		{"Invalid limit too high", map[string]string{"limit": "600"}, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Add(key, value)
			}
			req.URL.RawQuery = q.Encode()
			c.Request = req

			params, err := parseOffsetParams(c)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if params.Page != tt.expectedPage {
				t.Errorf("Expected page %d, got %d", tt.expectedPage, params.Page)
			}
			if params.Limit != tt.expectedLimit {
				t.Errorf("Expected limit %d, got %d", tt.expectedLimit, params.Limit)
			}
		})
	}
}

func TestBuildCursorFilter(t *testing.T) {
	tests := []struct {
		name        string
		cursor      string
		expectError bool
	}{
		{"Empty cursor", "", false},
		{"Valid ObjectID", "507f1f77bcf86cd799439011", false},
		{"Invalid cursor", "invalid-cursor", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := buildCursorFilter(tt.cursor)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error for invalid cursor")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.cursor == "" && len(filter) != 0 {
				t.Error("Empty cursor should return empty filter")
			}
		})
	}
}