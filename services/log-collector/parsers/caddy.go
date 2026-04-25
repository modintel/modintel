package parsers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type CaddyAccessLog struct {
	Level   string  `json:"level"`
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Msg     string  `json:"msg"`
	Request struct {
		RemoteIP   string              `json:"remote_ip"`
		RemotePort string              `json:"remote_port"`
		ClientIP   string              `json:"client_ip"`
		Proto      string              `json:"proto"`
		Method     string              `json:"method"`
		Host       string              `json:"host"`
		URI        string              `json:"uri"`
		Headers    map[string][]string `json:"headers"`
	} `json:"request"`
	BytesRead    int                 `json:"bytes_read"`
	Duration     float64             `json:"duration"`
	Size         int                 `json:"size"`
	Status       int                 `json:"status"`
	RespHeaders  map[string][]string `json:"resp_headers"`
	RequestBody  string              `json:"request_body"`
	CapturedBody string              `json:"captured_body"`
}

func ParseCaddyAccessLog(data []byte) (*AlertDocument, error) {
	var caddy CaddyAccessLog
	if err := json.Unmarshal(data, &caddy); err != nil {
		return nil, fmt.Errorf("unmarshal caddy log: %w", err)
	}

	capturedBody := extractFirstJsonValue(data, "captured_body")
	if capturedBody == "" {
		capturedBody = extractFirstJsonValue(data, "request_body")
	}

	doc := &AlertDocument{
		Timestamp:      time.Unix(int64(caddy.TS), 0).UTC().Format(time.RFC3339),
		ClientIP:       caddy.Request.ClientIP,
		Method:         caddy.Request.Method,
		URI:            caddy.Request.URI,
		Headers:        flattenHeaders(caddy.Request.Headers),
		HTTPStatus:     caddy.Status,
		TriggeredRules: []string{},
		AnomalyScore:   0,
		RuleDetails:    []RuleDetail{},
		AIStatus:       "pending",
		Source:         "unknown",
	}

	if capturedBody != "" {
		doc.Body = capturedBody
		doc.BodyLength = len(capturedBody)
	} else if caddy.Request.Method == "GET" || caddy.Request.Method == "HEAD" {
		if u, err := url.Parse(caddy.Request.URI); err == nil {
			doc.Body = u.RawQuery
		}
	}

	return doc, nil
}

func extractFirstJsonValue(data []byte, key string) string {
	searchKey := `"` + key + `":`
	idx := strings.Index(string(data), searchKey)
	if idx == -1 {
		return ""
	}
	valueStart := idx + len(searchKey)
	remaining := data[valueStart:]
	end := findJsonStringEnd(remaining)
	if end == 0 {
		end = len(remaining)
	}
	trimmed := remaining[:end]
	var raw string
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		end2 := strings.Index(string(trimmed), "\",\"")
		if end2 > 0 {
			raw = string(trimmed[:end2])
		} else {
			raw = string(trimmed)
		}
	}
	return raw
}

func findJsonStringEnd(data []byte) int {
	if len(data) == 0 || data[0] != '"' {
		return 0
	}
	escaped := false
	for i := 1; i < len(data); i++ {
		if escaped {
			escaped = false
			continue
		}
		if data[i] == '\\' {
			escaped = true
			continue
		}
		if data[i] == '"' {
			return i + 1
		}
	}
	return 0
}

func flattenHeaders(headers map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

func IsBlockedByWAF(status int) bool {
	return status == 403 || status == 406 || status == 500
}

func IsWAFPassed(status int) bool {
	return status >= 200 && status < 400
}
