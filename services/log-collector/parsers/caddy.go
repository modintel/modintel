package parsers

import (
	"encoding/json"
	"net/url"
	"time"
)

func ParseCaddyAccessLog(raw []byte) (*AlertDocument, error) {
	var rawData map[string]interface{}
	if err := json.Unmarshal(raw, &rawData); err != nil {
		return nil, err
	}

	doc := &AlertDocument{
		Status:   "generated",
		AIStatus: "unavailable",
		RawLog:   rawData,
		Headers:  make(map[string]string),
	}

	if ts, ok := rawData["ts"].(float64); ok {
		doc.Timestamp = time.Unix(0, int64(ts*1e9)).UTC().Format(time.RFC3339Nano)
	} else {
		doc.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if request, ok := rawData["request"].(map[string]interface{}); ok {
		if ip, ok := request["remote_ip"].(string); ok {
			doc.ClientIP = ip
		}
		if method, ok := request["method"].(string); ok {
			doc.Method = method
		}
		if uri, ok := request["uri"].(string); ok {
			doc.URI = uri
		}
		if headers, ok := request["headers"].(map[string]interface{}); ok {
			doc.HeaderCount = len(headers)
			for k, v := range headers {
				switch cv := v.(type) {
				case string:
					doc.Headers[k] = cv
				case []interface{}:
					if len(cv) > 0 {
						if s, ok := cv[0].(string); ok {
							doc.Headers[k] = s
						}
					}
				}
			}
		}
	}

	status := 0
	if s, ok := rawData["status"].(float64); ok {
		status = int(s)
	}

	if status == 403 {
		doc.AnomalyScore = 1.0
	} else {
		doc.AnomalyScore = 0.0
	}

	doc.QueryParams = make(map[string]string)
	if doc.URI != "" {
		if parsed, err := url.Parse(doc.URI); err == nil {
			for k, vals := range parsed.Query() {
				if len(vals) > 0 {
					doc.QueryParams[k] = vals[0]
				}
			}
		}
	}

	doc.TimeBucket = bucketMinuteUTC(doc.Timestamp)
	doc.RequestFingerprintVersion = "rfp-v1"
	doc.RequestFingerprint = computeRequestFingerprint(doc)

	return doc, nil
}
