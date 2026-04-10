package parsers

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RuleDetail struct {
	RuleID   string `bson:"rule_id" json:"rule_id"`
	Severity string `bson:"severity" json:"severity"`
	Message  string `bson:"message" json:"message"`
}

type AlertDocument struct {
	ID             primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Timestamp      string                 `bson:"timestamp" json:"timestamp"`
	ClientIP       string                 `bson:"client_ip" json:"client_ip"`
	URI            string                 `bson:"uri" json:"uri"`
	Method         string                 `bson:"method" json:"method"`
	Body           string                 `bson:"body" json:"body"`
	Headers        map[string]string      `bson:"headers" json:"headers"`
	TriggeredRules []string               `bson:"triggered_rules" json:"triggered_rules"`
	AnomalyScore   float64                `bson:"anomaly_score" json:"anomaly_score"`
	Status         string                 `bson:"status" json:"status"`
	MLScore        *float64               `bson:"ml_score" json:"ml_score"`
	HumanLabel     *string                `bson:"human_label" json:"human_label"`
	RawLog         map[string]interface{} `bson:"raw_log" json:"raw_log"`

	// Inference input fields
	BodyLength   int               `bson:"body_length" json:"body_length"`
	HeaderCount  int               `bson:"header_count" json:"header_count"`
	QueryParams  map[string]string `bson:"query_params" json:"query_params"`
	RuleDetails  []RuleDetail      `bson:"rule_details" json:"rule_details"`

	// AI enrichment fields
	AIStatus             string                 `bson:"ai_status" json:"ai_status"`
	AIScore              *float64               `bson:"ai_score" json:"ai_score"`
	AIConfidence         *float64               `bson:"ai_confidence" json:"ai_confidence"`
	AIPriority           *string                `bson:"ai_priority" json:"ai_priority"`
	AIExplanation        map[string]interface{} `bson:"ai_explanation" json:"ai_explanation"`
	AIModelVersion       *string                `bson:"ai_model_version" json:"ai_model_version"`
	AIConfidenceInterval map[string]float64     `bson:"ai_confidence_interval" json:"ai_confidence_interval"`
	AIEntropy            *float64               `bson:"ai_entropy" json:"ai_entropy"`
}

func ParseCorazaLog(raw []byte) (*AlertDocument, error) {
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

	if transaction, ok := rawData["transaction"].(map[string]interface{}); ok {
		if ts, ok := transaction["timestamp"].(string); ok {
			doc.Timestamp = ts
		} else {
			doc.Timestamp = time.Now().UTC().Format(time.RFC3339)
		}
		if ip, ok := transaction["client_ip"].(string); ok {
			doc.ClientIP = ip
		}
		if req, ok := transaction["request"].(map[string]interface{}); ok {
			if uri, ok := req["uri"].(string); ok {
				doc.URI = uri
			}
			if method, ok := req["method"].(string); ok {
				doc.Method = method
			}
			if body, ok := req["body"].(string); ok {
				doc.Body = body
				doc.BodyLength = len(body)
			}
			if headers, ok := req["headers"].(map[string]interface{}); ok {
				doc.HeaderCount = len(headers)
				for k, v := range headers {
					if sv, ok := v.(string); ok {
						doc.Headers[k] = sv
					}
				}
			}
		}
	} else {
		doc.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Parse query params from URI
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

	var triggeredRules []string
	triggeredRulesSet := make(map[string]bool)
	anomalyScore := 0.0
	var ruleDetails []RuleDetail

	if messages, ok := rawData["messages"].([]interface{}); ok {
		for _, msgObj := range messages {
			if msg, ok := msgObj.(map[string]interface{}); ok {
				mText, hasMessage := msg["message"].(string)

				if mData, ok := msg["data"].(map[string]interface{}); ok {
					if idVal, ok := mData["id"]; ok {
						ruleId := 0
						switch v := idVal.(type) {
						case float64:
							ruleId = int(v)
						case int:
							ruleId = v
						}

						ruleIdStr := strconv.Itoa(ruleId)
						if _, exists := triggeredRulesSet[ruleIdStr]; !exists {
							if hasMessage && mText != "" {
								triggeredRules = append(triggeredRules, ruleIdStr)
								triggeredRulesSet[ruleIdStr] = true
							}
						}

						// Collect rule detail for every rule
						severity, _ := mData["severity"].(string)
						detail := RuleDetail{
							RuleID:   ruleIdStr,
							Severity: severity,
							Message:  mText,
						}
						ruleDetails = append(ruleDetails, detail)
					}
				}
				if hasMessage {
					if strings.Contains(mText, "Inbound Anomaly Score Exceeded") {
						parts := strings.Split(mText, "Total Score: ")
						if len(parts) > 1 {
							trimmed := strings.TrimRight(parts[1], ")")
							if s, err := strconv.ParseFloat(trimmed, 64); err == nil {
								anomalyScore = s
							}
						}
					}
				}
			}
		}
	}

	doc.TriggeredRules = triggeredRules
	doc.AnomalyScore = anomalyScore
	doc.RuleDetails = ruleDetails

	return doc, nil
}
