package api

import (
	"context"
	"log"
	"time"
)

type auditEvent struct {
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]interface{}
	Outcome      string
	ErrorMessage string
	UserID       string
	UserEmail    string
	UserRole     string
	ClientIP     string
	UserAgent    string
}

type AuditEvent struct {
	Timestamp    time.Time              `bson:"timestamp" json:"timestamp"`
	Action       string                 `bson:"action" json:"action"`
	Outcome      string                 `bson:"outcome" json:"outcome"`
	UserID       string                 `bson:"user_id" json:"user_id"`
	UserEmail    string                 `bson:"user_email" json:"user_email"`
	UserRole     string                 `bson:"user_role" json:"user_role"`
	ResourceType string                 `bson:"resource_type" json:"resource_type"`
	ResourceID   string                 `bson:"resource_id" json:"resource_id"`
	Details      map[string]interface{} `bson:"details" json:"details"`
	IPAddress    string                 `bson:"ip_address" json:"ip_address"`
	UserAgent    string                 `bson:"user_agent" json:"user_agent"`
	ErrorMessage string                 `bson:"error_message,omitempty" json:"error_message,omitempty"`
}

func (h *Handler) logAuditEvent(event auditEvent) {
	if event.Action == "" {
		return
	}

	auditDoc := AuditEvent{
		Timestamp:    time.Now().UTC(),
		Action:       event.Action,
		Outcome:      event.Outcome,
		UserID:       event.UserID,
		UserEmail:    event.UserEmail,
		UserRole:     event.UserRole,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		IPAddress:    event.ClientIP,
		UserAgent:    event.UserAgent,
		ErrorMessage: event.ErrorMessage,
	}

	if h.db == nil || h.db.DB == nil {
		return
	}

	if event.Details != nil {
		details := map[string]interface{}{}
		for k, v := range event.Details {
			details[k] = v
		}
		if event.ClientIP != "" {
			details["client_ip"] = event.ClientIP
		}
		if event.UserAgent != "" {
			details["user_agent"] = event.UserAgent
		}
		auditDoc.Details = details
	}

	go h.saveAuditEvent(auditDoc)
}

func (h *Handler) saveAuditEvent(event AuditEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := h.db.DB.Collection("audit_logs")
	_, err := collection.InsertOne(ctx, event)
	if err != nil {
		log.Printf("[AUDIT DB] failed to save audit event %s: %v", event.Action, err)
	} else {
		log.Printf("[AUDIT DB] saved audit event: %s (%s)", event.Action, event.Outcome)
	}
}
