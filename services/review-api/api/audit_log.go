package api

import (
	"context"
	"log"
	"time"

	"modintel/services/review-api/db"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuditLog struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"_id"`
	Timestamp    time.Time              `bson:"timestamp" json:"timestamp"`
	UserID       string                 `bson:"user_id" json:"user_id"`
	UserEmail    string                 `bson:"user_email" json:"user_email"`
	UserRole     string                 `bson:"user_role" json:"user_role"`
	Action       string                 `bson:"action" json:"action"`
	ResourceType string                 `bson:"resource_type" json:"resource_type"`
	ResourceID   string                 `bson:"resource_id" json:"resource_id"`
	Details      map[string]interface{} `bson:"details" json:"details"`
	IPAddress    string                 `bson:"ip_address" json:"ip_address"`
	UserAgent    string                 `bson:"user_agent" json:"user_agent"`
	Outcome      string                 `bson:"outcome" json:"outcome"`
	ErrorMessage string                 `bson:"error_message,omitempty" json:"error_message,omitempty"`
}

func LogAction(c *gin.Context, action string, resourceType string, resourceID string, details map[string]interface{}, outcome string, errMsg string) {
	claimsAny, _ := c.Get("access_claims")
	var userID, userEmail, userRole = "", "", ""
	if claims, ok := claimsAny.(*AccessClaims); ok {
		userID = claims.UserID
		userEmail = claims.Email
		userRole = claims.Role
	} else if roleClaim, ok := claimsAny.(map[string]interface{}); ok {
		// Fallback for generic claims if needed
		if id, ok := roleClaim["user_id"].(string); ok {
			userID = id
		}
		if e, ok := roleClaim["email"].(string); ok {
			userEmail = e
		}
		if r, ok := roleClaim["role"].(string); ok {
			userRole = r
		}
	}

	log := AuditLog{
		UserID:       userID,
		UserEmail:    userEmail,
		UserRole:     userRole,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Outcome:      outcome,
		ErrorMessage: errMsg,
	}

	LogAudit(log)
}

func LogAudit(log AuditLog) {
	collection := db.GetCollection("modintel", "audit_logs")
	ctx := context.Background()
	log.Timestamp = time.Now().UTC()
	_, _ = collection.InsertOne(ctx, log)
}

func GetAuditLogs(filter bson.M, limit int64, sort bson.D) ([]AuditLog, error) {
	collection := db.GetCollection("modintel", "audit_logs")
	ctx := context.Background()

	opts := options.Find().SetSort(sort).SetLimit(limit)
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func InitAuditIndexes() {
	collection := db.GetCollection("modintel", "audit_logs")
	ctx := context.Background()

	indexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "action", Value: 1}}},
		{Keys: bson.D{{Key: "resource_type", Value: 1}}},
		{Keys: bson.D{{Key: "timestamp", Value: -1}, {Key: "user_id", Value: 1}}},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		log.Printf("Failed to create audit log indexes: %v", err)
	}
}
