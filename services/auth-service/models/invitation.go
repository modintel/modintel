package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Invitation struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"  json:"id"`
	Email     string             `bson:"email"          json:"email"`
	Role      string             `bson:"role"           json:"role"`
	Token     string             `bson:"token"          json:"-"`
	InvitedBy string             `bson:"invited_by"     json:"invited_by"`
	Status    string             `bson:"status"         json:"status"`
	ExpiresAt time.Time          `bson:"expires_at"     json:"expires_at"`
	CreatedAt time.Time          `bson:"created_at"     json:"created_at"`
}

const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusExpired  = "expired"
)