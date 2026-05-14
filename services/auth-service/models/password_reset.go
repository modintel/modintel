package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type PasswordReset struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id"       json:"user_id"`
	Token     string             `bson:"token"         json:"-"`
	ExpiresAt time.Time          `bson:"expires_at"    json:"expires_at"`
	Used      bool               `bson:"used"          json:"used"`
	CreatedAt time.Time          `bson:"created_at"    json:"created_at"`
}