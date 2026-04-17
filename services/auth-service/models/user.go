package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email         string             `bson:"email" json:"email"`
	PasswordHash  string             `bson:"password_hash" json:"-"`
	Role          string             `bson:"role" json:"role"`
	FirstName     string             `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName      string             `bson:"last_name,omitempty" json:"last_name,omitempty"`
	IsActive      bool               `bson:"is_active" json:"is_active"`
	EmailVerified bool               `bson:"email_verified" json:"email_verified"`
	LastLogin     time.Time          `bson:"last_login,omitempty" json:"last_login,omitempty"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

type RefreshToken struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID     string             `bson:"user_id" json:"user_id"`
	TokenHash  string             `bson:"token_hash" json:"-"`
	JTI        string             `bson:"jti" json:"jti"`
	UserAgent  string             `bson:"user_agent,omitempty" json:"user_agent,omitempty"`
	ClientIP   string             `bson:"client_ip,omitempty" json:"client_ip,omitempty"`
	ExpiresAt  time.Time          `bson:"expires_at" json:"expires_at"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	LastUsedAt time.Time          `bson:"last_used_at,omitempty" json:"last_used_at,omitempty"`
	Revoked    bool               `bson:"revoked" json:"revoked"`
	RevokedAt  time.Time          `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
}
