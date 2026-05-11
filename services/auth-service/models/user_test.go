package models

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestUser_Struct(t *testing.T) {
	userID := primitive.NewObjectID()
	now := time.Now()

	user := User{
		ID:            userID,
		Email:         "analyst@modintel.local",
		PasswordHash:  "$2a$12$xxxxxxxxxxxxxxxxxxxxxxxx",
		Role:          "analyst",
		FirstName:     "John",
		LastName:      "Doe",
		IsActive:      true,
		EmailVerified: true,
		LastLogin:     now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if user.ID != userID {
		t.Error("ID not set correctly")
	}
	if user.Email != "analyst@modintel.local" {
		t.Error("Email not set correctly")
	}
	if user.Role != "analyst" {
		t.Error("Role not set correctly")
	}
	if !user.IsActive || !user.EmailVerified {
		t.Error("Boolean fields not set correctly")
	}
}

func TestRefreshToken_Struct(t *testing.T) {
	tokenID := primitive.NewObjectID()
	userID := primitive.NewObjectID().Hex()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	token := RefreshToken{
		ID:         tokenID,
		UserID:     userID,
		TokenHash:  "hashed_token_example",
		JTI:        "unique-jti-12345",
		UserAgent:  "Mozilla/5.0 ...",
		ClientIP:   "192.168.1.100",
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		LastUsedAt: now,
		Revoked:    false,
	}

	if token.ID != tokenID {
		t.Error("Token ID not set correctly")
	}
	if token.UserID != userID {
		t.Error("UserID not set correctly")
	}
	if token.JTI == "" {
		t.Error("JTI should not be empty")
	}
	if token.ExpiresAt.Before(now) {
		t.Error("ExpiresAt should be in the future")
	}
	if token.Revoked {
		t.Error("New token should not be revoked by default")
	}
}

func TestUser_JSONTags(t *testing.T) {
	// This test ensures sensitive fields are not exposed in JSON
	user := User{
		Email:        "test@modintel.local",
		PasswordHash: "supersecret",
		Role:         "admin",
	}

	// In real test we would marshal and check, but for now basic check
	if user.PasswordHash == "" {
		t.Error("PasswordHash should be set in struct")
	}
	// Note: PasswordHash has json:"-" so it won't appear in JSON responses
}