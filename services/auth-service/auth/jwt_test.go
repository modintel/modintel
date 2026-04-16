package auth

import (
	"testing"
	"time"
)

func TestGenerateAndParseAccessToken(t *testing.T) {
	issuer := TokenIssuer{
		Secret:       []byte("0123456789abcdef0123456789abcdef"),
		AccessExpiry: 15 * time.Minute,
	}

	now := time.Now().UTC()
	raw, _, err := issuer.GenerateAccessToken("u1", "user@example.com", "analyst", now)
	if err != nil {
		t.Fatalf("GenerateAccessToken error: %v", err)
	}

	claims, err := issuer.ParseAccessToken(raw)
	if err != nil {
		t.Fatalf("ParseAccessToken error: %v", err)
	}

	if claims.UserID != "u1" {
		t.Fatalf("expected user id u1, got %s", claims.UserID)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("unexpected email: %s", claims.Email)
	}
	if claims.Role != "analyst" {
		t.Fatalf("unexpected role: %s", claims.Role)
	}
}

func TestGenerateAndParseRefreshToken(t *testing.T) {
	issuer := TokenIssuer{
		Secret:        []byte("0123456789abcdef0123456789abcdef"),
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	now := time.Now().UTC()
	raw, _, err := issuer.GenerateRefreshToken("u1", "jti-123", now)
	if err != nil {
		t.Fatalf("GenerateRefreshToken error: %v", err)
	}

	claims, err := issuer.ParseRefreshToken(raw)
	if err != nil {
		t.Fatalf("ParseRefreshToken error: %v", err)
	}

	if claims.UserID != "u1" {
		t.Fatalf("expected user id u1, got %s", claims.UserID)
	}
	if claims.Type != "refresh" {
		t.Fatalf("unexpected token type: %s", claims.Type)
	}
	if claims.ID != "jti-123" {
		t.Fatalf("unexpected jti: %s", claims.ID)
	}
}
