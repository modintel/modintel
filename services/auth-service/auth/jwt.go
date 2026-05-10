package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenIssuer struct {
	Secret        []byte
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

type AccessClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID string `json:"user_id"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}

// TwoFactorClaims is a short-lived intermediate token issued after password
// verification when 2FA is required. It cannot be used as an access token.
type TwoFactorClaims struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	Purpose string `json:"purpose"` // always "2fa_login"
	Type    string `json:"type"`    // always "intermediate"
	jwt.RegisteredClaims
}

func (t TokenIssuer) GenerateAccessToken(userID, email, role string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(t.AccessExpiry)
	claims := AccessClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Subject:   userID,
		},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.Secret)
	return raw, expiresAt, err
}

func (t TokenIssuer) GenerateRefreshToken(userID, jti string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(t.RefreshExpiry)
	claims := RefreshClaims{
		UserID: userID,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Subject:   userID,
		},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.Secret)
	return raw, expiresAt, err
}

func (t TokenIssuer) ParseAccessToken(raw string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return t.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

func (t TokenIssuer) ParseRefreshToken(raw string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return t.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}
	if claims.Type != "refresh" {
		return nil, errors.New("wrong token type")
	}
	return claims, nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateTwoFactorToken issues a 5-minute intermediate token after password
// verification when 2FA is required.
func (t TokenIssuer) GenerateTwoFactorToken(userID, email, role string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(5 * time.Minute)
	claims := TwoFactorClaims{
		UserID:  userID,
		Email:   email,
		Role:    role,
		Purpose: "2fa_login",
		Type:    "intermediate",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Subject:   userID,
		},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.Secret)
	return raw, expiresAt, err
}

// ParseTwoFactorToken validates and parses an intermediate 2FA token.
func (t TokenIssuer) ParseTwoFactorToken(raw string) (*TwoFactorClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &TwoFactorClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return t.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*TwoFactorClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid 2fa token")
	}
	if claims.Type != "intermediate" || claims.Purpose != "2fa_login" {
		return nil, errors.New("wrong token type")
	}
	return claims, nil
}
