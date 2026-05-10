package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"net/http"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ── Request types ─────────────────────────────────────────────────────────────

type TwoFAVerifyRequest struct {
	Code string `json:"code"`
}

type TwoFALoginRequest struct {
	TwoFAToken string `json:"2fa_token"`
	Code       string `json:"code"`
}

type TwoFARecoverRequest struct {
	TwoFAToken   string `json:"2fa_token"`
	RecoveryCode string `json:"recovery_code"`
}

// ── 2FA Status ────────────────────────────────────────────────────────────────

// twoFAStatus handles GET /api/v1/auth/2fa/status
func (h *Handler) twoFAStatus(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID},
		options.FindOne().SetProjection(bson.M{"totp_enabled": 1, "totp_verified_at": 1})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"totp_enabled":    user.TOTPEnabled,
		"totp_verified_at": user.TOTPVerifiedAt,
	})
}

// ── 2FA Setup ─────────────────────────────────────────────────────────────────

// twoFASetup handles POST /api/v1/auth/2fa/setup
// Generates a TOTP secret, stores it (not yet enabled), returns QR code.
func (h *Handler) twoFASetup(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Generate TOTP secret
	secret, otpauthURL, err := auth.GenerateTOTPSecret(claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating 2FA secret", "AUTH_500"))
		return
	}

	// Generate QR code as base64 PNG
	qrBase64, err := generateQRBase64(otpauthURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating QR code", "AUTH_500"))
		return
	}

	// Store secret in DB (not yet enabled — user must verify first)
	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	_, err = h.users.UpdateOne(ctx,
		bson.M{"_id": userOID},
		bson.M{"$set": bson.M{
			"totp_secret":  secret,
			"totp_enabled": false,
			"updated_at":   time.Now().UTC(),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing 2FA secret", "AUTH_500"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"qr_code":    "data:image/png;base64," + qrBase64,
		"manual_key": secret,
		"otpauth_url": otpauthURL,
	})
}

// ── 2FA Verify (complete setup) ───────────────────────────────────────────────

// twoFAVerify handles POST /api/v1/auth/2fa/verify
// User submits a code to confirm setup and enable 2FA.
func (h *Handler) twoFAVerify(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	var req TwoFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Code = strings.TrimSpace(req.Code)
	if len(req.Code) != 6 {
		c.JSON(http.StatusBadRequest, errResp("Code must be 6 digits", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	// Fetch user with TOTP secret
	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID},
		options.FindOne().SetProjection(bson.M{"totp_secret": 1, "totp_enabled": 1})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	if user.TOTPSecret == "" {
		c.JSON(http.StatusBadRequest, errResp("2FA setup not initiated. Call /2fa/setup first.", "AUTH_400"))
		return
	}

	// Validate the code
	if !auth.ValidateTOTPCode(user.TOTPSecret, req.Code) {
		c.JSON(http.StatusUnauthorized, errResp("Invalid 2FA code", "AUTH_401"))
		return
	}

	// Generate recovery codes
	plainCodes, hashedCodes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating recovery codes", "AUTH_500"))
		return
	}

	now := time.Now().UTC()
	_, err = h.users.UpdateOne(ctx,
		bson.M{"_id": userOID},
		bson.M{"$set": bson.M{
			"totp_enabled":        true,
			"totp_verified_at":    now,
			"totp_recovery_codes": hashedCodes,
			"updated_at":          now,
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed enabling 2FA", "AUTH_500"))
		return
	}

	h.logAuditEvent(auditEvent{
		Action:    "2fa_enabled",
		Outcome:   "success",
		UserID:    claims.UserID,
		UserEmail: claims.Email,
		UserRole:  claims.Role,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"message":        "2FA enabled successfully. Save your recovery codes — they will not be shown again.",
		"recovery_codes": plainCodes,
	})
}

// ── 2FA Login (submit code after password) ────────────────────────────────────

// twoFALogin handles POST /api/v1/auth/2fa/login
// Accepts the intermediate 2FA token + TOTP code, issues full tokens.
func (h *Handler) twoFALogin(c *gin.Context) {
	var req TwoFALoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.TwoFAToken = strings.TrimSpace(req.TwoFAToken)
	req.Code = strings.TrimSpace(req.Code)

	if req.TwoFAToken == "" || req.Code == "" {
		c.JSON(http.StatusBadRequest, errResp("2fa_token and code are required", "AUTH_400"))
		return
	}

	// Validate the intermediate token
	tfaClaims, err := h.issuer.ParseTwoFactorToken(req.TwoFAToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Invalid or expired 2FA token", "AUTH_401"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(tfaClaims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID, "is_active": true},
		options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found or inactive", "AUTH_003"))
		return
	}

	// Validate TOTP code
	if !auth.ValidateTOTPCode(user.TOTPSecret, req.Code) {
		h.logAuditEvent(auditEvent{
			Action:       "2fa_login",
			Outcome:      "failure",
			UserID:       user.ID.Hex(),
			UserEmail:    user.Email,
			UserRole:     user.Role,
			ErrorMessage: "invalid 2fa code",
			ClientIP:     c.ClientIP(),
			UserAgent:    c.Request.UserAgent(),
		})
		c.JSON(http.StatusUnauthorized, errResp("Invalid 2FA code", "AUTH_401"))
		return
	}

	// Issue full tokens
	now := time.Now().UTC()
	userIDHex := user.ID.Hex()

	accessToken, accessExp, err := h.issuer.GenerateAccessToken(userIDHex, user.Email, user.Role, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating token", "AUTH_500"))
		return
	}

	jti, err := randomID(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating token id", "AUTH_500"))
		return
	}

	refreshToken, refreshExp, err := h.issuer.GenerateRefreshToken(userIDHex, jti, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating refresh token", "AUTH_500"))
		return
	}

	tokenDoc := models.RefreshToken{
		UserID:     userIDHex,
		TokenHash:  auth.HashToken(refreshToken),
		JTI:        jti,
		UserAgent:  c.GetHeader("User-Agent"),
		ClientIP:   c.ClientIP(),
		ExpiresAt:  refreshExp,
		CreatedAt:  now,
		LastUsedAt: now,
		Revoked:    false,
	}

	if _, err := h.tokens.InsertOne(ctx, tokenDoc); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing refresh token", "AUTH_500"))
		return
	}

	_, _ = h.users.UpdateOne(ctx, bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{"last_login": now, "updated_at": now}})

	h.setAccessTokenCookie(c, accessToken, time.Until(accessExp))
	h.setRefreshTokenCookie(c, refreshToken, time.Until(refreshExp))

	h.logAuditEvent(auditEvent{
		Action:    "2fa_login",
		Outcome:   "success",
		UserID:    userIDHex,
		UserEmail: user.Email,
		UserRole:  user.Role,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"expires_in": int(time.Until(accessExp).Seconds()),
			"user": gin.H{
				"id":         userIDHex,
				"email":      user.Email,
				"role":       user.Role,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
			},
		},
	})
}

// ── 2FA Recovery ──────────────────────────────────────────────────────────────

// twoFARecover handles POST /api/v1/auth/2fa/recover
// Allows login using a one-time recovery code instead of TOTP.
func (h *Handler) twoFARecover(c *gin.Context) {
	var req TwoFARecoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.TwoFAToken = strings.TrimSpace(req.TwoFAToken)
	req.RecoveryCode = strings.ToUpper(strings.TrimSpace(req.RecoveryCode))

	if req.TwoFAToken == "" || req.RecoveryCode == "" {
		c.JSON(http.StatusBadRequest, errResp("2fa_token and recovery_code are required", "AUTH_400"))
		return
	}

	tfaClaims, err := h.issuer.ParseTwoFactorToken(req.TwoFAToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Invalid or expired 2FA token", "AUTH_401"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(tfaClaims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID, "is_active": true},
		options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found or inactive", "AUTH_003"))
		return
	}

	// Match recovery code
	idx := auth.MatchRecoveryCode(req.RecoveryCode, user.TOTPRecoveryCodes)
	if idx < 0 {
		c.JSON(http.StatusUnauthorized, errResp("Invalid recovery code", "AUTH_401"))
		return
	}

	// Remove used recovery code
	newCodes := append(user.TOTPRecoveryCodes[:idx], user.TOTPRecoveryCodes[idx+1:]...)
	now := time.Now().UTC()
	_, _ = h.users.UpdateOne(ctx, bson.M{"_id": userOID},
		bson.M{"$set": bson.M{"totp_recovery_codes": newCodes, "updated_at": now}})

	// Issue full tokens
	userIDHex := user.ID.Hex()
	accessToken, accessExp, err := h.issuer.GenerateAccessToken(userIDHex, user.Email, user.Role, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating token", "AUTH_500"))
		return
	}

	jti, err := randomID(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating token id", "AUTH_500"))
		return
	}

	refreshToken, refreshExp, err := h.issuer.GenerateRefreshToken(userIDHex, jti, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating refresh token", "AUTH_500"))
		return
	}

	tokenDoc := models.RefreshToken{
		UserID:     userIDHex,
		TokenHash:  auth.HashToken(refreshToken),
		JTI:        jti,
		UserAgent:  c.GetHeader("User-Agent"),
		ClientIP:   c.ClientIP(),
		ExpiresAt:  refreshExp,
		CreatedAt:  now,
		LastUsedAt: now,
		Revoked:    false,
	}
	if _, err := h.tokens.InsertOne(ctx, tokenDoc); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing refresh token", "AUTH_500"))
		return
	}

	_, _ = h.users.UpdateOne(ctx, bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{"last_login": now, "updated_at": now}})

	h.setAccessTokenCookie(c, accessToken, time.Until(accessExp))
	h.setRefreshTokenCookie(c, refreshToken, time.Until(refreshExp))

	h.logAuditEvent(auditEvent{
		Action:    "2fa_recover",
		Outcome:   "success",
		UserID:    userIDHex,
		UserEmail: user.Email,
		UserRole:  user.Role,
		Details:   map[string]interface{}{"codes_remaining": len(newCodes)},
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logged in via recovery code.",
		"data": gin.H{
			"expires_in":      int(time.Until(accessExp).Seconds()),
			"codes_remaining": len(newCodes),
			"user": gin.H{
				"id":    userIDHex,
				"email": user.Email,
				"role":  user.Role,
			},
		},
	})
}

// ── 2FA Disable ───────────────────────────────────────────────────────────────

// twoFADisable handles POST /api/v1/auth/2fa/disable
// Requires password re-entry. Admin only.
func (h *Handler) twoFADisable(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		c.JSON(http.StatusBadRequest, errResp("Password is required to disable 2FA", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID, "is_active": true}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	if err := auth.ComparePassword(user.PasswordHash, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Incorrect password", "AUTH_401"))
		return
	}

	now := time.Now().UTC()
	_, _ = h.users.UpdateOne(ctx, bson.M{"_id": userOID},
		bson.M{"$set": bson.M{
			"totp_enabled":        false,
			"totp_secret":         "",
			"totp_recovery_codes": []string{},
			"totp_verified_at":    nil,
			"updated_at":          now,
		}},
	)

	h.logAuditEvent(auditEvent{
		Action:    "2fa_disabled",
		Outcome:   "success",
		UserID:    claims.UserID,
		UserEmail: claims.Email,
		UserRole:  claims.Role,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "2FA has been disabled."})
}

// ── QR code helper ────────────────────────────────────────────────────────────

func generateQRBase64(otpauthURL string) (string, error) {
	// Parse the otpauth URL back into a key to get the QR image
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		return "", err
	}

	img, err := key.Image(200, 200)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
