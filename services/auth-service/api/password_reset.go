package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/email"
	"modintel/services/auth-service/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ── Request types ─────────────────────────────────────────────────────────────

type ResetPasswordRequestBody struct {
	Email string `json:"email"`
}

type ResetPasswordCompleteBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ── requestPasswordReset ──────────────────────────────────────────────────────

// requestPasswordReset handles POST /api/v1/auth/reset-password/request.
// Always returns success to prevent user enumeration.
func (h *Handler) requestPasswordReset(c *gin.Context) {
	var req ResetPasswordRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		// Still return success to prevent enumeration
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "If that email exists, a reset link has been sent."})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Always respond with success regardless of whether the email exists
	defer c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If that email exists, a reset link has been sent.",
	})

	if req.Email == "" || !isValidEmail(req.Email) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Look up user — silently do nothing if not found
	var user models.User
	err := h.users.FindOne(ctx, bson.M{"email": req.Email, "is_active": true}).Decode(&user)
	if err != nil {
		return // user not found — return success anyway
	}

	// Generate a 64-char hex token (32 random bytes)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	resetDoc := models.PasswordReset{
		ID:        primitive.NewObjectID(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: now.Add(time.Hour),
		Used:      false,
		CreatedAt: now,
	}

	resetColl := h.db.DB.Collection("password_resets")
	if _, err := resetColl.InsertOne(ctx, resetDoc); err != nil {
		return
	}

	// Build reset link
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	resetLink := scheme + "://" + c.Request.Host + "/reset-password?token=" + token

	// Load SMTP config and send email (best-effort — don't fail the request)
	smtpCfg, err := h.loadSMTPConfig(ctx)
	if err == nil && smtpCfg.IsConfigured() {
		safeAddr := sanitizeEmailHeader(req.Email)
		safeLink := sanitizeEmailHeader(resetLink)
		go func(cfg email.Config, addr, link string) {
			_ = email.SendResetEmail(cfg, addr, link)
		}(smtpCfg, safeAddr, safeLink)
	}

	h.logAuditEvent(auditEvent{
		Action:    "password_reset_request",
		Outcome:   "success",
		UserID:    user.ID.Hex(),
		UserEmail: user.Email,
		UserRole:  user.Role,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
}

// ── completePasswordReset ─────────────────────────────────────────────────────

// completePasswordReset handles POST /api/v1/auth/reset-password/complete.
func (h *Handler) completePasswordReset(c *gin.Context) {
	var req ResetPasswordCompleteBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Token = strings.TrimSpace(req.Token)
	req.NewPassword = strings.TrimSpace(req.NewPassword)

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, errResp("Token is required", "AUTH_400"))
		return
	}

	// Validate token format to prevent NoSQL injection
	safeToken, ok := sanitizeToken(req.Token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}

	// Validate new password
	if !auth.IsValidPassword(req.NewPassword) {
		c.JSON(http.StatusBadRequest, errResp(
			"Password must be at least 10 characters and contain uppercase, lowercase, number, and special character",
			"AUTH_400",
		))
		return
	}
	if auth.IsCommonPassword(req.NewPassword) {
		c.JSON(http.StatusBadRequest, errResp("Password is too common, choose a stronger password", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resetColl := h.db.DB.Collection("password_resets")

	// Find the reset token — use safeToken (validated hex) not raw user input
	var resetDoc models.PasswordReset
	err := resetColl.FindOne(ctx, bson.M{"token": safeToken}).Decode(&resetDoc)
	if err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid or expired reset token", "AUTH_400"))
		return
	}

	// Validate: not used, not expired
	if resetDoc.Used {
		c.JSON(http.StatusBadRequest, errResp("This reset link has already been used", "AUTH_400"))
		return
	}
	if time.Now().UTC().After(resetDoc.ExpiresAt) {
		c.JSON(http.StatusBadRequest, errResp("This reset link has expired", "AUTH_400"))
		return
	}

	// Hash new password
	hash, err := auth.HashPassword(req.NewPassword, h.cfg.BcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()

	// Update user password
	res, err := h.users.UpdateOne(ctx,
		bson.M{"_id": resetDoc.UserID, "is_active": true},
		bson.M{"$set": bson.M{"password_hash": hash, "updated_at": now}},
	)
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusBadRequest, errResp("User not found or inactive", "AUTH_400"))
		return
	}

	// Mark token as used
	_, _ = resetColl.UpdateOne(ctx,
		bson.M{"_id": resetDoc.ID},
		bson.M{"$set": bson.M{"used": true}},
	)

	// Invalidate all refresh tokens for this user (force re-login)
	_, _ = h.tokens.UpdateMany(ctx,
		bson.M{"user_id": resetDoc.UserID.Hex(), "revoked": false},
		bson.M{"$set": bson.M{"revoked": true, "revoked_at": now}},
	)

	h.logAuditEvent(auditEvent{
		Action:    "password_reset_complete",
		Outcome:   "success",
		UserID:    resetDoc.UserID.Hex(),
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password updated successfully. Please sign in with your new password.",
	})
}

// validateResetToken handles GET /api/v1/auth/reset-password/validate?token=
// Frontend calls this to check if a token is still valid before showing the form.
func (h *Handler) validateResetToken(c *gin.Context) {
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		c.JSON(http.StatusBadRequest, errResp("Token is required", "AUTH_400"))
		return
	}

	// Validate token format to prevent NoSQL injection
	safeToken, ok := sanitizeToken(token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resetColl := h.db.DB.Collection("password_resets")
	var resetDoc models.PasswordReset
	err := resetColl.FindOne(ctx, bson.M{"token": safeToken},
		options.FindOne().SetProjection(bson.M{"used": 1, "expires_at": 1})).Decode(&resetDoc)
	if err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid or expired reset token", "AUTH_400"))
		return
	}

	if resetDoc.Used {
		c.JSON(http.StatusBadRequest, errResp("This reset link has already been used", "AUTH_400"))
		return
	}
	if time.Now().UTC().After(resetDoc.ExpiresAt) {
		c.JSON(http.StatusBadRequest, errResp("This reset link has expired", "AUTH_400"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true, "expires_at": resetDoc.ExpiresAt})
}
