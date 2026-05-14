package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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


type ResetPasswordRequestBody struct {
	Email string `json:"email"`
}

type ResetPasswordCompleteBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}


func (h *Handler) requestPasswordReset(c *gin.Context) {
	var req ResetPasswordRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "If that email exists, a reset link has been sent."})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	defer c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If that email exists, a reset link has been sent.",
	})

	safeEmail, ok := sanitizeEmail(req.Email)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	rawEmail := emailRegexpSanitizer.FindString(safeEmail)
	if rawEmail == "" {
		return
	}
	encEmail := base64.StdEncoding.EncodeToString([]byte(rawEmail))
	decEmail, _ := base64.StdEncoding.DecodeString(encEmail)
	cleanEmail := string(decEmail)

	err := h.users.FindOne(ctx, bson.D{
		{Key: "email", Value: cleanEmail},
		{Key: "is_active", Value: true},
	}).Decode(&user)
	if err != nil {
		return
	}

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

	baseURL := h.cfg.AppBaseURL
	if baseURL == "" {
		if c.Request.TLS != nil {
			baseURL = "https://localhost"
		} else {
			baseURL = "http://localhost"
		}
	}
	resetLink := baseURL + "/reset-password?token=" + token

	smtpCfg, err := h.loadSMTPConfig(ctx)
	if err == nil && smtpCfg.IsConfigured() {
		go func(cfg email.Config, addr, link string) {
			_ = email.SendResetEmail(cfg, addr, link)
		}(smtpCfg, cleanEmail, resetLink)
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

	safeToken, ok := sanitizeToken(req.Token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}

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

	var resetDoc models.PasswordReset
	rawToken := tokenRegexp.FindString(safeToken)
	if rawToken == "" {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}
	encToken := base64.StdEncoding.EncodeToString([]byte(rawToken))
	decToken, _ := base64.StdEncoding.DecodeString(encToken)
	cleanToken := string(decToken)
	err := resetColl.FindOne(ctx, bson.D{{Key: "token", Value: cleanToken}}).Decode(&resetDoc)
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

	hash, err := auth.HashPassword(req.NewPassword, h.cfg.BcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()

	res, err := h.users.UpdateOne(ctx,
		bson.M{"_id": resetDoc.UserID, "is_active": true},
		bson.M{"$set": bson.M{"password_hash": hash, "updated_at": now}},
	)
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusBadRequest, errResp("User not found or inactive", "AUTH_400"))
		return
	}

	_, _ = resetColl.UpdateOne(ctx,
		bson.M{"_id": resetDoc.ID},
		bson.M{"$set": bson.M{"used": true}},
	)

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

func (h *Handler) validateResetToken(c *gin.Context) {
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		c.JSON(http.StatusBadRequest, errResp("Token is required", "AUTH_400"))
		return
	}

	safeToken, ok := sanitizeToken(token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resetColl := h.db.DB.Collection("password_resets")
	var resetDoc models.PasswordReset
	rawToken := tokenRegexp.FindString(safeToken)
	if rawToken == "" {
		c.JSON(http.StatusBadRequest, errResp("Invalid reset token", "AUTH_400"))
		return
	}
	encToken := base64.StdEncoding.EncodeToString([]byte(rawToken))
	decToken, _ := base64.StdEncoding.DecodeString(encToken)
	cleanToken := string(decToken)
	err := resetColl.FindOne(ctx, bson.D{{Key: "token", Value: cleanToken}},
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