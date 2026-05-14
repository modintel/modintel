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


type SendInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type AcceptInviteRequest struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

const inviteRateLimitPerHour = 10

func (h *Handler) checkInviteRateLimit(ctx context.Context, adminEmail string) (bool, error) {
	coll := h.db.DB.Collection("invite_logs")
	cutoff := time.Now().UTC().Add(-time.Hour)
	count, err := coll.CountDocuments(ctx, bson.M{
		"invited_by": adminEmail,
		"created_at": bson.M{"$gte": cutoff},
	})
	if err != nil {
		return false, err
	}
	return count >= inviteRateLimitPerHour, nil
}

func (h *Handler) recordInviteLog(ctx context.Context, adminEmail, inviteeEmail string) {
	coll := h.db.DB.Collection("invite_logs")
	_, _ = coll.InsertOne(ctx, bson.M{
		"invited_by":    adminEmail,
		"invitee_email": inviteeEmail,
		"created_at":    time.Now().UTC(),
	})
}


func (h *Handler) sendInvite(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	var req SendInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if req.Role == "" {
		req.Role = "analyst"
	}

	safeEmail, ok := sanitizeEmail(req.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid email format", "AUTH_400"))
		return
	}

	if req.Role == "admin" {
		c.JSON(http.StatusBadRequest, errResp("Admin role cannot be assigned via invite", "AUTH_400"))
		return
	}
	if !isValidRole(req.Role) {
		c.JSON(http.StatusBadRequest, errResp("Role must be 'analyst' or 'viewer'", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	exceeded, err := h.checkInviteRateLimit(ctx, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed checking rate limit", "AUTH_500"))
		return
	}
	if exceeded {
		c.JSON(http.StatusTooManyRequests, errResp("Rate limit exceeded. You can send at most 10 invites per hour.", "AUTH_429"))
		return
	}

	rawEmail := emailRegexpSanitizer.FindString(safeEmail)
	if rawEmail == "" {
		c.JSON(http.StatusBadRequest, errResp("Invalid email format", "AUTH_400"))
		return
	}
	encEmail := base64.StdEncoding.EncodeToString([]byte(rawEmail))
	decEmail, _ := base64.StdEncoding.DecodeString(encEmail)
	cleanEmail := string(decEmail)

	existingCount, _ := h.users.CountDocuments(ctx, bson.D{{Key: "email", Value: cleanEmail}})
	if existingCount > 0 {
		c.JSON(http.StatusConflict, errResp("A user with this email already exists", "AUTH_409"))
		return
	}

	invColl := h.db.DB.Collection("invitations")
	pendingCount, _ := invColl.CountDocuments(ctx, bson.D{
		{Key: "email", Value: cleanEmail},
		{Key: "status", Value: models.InvitationStatusPending},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: time.Now().UTC()}}},
	})
	if pendingCount > 0 {
		c.JSON(http.StatusConflict, errResp("A pending invitation already exists for this email", "AUTH_409"))
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating invite token", "AUTH_500"))
		return
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	invitation := models.Invitation{
		ID:        primitive.NewObjectID(),
		Email:     safeEmail,
		Role:      req.Role,
		Token:     token,
		InvitedBy: claims.Email,
		Status:    models.InvitationStatusPending,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if _, err := invColl.InsertOne(ctx, invitation); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing invitation", "AUTH_500"))
		return
	}

	h.recordInviteLog(ctx, claims.Email, safeEmail)

	h.logAuditEvent(auditEvent{
		Action:       "user_invite",
		Outcome:      "success",
		UserID:       claims.UserID,
		UserEmail:    claims.Email,
		UserRole:     claims.Role,
		ResourceType: "invitation",
		ResourceID:   invitation.ID.Hex(),
		Details: map[string]interface{}{
			"invitee_email": safeEmail,
			"invitee_role":  req.Role,
		},
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	baseURL := h.cfg.AppBaseURL
	if baseURL == "" {
		if c.Request.TLS != nil {
			baseURL = "https://localhost"
		} else {
			baseURL = "http://localhost"
		}
	}
	acceptLink := baseURL + "/accept-invite?token=" + token

	smtpCfg, smtpErr := h.loadSMTPConfig(ctx)
	if smtpErr == nil && smtpCfg.IsConfigured() {
		safeInviter := sanitizeEmailHeader(claims.Email)
		safeRole := sanitizeEmailHeader(req.Role)
		go func(cfg email.Config, to, inviter, role, link string) {
			_ = email.SendInviteEmail(cfg, to, inviter, role, link)
		}(smtpCfg, cleanEmail, safeInviter, safeRole, acceptLink)
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Invitation sent to " + safeEmail + ". They have 24 hours to accept.",
		"data": gin.H{
			"email":       safeEmail,
			"role":        req.Role,
			"expires_at":  invitation.ExpiresAt,
			"accept_link": acceptLink,
		},
	})
}


func (h *Handler) acceptInvite(c *gin.Context) {
	var req AcceptInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Token = strings.TrimSpace(req.Token)
	req.Password = strings.TrimSpace(req.Password)
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, errResp("Token is required", "AUTH_400"))
		return
	}

	safeToken, ok := sanitizeToken(req.Token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid invitation token", "AUTH_400"))
		return
	}

	if !auth.IsValidPassword(req.Password) {
		c.JSON(http.StatusBadRequest, errResp(
			"Password must be at least 10 characters and contain uppercase, lowercase, number, and special character",
			"AUTH_400",
		))
		return
	}
	if auth.IsCommonPassword(req.Password) {
		c.JSON(http.StatusBadRequest, errResp("Password is too common, choose a stronger password", "AUTH_400"))
		return
	}

	if len(req.FirstName) < 1 {
		c.JSON(http.StatusBadRequest, errResp("First name is required", "AUTH_400"))
		return
	}
	if len(req.LastName) < 1 {
		c.JSON(http.StatusBadRequest, errResp("Last name is required", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	rawToken := tokenRegexp.FindString(safeToken)
	if rawToken == "" {
		c.JSON(http.StatusBadRequest, errResp("Invalid invitation token", "AUTH_400"))
		return
	}
	encToken := base64.StdEncoding.EncodeToString([]byte(rawToken))
	decToken, _ := base64.StdEncoding.DecodeString(encToken)
	cleanToken := string(decToken)

	invColl := h.db.DB.Collection("invitations")

	var claimed struct {
		ID        primitive.ObjectID `bson:"_id"`
		Email     string             `bson:"email"`
		Role      string             `bson:"role"`
		InvitedBy string             `bson:"invited_by"`
	}
	err := invColl.FindOneAndUpdate(ctx,
		bson.D{
			{Key: "token", Value: cleanToken},
			{Key: "status", Value: models.InvitationStatusPending},
			{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: time.Now().UTC()}}},
		},
		bson.M{"$set": bson.M{"status": models.InvitationStatusAccepted}},
		options.FindOneAndUpdate().SetProjection(bson.M{"email": 1, "role": 1, "invited_by": 1}),
	).Decode(&claimed)
	if err != nil {
		var expired struct {
			ExpiresAt time.Time `bson:"expires_at"`
		}
		if findErr := invColl.FindOne(ctx,
			bson.D{{Key: "token", Value: cleanToken}},
			options.FindOne().SetProjection(bson.M{"expires_at": 1}),
		).Decode(&expired); findErr == nil && time.Now().UTC().After(expired.ExpiresAt) {
			c.JSON(http.StatusBadRequest, errResp("This invitation has expired", "AUTH_400"))
			return
		}
		c.JSON(http.StatusBadRequest, errResp("Invalid or already used invitation", "AUTH_400"))
		return
	}

	hash, err := auth.HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		_, _ = invColl.UpdateOne(ctx, bson.M{"_id": claimed.ID},
			bson.M{"$set": bson.M{"status": models.InvitationStatusPending}})
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()
	insert := bson.M{
		"email":          claimed.Email,
		"password_hash":  hash,
		"role":           claimed.Role,
		"first_name":     req.FirstName,
		"last_name":      req.LastName,
		"is_active":      true,
		"email_verified": true,
		"totp_enabled":   false,
		"created_at":     now,
		"updated_at":     now,
	}

	res, err := h.users.InsertOne(ctx, insert)
	if err != nil {
		_, _ = invColl.UpdateOne(ctx, bson.M{"_id": claimed.ID},
			bson.M{"$set": bson.M{"status": models.InvitationStatusPending}})
		c.JSON(http.StatusConflict, errResp("A user with this email already exists", "AUTH_409"))
		return
	}

	userID := res.InsertedID.(primitive.ObjectID)

	var user models.User
	_ = h.users.FindOne(ctx, bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)

	h.logAuditEvent(auditEvent{
		Action:       "invite_accept",
		Outcome:      "success",
		UserID:       userID.Hex(),
		UserEmail:    claimed.Email,
		UserRole:     claimed.Role,
		ResourceType: "invitation",
		ResourceID:   claimed.ID.Hex(),
		Details: map[string]interface{}{
			"invited_by": claimed.InvitedBy,
		},
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Account created successfully. You can now sign in.",
		"data": gin.H{
			"id":    userID.Hex(),
			"email": claimed.Email,
			"role":  claimed.Role,
		},
	})
}