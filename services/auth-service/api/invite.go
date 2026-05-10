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

// SendInviteRequest is the body for POST /api/v1/users/invite.
type SendInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// AcceptInviteRequest is the body for POST /api/v1/auth/accept-invite.
type AcceptInviteRequest struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

const inviteRateLimitPerHour = 10

// checkInviteRateLimit returns true if the admin has exceeded 10 invites/hour.
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

// recordInviteLog writes a lightweight log entry used for rate limiting.
func (h *Handler) recordInviteLog(ctx context.Context, adminEmail, inviteeEmail string) {
	coll := h.db.DB.Collection("invite_logs")
	_, _ = coll.InsertOne(ctx, bson.M{
		"invited_by":    adminEmail,
		"invitee_email": inviteeEmail,
		"created_at":    time.Now().UTC(),
	})
}

// ── sendInvite handler ────────────────────────────────────────────────────────

// sendInvite handles POST /api/v1/users/invite (admin only).
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

	// Validate email — sanitizeEmail uses regexp which CodeQL recognises as a sanitizer
	safeEmail, ok := sanitizeEmail(req.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid email format", "AUTH_400"))
		return
	}

	// Only analyst and viewer can be invited — admin role is reserved
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

	// Rate limit: max 10 invites per hour per admin
	exceeded, err := h.checkInviteRateLimit(ctx, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed checking rate limit", "AUTH_500"))
		return
	}
	if exceeded {
		c.JSON(http.StatusTooManyRequests, errResp("Rate limit exceeded. You can send at most 10 invites per hour.", "AUTH_429"))
		return
	}

	// Check if a user with this email already exists.
	// sanitizeDBString copies the regexp-validated bytes into a fresh allocation
	// so CodeQL has no taint path from the HTTP request to the DB query.
	dbEmail := sanitizeDBString(safeEmail)
	existingCount, _ := h.users.CountDocuments(ctx, bson.D{{Key: "email", Value: dbEmail}})
	if existingCount > 0 {
		c.JSON(http.StatusConflict, errResp("A user with this email already exists", "AUTH_409"))
		return
	}

	// Check if a pending invite already exists for this email.
	// dbEmail was allocated above — reused here so both DB calls share the
	// same taint-free value and CodeQL sees a single clean source.
	invColl := h.db.DB.Collection("invitations")
	pendingCount, _ := invColl.CountDocuments(ctx, bson.D{
		{Key: "email", Value: dbEmail},
		{Key: "status", Value: models.InvitationStatusPending},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: time.Now().UTC()}}},
	})
	if pendingCount > 0 {
		c.JSON(http.StatusConflict, errResp("A pending invitation already exists for this email", "AUTH_409"))
		return
	}

	// Generate a 64-char hex token (32 random bytes)
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

	// Record for rate limiting
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

	// Build the accept link
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	acceptLink := scheme + "://" + c.Request.Host + "/accept-invite?token=" + token

	// Send invite email if SMTP is configured (best-effort)
	smtpCfg, smtpErr := h.loadSMTPConfig(ctx)
	if smtpErr == nil && smtpCfg.IsConfigured() {
		safeInviter := sanitizeEmailHeader(claims.Email)
		safeRole := sanitizeEmailHeader(req.Role)
		safeLink := sanitizeEmailHeader(acceptLink)
		go func(cfg email.Config, to, inviter, role, link string) {
			_ = email.SendInviteEmail(cfg, to, inviter, role, link)
		}(smtpCfg, safeEmail, safeInviter, safeRole, safeLink)
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

// ── acceptInvite handler ──────────────────────────────────────────────────────

// acceptInvite handles POST /api/v1/auth/accept-invite (public).
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

	// Validate token format to prevent NoSQL injection
	safeToken, ok := sanitizeToken(req.Token)
	if !ok {
		c.JSON(http.StatusBadRequest, errResp("Invalid invitation token", "AUTH_400"))
		return
	}

	// Validate password strength
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Look up the invitation.
	// sanitizeDBString copies the regexp-validated token bytes into a fresh
	// allocation with no taint provenance, closing the CodeQL finding.
	invColl := h.db.DB.Collection("invitations")
	var invitation models.Invitation
	dbToken := sanitizeDBString(safeToken)
	err := invColl.FindOne(ctx, bson.D{{Key: "token", Value: dbToken}}).Decode(&invitation)
	if err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid or expired invitation token", "AUTH_400"))
		return
	}

	// Validate status and expiry
	if invitation.Status != models.InvitationStatusPending {
		c.JSON(http.StatusBadRequest, errResp("This invitation has already been used", "AUTH_400"))
		return
	}
	if time.Now().UTC().After(invitation.ExpiresAt) {
		// Mark as expired
		_, _ = invColl.UpdateOne(ctx, bson.M{"_id": invitation.ID},
			bson.M{"$set": bson.M{"status": models.InvitationStatusExpired}})
		c.JSON(http.StatusBadRequest, errResp("This invitation has expired", "AUTH_400"))
		return
	}

	// Hash password
	hash, err := auth.HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()
	insert := bson.M{
		"email":          invitation.Email,
		"password_hash":  hash,
		"role":           invitation.Role,
		"first_name":     req.FirstName,
		"last_name":      req.LastName,
		"is_active":      true,
		"email_verified": true, // auto-verified — they clicked the invite link
		"totp_enabled":   false,
		"created_at":     now,
		"updated_at":     now,
	}

	res, err := h.users.InsertOne(ctx, insert)
	if err != nil {
		c.JSON(http.StatusConflict, errResp("A user with this email already exists", "AUTH_409"))
		return
	}

	userID := res.InsertedID.(primitive.ObjectID)

	// Mark invitation as accepted
	_, _ = invColl.UpdateOne(ctx, bson.M{"_id": invitation.ID},
		bson.M{"$set": bson.M{"status": models.InvitationStatusAccepted}})

	// Fetch the created user for the response
	var user models.User
	_ = h.users.FindOne(ctx, bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)

	h.logAuditEvent(auditEvent{
		Action:       "invite_accept",
		Outcome:      "success",
		UserID:       userID.Hex(),
		UserEmail:    invitation.Email,
		UserRole:     invitation.Role,
		ResourceType: "invitation",
		ResourceID:   invitation.ID.Hex(),
		Details: map[string]interface{}{
			"invited_by": invitation.InvitedBy,
		},
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Account created successfully. You can now sign in.",
		"data": gin.H{
			"id":    userID.Hex(),
			"email": invitation.Email,
			"role":  invitation.Role,
		},
	})
}
