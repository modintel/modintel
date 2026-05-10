package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/email"
	"modintel/services/auth-service/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ── Request types ─────────────────────────────────────────────────────────────

type SMTPSettingsRequest struct {
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"` // plaintext in request, encrypted at rest
	SMTPFrom     string `json:"smtp_from"`
	SMTPFromName string `json:"smtp_from_name"`
	SMTPUseTLS   bool   `json:"smtp_use_tls"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// loadSMTPConfig reads SMTP settings from MongoDB and returns an email.Config.
// Returns an empty config (not configured) if no settings are stored.
func (h *Handler) loadSMTPConfig(ctx context.Context) (email.Config, error) {
	coll := h.db.DB.Collection("settings")
	var doc models.SMTPSettings
	err := coll.FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&doc)
	if err != nil {
		return email.Config{}, nil // not configured yet — not an error
	}

	// Decrypt password
	password := ""
	if doc.SMTPPassword != "" {
		decrypted, err := auth.DecryptString(doc.SMTPPassword, h.cfg.JWTSecret)
		if err == nil {
			password = decrypted
		}
	}

	return email.Config{
		Host:     doc.SMTPHost,
		Port:     doc.SMTPPort,
		Username: doc.SMTPUsername,
		Password: password,
		From:     doc.SMTPFrom,
		FromName: doc.SMTPFromName,
		UseTLS:   doc.SMTPUseTLS,
	}, nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// getSMTPSettings handles GET /api/v1/settings/smtp (admin only).
func (h *Handler) getSMTPSettings(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	coll := h.db.DB.Collection("settings")
	var doc models.SMTPSettings
	err := coll.FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&doc)
	if err != nil {
		// Not configured yet — return empty defaults
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"smtp_host":      "",
				"smtp_port":      587,
				"smtp_username":  "",
				"smtp_from":      "",
				"smtp_from_name": "",
				"smtp_use_tls":   false,
				"configured":     false,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"smtp_host":      doc.SMTPHost,
			"smtp_port":      doc.SMTPPort,
			"smtp_username":  doc.SMTPUsername,
			"smtp_from":      doc.SMTPFrom,
			"smtp_from_name": doc.SMTPFromName,
			"smtp_use_tls":   doc.SMTPUseTLS,
			"configured":     doc.SMTPHost != "",
			// password intentionally omitted from response
		},
	})
}

// updateSMTPSettings handles PUT /api/v1/settings/smtp (admin only).
func (h *Handler) updateSMTPSettings(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	var req SMTPSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.SMTPHost = strings.TrimSpace(req.SMTPHost)
	req.SMTPFrom = strings.TrimSpace(req.SMTPFrom)
	req.SMTPUsername = strings.TrimSpace(req.SMTPUsername)

	if req.SMTPHost == "" {
		c.JSON(http.StatusBadRequest, errResp("smtp_host is required", "AUTH_400"))
		return
	}
	if req.SMTPPort <= 0 || req.SMTPPort > 65535 {
		c.JSON(http.StatusBadRequest, errResp("smtp_port must be between 1 and 65535", "AUTH_400"))
		return
	}
	if req.SMTPFrom == "" {
		c.JSON(http.StatusBadRequest, errResp("smtp_from is required", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Encrypt password before storing
	encryptedPassword := ""
	if strings.TrimSpace(req.SMTPPassword) != "" {
		var err error
		encryptedPassword, err = auth.EncryptString(req.SMTPPassword, h.cfg.JWTSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, errResp("Failed encrypting SMTP password", "AUTH_500"))
			return
		}
	} else {
		// If no new password provided, keep the existing one
		coll := h.db.DB.Collection("settings")
		var existing models.SMTPSettings
		if err := coll.FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&existing); err == nil {
			encryptedPassword = existing.SMTPPassword
		}
	}

	doc := bson.M{
		"smtp_host":      req.SMTPHost,
		"smtp_port":      req.SMTPPort,
		"smtp_username":  req.SMTPUsername,
		"smtp_password":  encryptedPassword,
		"smtp_from":      req.SMTPFrom,
		"smtp_from_name": req.SMTPFromName,
		"smtp_use_tls":   req.SMTPUseTLS,
		"updated_at":     time.Now().UTC(),
	}

	coll := h.db.DB.Collection("settings")
	_, err := coll.UpdateOne(ctx,
		bson.M{"_id": "smtp"},
		bson.M{"$set": doc},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed saving SMTP settings", "AUTH_500"))
		return
	}

	h.logAuditEvent(auditEvent{
		Action:    "smtp_settings_update",
		Outcome:   "success",
		UserID:    claims.UserID,
		UserEmail: claims.Email,
		UserRole:  claims.Role,
		Details:   map[string]interface{}{"smtp_host": req.SMTPHost, "smtp_from": req.SMTPFrom},
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "SMTP settings saved"})
}

// testSMTPSettings handles POST /api/v1/settings/smtp/test (admin only).
// Sends a test email to the admin's own address.
func (h *Handler) testSMTPSettings(c *gin.Context) {
	claims, ok := getAccessClaims(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	cfg, err := h.loadSMTPConfig(ctx)
	if err != nil || !cfg.IsConfigured() {
		c.JSON(http.StatusBadRequest, errResp("SMTP is not configured. Save settings first.", "AUTH_400"))
		return
	}

	if err := email.SendTestEmail(cfg, claims.Email); err != nil {
		c.JSON(http.StatusBadGateway, errResp("Failed sending test email: "+err.Error(), "AUTH_502"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Test email sent to " + claims.Email,
	})
}
