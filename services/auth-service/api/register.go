package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (h *Handler) register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Password = strings.TrimSpace(req.Password)
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	if req.Email == "" {
		c.JSON(http.StatusBadRequest, errResp("Email is required", "AUTH_400"))
		return
	}
	if !isValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, errResp("Invalid email format", "AUTH_400"))
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	count, err := h.users.CountDocuments(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed checking user count", "AUTH_500"))
		return
	}

	if count > 0 {
		c.JSON(http.StatusForbidden, errResp("Registration closed. Ask an admin to invite you.", "AUTH_403"))
		return
	}

	hash, err := auth.HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()
	insert := bson.M{
		"email":              req.Email,
		"password_hash":      hash,
		"role":               "admin",
		"first_name":         req.FirstName,
		"last_name":          req.LastName,
		"is_active":          true,
		"email_verified":     false,
		"totp_enabled":       false,
		"require_2fa_setup":  true,
		"created_at":         now,
		"updated_at":         now,
	}

	res, err := h.users.InsertOne(ctx, insert)
	if err != nil {
		c.JSON(http.StatusConflict, errResp("User already exists", "AUTH_409"))
		return
	}

	id := res.InsertedID.(primitive.ObjectID)

	var user models.User
	_ = h.users.FindOne(ctx, bson.M{"_id": id}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)

	h.logAuditEvent(auditEvent{
		Action:       "auth_register",
		Outcome:      "success",
		UserID:       id.Hex(),
		UserEmail:    req.Email,
		UserRole:     "admin",
		ResourceType: "user",
		ResourceID:   id.Hex(),
		Details:      map[string]interface{}{"first_admin": true},
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Admin account created. Please set up two-factor authentication.",
		"data": gin.H{
			"id":                id.Hex(),
			"email":             user.Email,
			"role":              user.Role,
			"require_2fa_setup": true,
		},
	})
}

func (h *Handler) authStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	count, err := h.users.CountDocuments(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed checking status", "AUTH_500"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"has_users": count > 0,
	})
}