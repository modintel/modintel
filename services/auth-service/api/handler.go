package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/config"
	"modintel/services/auth-service/db"
	"modintel/services/auth-service/middleware"
	"modintel/services/auth-service/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Handler struct {
	cfg    config.Config
	db     *db.Database
	issuer auth.TokenIssuer
	users  *mongo.Collection
	tokens *mongo.Collection
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type CreateUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type UpdateUserRequest struct {
	Role      string `json:"role"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsActive  *bool  `json:"is_active"`
}

var emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func SetupRouter(cfg config.Config, database *db.Database) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.AuditLog())

	h := &Handler{
		cfg: cfg,
		db:  database,
		issuer: auth.TokenIssuer{
			Secret:        []byte(cfg.JWTSecret),
			AccessExpiry:  cfg.JWTAccessExpiry,
			RefreshExpiry: cfg.JWTRefreshExpiry,
		},
		users:  database.DB.Collection("users"),
		tokens: database.DB.Collection("refresh_tokens"),
	}

	r.GET("/health", h.health)

	v1 := r.Group("/api/v1")
	authGroup := v1.Group("/auth")
	loginLimiter := middleware.NewAuthRateLimiter(cfg.RateLimitAuthPerMin)
	{
		authGroup.POST("/login", loginLimiter.Middleware(), h.login)
		authGroup.POST("/refresh", h.refresh)
		authGroup.POST("/logout", h.logout)
	}

	v1.GET("/auth/me", h.authMiddleware(), h.me)

	users := v1.Group("/users", h.authMiddleware())
	{
		users.GET("", h.requireRoles("admin"), h.listUsers)
		users.GET(":id", h.requireRoles("admin"), h.getUser)
		users.POST("", h.requireRoles("admin"), h.createUser)
		users.PUT(":id", h.requireRoles("admin"), h.updateUser)
		users.DELETE(":id", h.requireRoles("admin"), h.deactivateUser)
	}

	return r
}

func (h *Handler) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"service": "auth-service", "status": "ok"})
}

func (h *Handler) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, errResp("Email and password are required", "AUTH_400"))
		return
	}
	if !isValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, errResp("Invalid email format", "AUTH_400"))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	err := h.users.FindOne(ctx, bson.M{"email": req.Email, "is_active": true}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusUnauthorized, errResp("Invalid credentials", "AUTH_001"))
			return
		}
		c.JSON(http.StatusInternalServerError, errResp("Authentication service unavailable", "AUTH_500"))
		return
	}

	if strings.TrimSpace(user.PasswordHash) == "" {
		c.JSON(http.StatusUnauthorized, errResp("Invalid credentials", "AUTH_001"))
		return
	}

	if err := auth.ComparePassword(user.PasswordHash, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Invalid credentials", "AUTH_001"))
		return
	}

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
		UserID:    userIDHex,
		TokenHash: auth.HashToken(refreshToken),
		JTI:       jti,
		ExpiresAt: refreshExp,
		CreatedAt: now,
		Revoked:   false,
	}

	if _, err := h.tokens.InsertOne(ctx, tokenDoc); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing refresh token", "AUTH_500"))
		return
	}

	_, _ = h.users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"last_login": now, "updated_at": now}})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    int(time.Until(accessExp).Seconds()),
			"refresh_token": refreshToken,
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

func (h *Handler) refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, errResp("refresh_token is required", "AUTH_400"))
		return
	}

	claims, err := h.issuer.ParseRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Invalid refresh token", "AUTH_002"))
		return
	}

	hash := auth.HashToken(req.RefreshToken)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var stored models.RefreshToken
	err = h.tokens.FindOne(ctx, bson.M{
		"token_hash": hash,
		"jti":        claims.ID,
		"revoked":    false,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&stored)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("Refresh token revoked or expired", "AUTH_002"))
		return
	}

	now := time.Now().UTC()
	newJTI, err := randomID(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed rotating token", "AUTH_500"))
		return
	}

	newRefresh, refreshExp, err := h.issuer.GenerateRefreshToken(claims.UserID, newJTI, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating refresh token", "AUTH_500"))
		return
	}

	if _, err := h.tokens.UpdateOne(ctx, bson.M{"token_hash": hash}, bson.M{"$set": bson.M{"revoked": true, "revoked_at": now}}); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed rotating token", "AUTH_500"))
		return
	}

	_, err = h.tokens.InsertOne(ctx, models.RefreshToken{
		UserID:    claims.UserID,
		TokenHash: auth.HashToken(newRefresh),
		JTI:       newJTI,
		ExpiresAt: refreshExp,
		CreatedAt: now,
		Revoked:   false,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed storing refresh token", "AUTH_500"))
		return
	}

	var user models.User
	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User no longer active", "AUTH_003"))
		return
	}

	err = h.users.FindOne(ctx, bson.M{"_id": userOID, "is_active": true}, options.FindOne().SetProjection(bson.M{
		"password_hash": 0,
	})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User no longer active", "AUTH_003"))
		return
	}

	accessToken, accessExp, err := h.issuer.GenerateAccessToken(claims.UserID, user.Email, user.Role, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed generating token", "AUTH_500"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    int(time.Until(accessExp).Seconds()),
			"refresh_token": newRefresh,
		},
	})
}

func (h *Handler) logout(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, errResp("refresh_token is required", "AUTH_400"))
		return
	}

	hash := auth.HashToken(req.RefreshToken)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	_, err := h.tokens.UpdateOne(ctx, bson.M{"token_hash": hash, "revoked": false}, bson.M{
		"$set": bson.M{
			"revoked":    true,
			"revoked_at": time.Now().UTC(),
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed to revoke token", "AUTH_500"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Logged out"})
}

func (h *Handler) me(c *gin.Context) {
	claimsAny, exists := c.Get("access_claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, errResp("Unauthorized", "AUTH_003"))
		return
	}
	claims := claimsAny.(*auth.AccessClaims)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	userOID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	err = h.users.FindOne(ctx, bson.M{"_id": userOID, "is_active": true}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("User not found", "AUTH_003"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"id":             user.ID.Hex(),
			"email":          user.Email,
			"role":           user.Role,
			"first_name":     user.FirstName,
			"last_name":      user.LastName,
			"is_active":      user.IsActive,
			"email_verified": user.EmailVerified,
		},
	})
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("Authorization")
		parts := strings.SplitN(raw, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, errResp("Missing bearer token", "AUTH_003"))
			c.Abort()
			return
		}

		claims, err := h.issuer.ParseAccessToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, errResp("Invalid access token", "AUTH_003"))
			c.Abort()
			return
		}

		c.Set("access_claims", claims)
		c.Next()
	}
}

func (h *Handler) requireRoles(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[strings.ToLower(strings.TrimSpace(role))] = struct{}{}
	}

	return func(c *gin.Context) {
		claimsAny, exists := c.Get("access_claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, errResp("Unauthorized", "AUTH_003"))
			c.Abort()
			return
		}
		claims := claimsAny.(*auth.AccessClaims)
		if _, ok := allowed[strings.ToLower(claims.Role)]; !ok {
			c.JSON(http.StatusForbidden, errResp("Insufficient permissions", "AUTH_004"))
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *Handler) listUsers(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	cursor, err := h.users.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"password_hash": 0}).SetSort(bson.M{"created_at": -1}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed listing users", "AUTH_500"))
		return
	}
	defer cursor.Close(ctx)

	users := make([]gin.H, 0)
	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			c.JSON(http.StatusInternalServerError, errResp("Failed decoding users", "AUTH_500"))
			return
		}
		users = append(users, userDTO(user))
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed iterating users", "AUTH_500"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"users": users}})
}

func (h *Handler) getUser(c *gin.Context) {
	userOID, ok := parseUserID(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	err := h.users.FindOne(ctx, bson.M{"_id": userOID}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, errResp("User not found", "AUTH_404"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": userDTO(user)})
}

func (h *Handler) createUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Password = strings.TrimSpace(req.Password)
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if req.Role == "" {
		req.Role = "analyst"
	}

	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, errResp("email and password are required", "AUTH_400"))
		return
	}
	if !isValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, errResp("invalid email format", "AUTH_400"))
		return
	}
	if len(req.Password) < 10 {
		c.JSON(http.StatusBadRequest, errResp("password must be at least 10 characters", "AUTH_400"))
		return
	}
	if !isValidRole(req.Role) {
		c.JSON(http.StatusBadRequest, errResp("invalid role", "AUTH_400"))
		return
	}

	hash, err := auth.HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("Failed hashing password", "AUTH_500"))
		return
	}

	now := time.Now().UTC()
	insert := bson.M{
		"email":          req.Email,
		"password_hash":  hash,
		"role":           req.Role,
		"first_name":     strings.TrimSpace(req.FirstName),
		"last_name":      strings.TrimSpace(req.LastName),
		"is_active":      true,
		"email_verified": false,
		"created_at":     now,
		"updated_at":     now,
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := h.users.InsertOne(ctx, insert)
	if err != nil {
		c.JSON(http.StatusConflict, errResp("user already exists", "AUTH_409"))
		return
	}

	id := res.InsertedID.(primitive.ObjectID)
	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": id}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"id": id.Hex()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": userDTO(user)})
}

func (h *Handler) updateUser(c *gin.Context) {
	userOID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("Invalid request payload", "AUTH_400"))
		return
	}

	updates := bson.M{}
	if strings.TrimSpace(req.Role) != "" {
		role := strings.ToLower(strings.TrimSpace(req.Role))
		if !isValidRole(role) {
			c.JSON(http.StatusBadRequest, errResp("invalid role", "AUTH_400"))
			return
		}
		updates["role"] = role
	}
	if req.FirstName != "" {
		updates["first_name"] = strings.TrimSpace(req.FirstName)
	}
	if req.LastName != "" {
		updates["last_name"] = strings.TrimSpace(req.LastName)
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, errResp("no updates provided", "AUTH_400"))
		return
	}
	updates["updated_at"] = time.Now().UTC()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := h.users.UpdateOne(ctx, bson.M{"_id": userOID}, bson.M{"$set": updates})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("failed updating user", "AUTH_500"))
		return
	}
	if res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, errResp("User not found", "AUTH_404"))
		return
	}

	var user models.User
	err = h.users.FindOne(ctx, bson.M{"_id": userOID}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(&user)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": userDTO(user)})
}

func (h *Handler) deactivateUser(c *gin.Context) {
	userOID, ok := parseUserID(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	res, err := h.users.UpdateOne(ctx, bson.M{"_id": userOID}, bson.M{"$set": bson.M{"is_active": false, "updated_at": time.Now().UTC()}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errResp("failed deactivating user", "AUTH_500"))
		return
	}
	if res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, errResp("User not found", "AUTH_404"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func parseUserID(c *gin.Context) (primitive.ObjectID, bool) {
	id := strings.TrimSpace(c.Param("id"))
	userOID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, errResp("invalid user id", "AUTH_400"))
		return primitive.NilObjectID, false
	}
	return userOID, true
}

func isValidRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "analyst", "viewer":
		return true
	default:
		return false
	}
}

func isValidEmail(email string) bool {
	return emailRegex.MatchString(strings.TrimSpace(strings.ToLower(email)))
}

func userDTO(user models.User) gin.H {
	return gin.H{
		"id":             user.ID.Hex(),
		"email":          user.Email,
		"role":           user.Role,
		"first_name":     user.FirstName,
		"last_name":      user.LastName,
		"is_active":      user.IsActive,
		"email_verified": user.EmailVerified,
		"last_login":     user.LastLogin,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}
}

func errResp(message, code string) gin.H {
	return gin.H{
		"success": false,
		"error":   message,
		"code":    code,
	}
}

func randomID(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
