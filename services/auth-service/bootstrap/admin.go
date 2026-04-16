package bootstrap

import (
	"context"
	"log"
	"strings"
	"time"

	"modintel/services/auth-service/auth"
	"modintel/services/auth-service/config"
	"modintel/services/auth-service/db"

	"go.mongodb.org/mongo-driver/bson"
)

func EnsureAdmin(cfg config.Config, database *db.Database) {
	email := strings.TrimSpace(strings.ToLower(cfg.BootstrapAdminEmail))
	password := strings.TrimSpace(cfg.BootstrapAdminPass)
	if email == "" || password == "" {
		log.Printf("Auth bootstrap admin skipped (AUTH_BOOTSTRAP_ADMIN_EMAIL/PASSWORD not set)")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	users := database.DB.Collection("users")
	count, err := users.CountDocuments(ctx, bson.M{"email": email})
	if err != nil {
		log.Printf("Auth bootstrap admin check failed: %v", err)
		return
	}
	if count > 0 {
		log.Printf("Auth bootstrap admin exists: %s", email)
		return
	}

	hash, err := auth.HashPassword(password, cfg.BcryptCost)
	if err != nil {
		log.Printf("Auth bootstrap admin password hash failed: %v", err)
		return
	}

	now := time.Now().UTC()
	nameParts := strings.Fields(strings.TrimSpace(cfg.BootstrapAdminName))
	first := "ModIntel"
	last := "Admin"
	if len(nameParts) > 0 {
		first = nameParts[0]
	}
	if len(nameParts) > 1 {
		last = strings.Join(nameParts[1:], " ")
	}

	_, err = users.InsertOne(ctx, bson.M{
		"email":          email,
		"password_hash":  hash,
		"role":           cfg.BootstrapAdminRole,
		"first_name":     first,
		"last_name":      last,
		"is_active":      true,
		"email_verified": true,
		"created_at":     now,
		"updated_at":     now,
	})
	if err != nil {
		log.Printf("Auth bootstrap admin create failed: %v", err)
		return
	}

	log.Printf("Auth bootstrap admin created: %s", email)
}
