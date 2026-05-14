package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"modintel/services/auth-service/config"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Database struct {
	Client *mongo.Client
	DB     *mongo.Database
}

func Connect(cfg config.Config) *Database {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	db := &Database{
		Client: client,
		DB:     client.Database(cfg.MongoDBName),
	}

	if err := ensureIndexes(ctx, db.DB); err != nil {
		log.Fatalf("Failed creating auth indexes: %v", err)
	}

	log.Printf("Connected to MongoDB for auth-service (%s)", cfg.MongoDBName)
	return db
}

func GetCollection(dbName, collectionName string) *mongo.Collection {
	return nil
}

func ensureIndexes(ctx context.Context, database *mongo.Database) error {
	users := database.Collection("users")
	_, err := users.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: map[string]int{"email": 1}, Options: options.Index().SetUnique(true)},
		{Keys: map[string]int{"role": 1}},
	})
	if err != nil {
		return fmt.Errorf("users indexes: %w", err)
	}

	refreshTokens := database.Collection("refresh_tokens")
	_, err = refreshTokens.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: map[string]int{"jti": 1}, Options: options.Index().SetUnique(true)},
		{Keys: map[string]int{"token_hash": 1}},
		{Keys: map[string]int{"user_id": 1}},
		{Keys: map[string]int{"expires_at": 1}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("refresh_tokens indexes: %w", err)
	}

	invitations := database.Collection("invitations")
	_, err = invitations.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: map[string]int{"token": 1}, Options: options.Index().SetUnique(true)},
		{Keys: map[string]int{"email": 1}},
		{Keys: map[string]int{"expires_at": 1}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("invitations indexes: %w", err)
	}

	inviteLogs := database.Collection("invite_logs")
	_, err = inviteLogs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "invited_by", Value: 1}, {Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(3600)},
	})
	if err != nil {
		return fmt.Errorf("invite_logs indexes: %w", err)
	}

	passwordResets := database.Collection("password_resets")
	_, err = passwordResets.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: map[string]int{"token": 1}, Options: options.Index().SetUnique(true)},
		{Keys: map[string]int{"user_id": 1}},
		{Keys: map[string]int{"expires_at": 1}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("password_resets indexes: %w", err)
	}

	return nil
}