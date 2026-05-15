package db

import (
	"context"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

func TestConnect(t *testing.T) {
	mongoURI := os.Getenv("MONGO_URI")

	if mongoURI == "" {
		t.Skip("Skipping MongoDB test: MONGO_URI not set")
	}

	// Reset client before test
	Client = nil

	Connect()

	if Client == nil {
		t.Fatal("expected MongoDB client to be initialized")
	}

	// Verify ping works
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Client.Ping(ctx, nil)
	if err != nil {
		t.Fatalf("failed to ping MongoDB: %v", err)
	}
}

func TestGetCollection(t *testing.T) {
	mongoURI := os.Getenv("MONGO_URI")

	if mongoURI == "" {
		t.Skip("Skipping MongoDB test: MONGO_URI not set")
	}

	// Ensure connection exists
	if Client == nil {
		Connect()
	}

	collection := GetCollection("modintel", "alerts")

	if collection == nil {
		t.Fatal("expected collection, got nil")
	}

	if collection.Name() != "alerts" {
		t.Errorf(
			"expected collection name alerts, got %s",
			collection.Name(),
		)
	}
}

func TestEnsureIndexes(t *testing.T) {
	mongoURI := os.Getenv("MONGO_URI")

	if mongoURI == "" {
		t.Skip("Skipping MongoDB test: MONGO_URI not set")
	}

	// Ensure connection exists
	if Client == nil {
		Connect()
	}

	ensureIndexes()

	collection := GetCollection("modintel", "alerts")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Indexes().List(ctx)
	if err != nil {
		t.Fatalf("failed to list indexes: %v", err)
	}

	var indexes []map[string]interface{}

	if err := cursor.All(ctx, &indexes); err != nil {
		t.Fatalf("failed to decode indexes: %v", err)
	}

	// MongoDB automatically creates _id index
	if len(indexes) < 5 {
		t.Errorf(
			"expected at least 5 indexes, got %d",
			len(indexes),
		)
	}
}

func TestClientIsMongoClient(t *testing.T) {
	mongoURI := os.Getenv("MONGO_URI")

	if mongoURI == "" {
		t.Skip("Skipping MongoDB test: MONGO_URI not set")
	}

	if Client == nil {
		Connect()
	}

	var _ *mongo.Client = Client
}