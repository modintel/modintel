package db

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func Connect() {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	Client = client
	log.Println("Connected to MongoDB successfully!")

	alertsColl := client.Database("modintel").Collection("alerts")
	indexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: 1}}, Options: options.Index().SetName("idx_alerts_timestamp")},
		{Keys: bson.D{{Key: "ai_status", Value: 1}}, Options: options.Index().SetName("idx_alerts_ai_status")},
		{Keys: bson.D{{Key: "anomaly_score", Value: 1}}, Options: options.Index().SetName("idx_alerts_anomaly_score")},
		{Keys: bson.D{{Key: "human_label", Value: 1}}, Options: options.Index().SetName("idx_alerts_human_label")},
		{Keys: bson.D{{Key: "ai_priority", Value: 1}}, Options: options.Index().SetName("idx_alerts_ai_priority")},
		{Keys: bson.D{{Key: "source", Value: 1}, {Key: "timestamp", Value: -1}}, Options: options.Index().SetName("idx_source_ts")},
		{Keys: bson.D{{Key: "ai_status", Value: 1}, {Key: "timestamp", Value: -1}}, Options: options.Index().SetName("idx_ai_status_ts")},
		{Keys: bson.D{{Key: "status", Value: 1}}, Options: options.Index().SetName("idx_alerts_status")},
		{Keys: bson.D{{Key: "alert_key", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true).SetName("idx_alerts_alert_key")},
	}
	_, err = alertsColl.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		log.Printf("Warning: could not create indexes: %v", err)
	} else {
		log.Println("Created indexes on alerts collection")
	}
}

func GetCollection(databaseName, collectionName string) *mongo.Collection {
	return Client.Database(databaseName).Collection(collectionName)
}

func InitRuleIndexes() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rulesColl := GetCollection("modintel", "waf_rules")

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "id", Value: 1},
			},
			Options: options.Index().
				SetUnique(true).
				SetName("idx_rule_id"),
		},
		{
			Keys: bson.D{
				{Key: "type", Value: 1},
				{Key: "category", Value: 1},
			},
			Options: options.Index().
				SetName("idx_type_category"),
		},
		{
			Keys: bson.D{
				{Key: "enabled", Value: 1},
			},
			Options: options.Index().
				SetName("idx_enabled"),
		},
		{
			Keys: bson.D{
				{Key: "archived", Value: 1},
			},
			Options: options.Index().
				SetName("idx_waf_rules_archived"),
		},
		{
			Keys: bson.D{
				{Key: "paranoia_level", Value: 1},
			},
			Options: options.Index().
				SetName("idx_waf_rules_paranoia"),
		},
	}

	_, err := rulesColl.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		log.Printf("Failed creating waf_rules indexes: %v", err)
		return
	}

	log.Println("Created indexes for waf_rules collection")
}
