package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	WAFRulesCollection = "waf_rules"
)

func GetWAFRulesCollection() *mongo.Collection {
	return GetCollection("modintel", WAFRulesCollection)
}

func CreateWAFRulesIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := GetWAFRulesCollection()

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "id", Value: 1},
			},
			Options: options.Index().
				SetUnique(true).
				SetName("idx_waf_rules_id_unique"),
		},
		{
			Keys: bson.D{
				{Key: "type", Value: 1},
				{Key: "category", Value: 1},
			},
			Options: options.Index().
				SetName("idx_waf_rules_type_category"),
		},
		{
			Keys: bson.D{
				{Key: "enabled", Value: 1},
			},
			Options: options.Index().
				SetName("idx_waf_rules_enabled"),
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

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return err
	}

	log.Println("Created indexes on waf_rules collection")

	return nil
}
