package db

import "time"

type WAFRule struct {
	ID            string    `bson:"id" json:"id"`
	Type          string    `bson:"type" json:"type"`
	Category      string    `bson:"category" json:"category"`
	Description   string    `bson:"description" json:"description"`
	Severity      string    `bson:"severity" json:"severity"`
	Phase         int       `bson:"phase" json:"phase"`
	ParanoiaLevel int       `bson:"paranoia_level" json:"paranoia_level"`
	Source        string    `bson:"source" json:"source"`
	Enabled       bool      `bson:"enabled" json:"enabled"`
	Archived      bool      `bson:"archived" json:"archived"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time `bson:"updated_at" json:"updated_at"`
	Signature     string    `bson:"signature" json:"signature"`
}
