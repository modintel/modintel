package models

type SMTPSettings struct {
	SMTPHost     string `bson:"smtp_host"      json:"smtp_host"`
	SMTPPort     int    `bson:"smtp_port"      json:"smtp_port"`
	SMTPUsername string `bson:"smtp_username"  json:"smtp_username"`
	SMTPPassword string `bson:"smtp_password"  json:"-"`
	SMTPFrom     string `bson:"smtp_from"      json:"smtp_from"`
	SMTPFromName string `bson:"smtp_from_name" json:"smtp_from_name"`
	SMTPUseTLS   bool   `bson:"smtp_use_tls"   json:"smtp_use_tls"`
}