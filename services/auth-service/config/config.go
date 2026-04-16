package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host                string
	Port                string
	MongoURI            string
	MongoDBName         string
	JWTSecret           string
	JWTAccessExpiry     time.Duration
	JWTRefreshExpiry    time.Duration
	BcryptCost          int
	RateLimitAuthPerMin int
	RateLimitBurst      int
	RateLimitWindow     time.Duration
	TrustedProxyCIDRs   []string
	BootstrapAdminEmail string
	BootstrapAdminPass  string
	BootstrapAdminRole  string
	BootstrapAdminName  string
}

func Load() Config {
	cfg := Config{
		Host:                getEnv("AUTH_HOST", "0.0.0.0"),
		Port:                getEnv("AUTH_PORT", "8084"),
		MongoURI:            getEnv("MONGO_URI", "mongodb://localhost:27017/modintel"),
		MongoDBName:         getEnv("MONGO_DB_NAME", "modintel"),
		JWTSecret:           getEnv("JWT_SECRET", "change-me-super-secret-key-min-32-chars"),
		JWTAccessExpiry:     getDurationEnv("JWT_ACCESS_EXPIRY", "15m"),
		JWTRefreshExpiry:    getDurationEnv("JWT_REFRESH_EXPIRY", "168h"),
		BcryptCost:          getIntEnv("BCRYPT_COST", 12),
		RateLimitAuthPerMin: getIntEnv("RATE_LIMIT_AUTH", 5),
		TrustedProxyCIDRs:   []string{},
		BootstrapAdminEmail: strings.ToLower(strings.TrimSpace(getEnv("AUTH_BOOTSTRAP_ADMIN_EMAIL", ""))),
		BootstrapAdminPass:  getEnv("AUTH_BOOTSTRAP_ADMIN_PASSWORD", ""),
		BootstrapAdminRole:  getEnv("AUTH_BOOTSTRAP_ADMIN_ROLE", "admin"),
		BootstrapAdminName:  getEnv("AUTH_BOOTSTRAP_ADMIN_NAME", "ModIntel"),
	}

	cfg.RateLimitWindow = time.Minute
	cfg.RateLimitBurst = cfg.RateLimitAuthPerMin

	if len(cfg.JWTSecret) < 32 {
		log.Printf("WARNING: JWT_SECRET is shorter than 32 chars; set a stronger secret for production")
	}

	if cfg.BcryptCost < 10 {
		cfg.BcryptCost = 10
	}

	if cfg.BootstrapAdminRole == "" {
		cfg.BootstrapAdminRole = "admin"
	}

	return cfg
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func getIntEnv(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getDurationEnv(key, fallback string) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		raw = fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		d, _ = time.ParseDuration(fallback)
	}
	return d
}
