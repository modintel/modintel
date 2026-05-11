package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_DefaultValues(t *testing.T) {
	// Clear environment for clean test
	os.Clearenv()

	cfg := Load()

	if cfg.Host != "0.0.0.0" {
		t.Errorf("Expected default Host '0.0.0.0', got %s", cfg.Host)
	}
	if cfg.Port != "8084" {
		t.Errorf("Expected default Port '8084', got %s", cfg.Port)
	}
	if cfg.BcryptCost != 12 {
		t.Errorf("Expected default BcryptCost 12, got %d", cfg.BcryptCost)
	}
	if cfg.JWTAccessExpiry != 15*time.Minute {
		t.Errorf("Expected default JWTAccessExpiry 15m, got %v", cfg.JWTAccessExpiry)
	}
	if cfg.JWTRefreshExpiry != 168*time.Hour {
		t.Errorf("Expected default JWTRefreshExpiry 168h, got %v", cfg.JWTRefreshExpiry)
	}
}

func TestLoad_EnvironmentVariables(t *testing.T) {
	os.Clearenv()
	
	t.Setenv("AUTH_HOST", "127.0.0.1")
	t.Setenv("AUTH_PORT", "9000")
	t.Setenv("JWT_SECRET", "my-super-secret-jwt-key-that-is-long-enough-32-chars")
	t.Setenv("BCRYPT_COST", "14")
	t.Setenv("JWT_ACCESS_EXPIRY", "30m")
	t.Setenv("AUTH_BOOTSTRAP_ADMIN_EMAIL", "admin@modintel.local")

	cfg := Load()

	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected Host from env '127.0.0.1', got %s", cfg.Host)
	}
	if cfg.Port != "9000" {
		t.Errorf("Expected Port from env '9000', got %s", cfg.Port)
	}
	if cfg.BcryptCost != 14 {
		t.Errorf("Expected BcryptCost 14, got %d", cfg.BcryptCost)
	}
	if cfg.JWTAccessExpiry != 30*time.Minute {
		t.Errorf("Expected JWTAccessExpiry 30m, got %v", cfg.JWTAccessExpiry)
	}
	if cfg.BootstrapAdminEmail != "admin@modintel.local" {
		t.Errorf("Expected admin email from env, got %s", cfg.BootstrapAdminEmail)
	}
}

func TestLoad_JWTSecretWarning(t *testing.T) {
	os.Clearenv()
	t.Setenv("JWT_SECRET", "shortsecret") // Less than 32 chars

	cfg := Load()

	if len(cfg.JWTSecret) < 32 {
		t.Log("Warning should be logged for short JWT secret - this is expected")
	}
}

func TestLoad_BcryptCostMinimum(t *testing.T) {
	os.Clearenv()
	t.Setenv("BCRYPT_COST", "4") // Too low

	cfg := Load()

	if cfg.BcryptCost < 10 {
		t.Errorf("BcryptCost should be minimum 10, got %d", cfg.BcryptCost)
	}
}

func TestLoad_BootstrapAdminCleanup(t *testing.T) {
	os.Clearenv()
	t.Setenv("AUTH_BOOTSTRAP_ADMIN_EMAIL", "  ADMIN@MODINTEL.LOCAL  ")
	t.Setenv("AUTH_BOOTSTRAP_ADMIN_ROLE", "")

	cfg := Load()

	if cfg.BootstrapAdminEmail != "admin@modintel.local" {
		t.Errorf("Email should be trimmed and lowercased, got %s", cfg.BootstrapAdminEmail)
	}
	if cfg.BootstrapAdminRole != "admin" {
		t.Errorf("Default role should be 'admin' when empty, got %s", cfg.BootstrapAdminRole)
	}
}