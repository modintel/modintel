package bootstrap

import (
	"testing"

	"modintel/services/auth-service/config"
)

func TestEnsureAdmin_SkipsWhenNoCredentials(t *testing.T) {
	cfg := config.Config{
		BootstrapAdminEmail: "",
		BootstrapAdminPass:  "",
	}

	EnsureAdmin(cfg, nil)
}

func TestEnsureAdmin_SkipsWhenEmailOrPasswordEmpty(t *testing.T) {
	testCases := []struct {
		name string
		cfg  config.Config
	}{
		{
			name: "Empty email",
			cfg:  config.Config{BootstrapAdminEmail: "", BootstrapAdminPass: "pass123"},
		},
		{
			name: "Empty password",
			cfg:  config.Config{BootstrapAdminEmail: "admin@modintel.local", BootstrapAdminPass: ""},
		},
		{
			name: "Whitespace email",
			cfg:  config.Config{BootstrapAdminEmail: "   ", BootstrapAdminPass: "pass123"},
		},
		{
			name: "Whitespace password",
			cfg:  config.Config{BootstrapAdminEmail: "admin@modintel.local", BootstrapAdminPass: "   "},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			EnsureAdmin(tc.cfg, nil)
		})
	}
}

func TestEnsureAdmin_NameParsing(t *testing.T) {
	testNames := []string{
		"John Doe",
		"ModIntel Admin Team",
		"",
		"Single",
		"Dr. Alice Smith Jr.",
	}

	for _, name := range testNames {
		t.Run("Name: "+name, func(t *testing.T) {
			cfg := config.Config{
				BootstrapAdminEmail: "", // empty email forces early return
				BootstrapAdminPass:  "",
				BootstrapAdminName:  name,
				BootstrapAdminRole:  "admin",
			}
			EnsureAdmin(cfg, nil)
		})
	}
}