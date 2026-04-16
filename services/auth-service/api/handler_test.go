package api

import "testing"

func TestIsValidEmail(t *testing.T) {
	valid := []string{"admin@modintel.local", "analyst+1@example.com", "viewer@corp.io"}
	invalid := []string{"", "bad", "bad@", "@bad.com", "bad @corp.io"}

	for _, value := range valid {
		if !isValidEmail(value) {
			t.Fatalf("expected valid email %q", value)
		}
	}

	for _, value := range invalid {
		if isValidEmail(value) {
			t.Fatalf("expected invalid email %q", value)
		}
	}
}

func TestIsValidRole(t *testing.T) {
	valid := []string{"admin", "analyst", "viewer", "ADMIN"}
	invalid := []string{"", "owner", "user"}

	for _, role := range valid {
		if !isValidRole(role) {
			t.Fatalf("expected valid role %q", role)
		}
	}

	for _, role := range invalid {
		if isValidRole(role) {
			t.Fatalf("expected invalid role %q", role)
		}
	}
}
