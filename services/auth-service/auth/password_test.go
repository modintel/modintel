package auth

import "testing"

func TestPasswordHashAndCompare(t *testing.T) {
	password := "SecurePass123!"
	hash, err := HashPassword(password, 10)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	if err := ComparePassword(hash, password); err != nil {
		t.Fatalf("ComparePassword error: %v", err)
	}

	if err := ComparePassword(hash, "wrong-password"); err == nil {
		t.Fatal("expected mismatch error for wrong password")
	}
}
