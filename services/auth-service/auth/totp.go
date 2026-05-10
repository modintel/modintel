package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpIssuer = "ModIntel"

// GenerateTOTPSecret creates a new TOTP secret for a user.
// Returns the secret key, the otpauth:// URL, and any error.
func GenerateTOTPSecret(email string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTPCode checks a 6-digit code against the stored secret.
func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ValidateTOTPCodeWithTime checks a code with a custom time (useful for testing).
func ValidateTOTPCodeWithTime(secret, code string, t time.Time) bool {
	valid, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      1, // allow 1 period skew (±30s)
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

// GenerateRecoveryCodes generates 8 one-time recovery codes.
// Returns plaintext codes (to show user once) and their SHA-256 hashes (to store).
func GenerateRecoveryCodes() (plaintext []string, hashed []string, err error) {
	plaintext = make([]string, 8)
	hashed = make([]string, 8)

	for i := 0; i < 8; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		// Format as XXXXX-XXXXX for readability
		encoded := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		code := encoded[:5] + "-" + encoded[5:10]
		plaintext[i] = code
		hashed[i] = HashToken(code) // reuse SHA-256 hash from jwt.go
	}

	return plaintext, hashed, nil
}

// MatchRecoveryCode checks if a plaintext code matches any stored hash.
// Returns the index of the matched code, or -1 if not found.
func MatchRecoveryCode(plaintext string, hashes []string) int {
	h := HashToken(strings.ToUpper(strings.TrimSpace(plaintext)))
	for i, stored := range hashes {
		if stored == h {
			return i
		}
	}
	return -1
}
