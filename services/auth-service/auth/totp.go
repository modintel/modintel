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

func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

func ValidateTOTPCodeWithTime(secret, code string, t time.Time) bool {
	valid, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

func GenerateRecoveryCodes() (plaintext []string, hashed []string, err error) {
	plaintext = make([]string, 8)
	hashed = make([]string, 8)

	for i := 0; i < 8; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		encoded := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		code := encoded[:5] + "-" + encoded[5:10]
		plaintext[i] = code
		hashed[i] = HashToken(code)
	}

	return plaintext, hashed, nil
}

func MatchRecoveryCode(plaintext string, hashes []string) int {
	h := HashToken(strings.ToUpper(strings.TrimSpace(plaintext)))
	for i, stored := range hashes {
		if stored == h {
			return i
		}
	}
	return -1
}