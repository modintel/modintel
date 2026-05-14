package auth

import (
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func ComparePassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func IsValidPassword(password string) bool {
	if len(password) < 10 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func IsCommonPassword(password string) bool {
	_, found := commonPasswords[strings.ToLower(password)]
	return found
}

var commonPasswords = map[string]bool{
	"password123":  true,
	"password1234": true,
	"admin123":     true,
	"admin1234":    true,
	"welcome123":   true,
	"letmein123":   true,
	"qwerty12345":  true,
	"abc123456":    true,
	"iloveyou123":  true,
	"monkey12345":  true,
	"dragon12345":  true,
	"master1234":   true,
	"sunshine123":  true,
	"princess123":  true,
	"football123":  true,
	"shadow12345":  true,
	"superman123":  true,
	"michael123":   true,
	"charlie123":   true,
	"donald1234":   true,
	"passw0rd123":  true,
	"p@ssword123":  true,
	"p@ssw0rd123":  true,
	"test123456":   true,
	"user123456":   true,
	"login12345":   true,
	"secure1234":   true,
	"changeme123":  true,
	"default123":   true,
	"modintel123":  true,
}