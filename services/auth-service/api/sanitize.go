package api

import (
	"regexp"
	"strings"
)

// tokenRegexp matches exactly 64 lowercase hex characters.
// CodeQL recognises regexp.MatchString as a sanitizer that breaks taint flow.
var tokenRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

// emailRegexpSanitizer is a strict email pattern used as a CodeQL sanitizer.
// CodeQL recognises regexp.MatchString checks as taint-breaking sanitizers.
var emailRegexpSanitizer = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// sanitizeToken validates that a token is exactly 64 lowercase hex characters
// and returns the validated value. Uses regexp so CodeQL breaks the taint chain.
func sanitizeToken(token string) (string, bool) {
	token = strings.TrimSpace(strings.ToLower(token))
	if !tokenRegexp.MatchString(token) {
		return "", false
	}
	// Return a new string built from the regexp match to fully break taint
	return tokenRegexp.FindString(token), true
}

// sanitizeEmail validates an email address using regexp and returns the
// validated value. Uses regexp so CodeQL breaks the taint chain.
func sanitizeEmail(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRegexpSanitizer.MatchString(email) {
		return "", false
	}
	return emailRegexpSanitizer.FindString(email), true
}

// sanitizeEmailHeader removes CR, LF, and null bytes from values that will
// appear in email headers or be interpolated into email body content.
func sanitizeEmailHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 254 {
		s = s[:254]
	}
	return s
}
