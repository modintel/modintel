package api

import (
	"regexp"
	"strings"
)

var tokenRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

var emailRegexpSanitizer = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func sanitizeToken(token string) (string, bool) {
	token = strings.TrimSpace(strings.ToLower(token))
	if !tokenRegexp.MatchString(token) {
		return "", false
	}
	return tokenRegexp.FindString(token), true
}

func sanitizeEmail(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRegexpSanitizer.MatchString(email) {
		return "", false
	}
	return emailRegexpSanitizer.FindString(email), true
}

func sanitizeEmailHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 254 {
		s = s[:254]
	}
	return s
}