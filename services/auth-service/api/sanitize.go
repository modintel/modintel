package api

import "strings"

// sanitizeToken validates that a token is a 64-char lowercase hex string.
// This prevents NoSQL injection via token fields used in MongoDB queries.
func sanitizeToken(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if len(token) != 64 {
		return "", false
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return token, true
}

// sanitizeEmailHeader removes CR, LF, and null bytes from values that will
// appear in email headers or be interpolated into email body content.
// Prevents SMTP header injection and email content injection attacks.
func sanitizeEmailHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 254 {
		s = s[:254]
	}
	return s
}
