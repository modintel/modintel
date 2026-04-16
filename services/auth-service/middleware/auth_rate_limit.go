package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type authBucket struct {
	Count        int
	WindowStart  time.Time
	BlockedUntil time.Time
}

type AuthRateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*authBucket
	maxPerMin int
	blockFor  time.Duration
}

func NewAuthRateLimiter(maxPerMin int) *AuthRateLimiter {
	if maxPerMin <= 0 {
		maxPerMin = 5
	}
	return &AuthRateLimiter{
		buckets:   make(map[string]*authBucket),
		maxPerMin: maxPerMin,
		blockFor:  time.Minute,
	}
}

func (r *AuthRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := rateLimitKey(c)
		now := time.Now().UTC()

		r.mu.Lock()
		bucket, ok := r.buckets[key]
		if !ok {
			bucket = &authBucket{WindowStart: now}
			r.buckets[key] = bucket
		}

		if now.Before(bucket.BlockedUntil) {
			retryAfter := int(bucket.BlockedUntil.Sub(now).Seconds())
			r.mu.Unlock()
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.JSON(429, gin.H{"success": false, "error": "Too many login attempts", "code": "AUTH_429"})
			c.Abort()
			return
		}

		if now.Sub(bucket.WindowStart) >= time.Minute {
			bucket.WindowStart = now
			bucket.Count = 0
		}

		r.mu.Unlock()

		c.Next()

		if c.Writer.Status() == http.StatusUnauthorized {
			r.mu.Lock()
			bucket, ok := r.buckets[key]
			if !ok {
				bucket = &authBucket{WindowStart: now}
				r.buckets[key] = bucket
			}
			if time.Now().UTC().Sub(bucket.WindowStart) >= time.Minute {
				bucket.WindowStart = time.Now().UTC()
				bucket.Count = 0
			}
			bucket.Count++
			if bucket.Count >= r.maxPerMin {
				bucket.BlockedUntil = time.Now().UTC().Add(r.blockFor)
			}
			r.mu.Unlock()
			return
		}

		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			r.mu.Lock()
			if bucket, ok := r.buckets[key]; ok {
				bucket.Count = 0
				bucket.WindowStart = time.Now().UTC()
			}
			r.mu.Unlock()
		}
	}
}

type loginRequest struct {
	Email string `json:"email"`
}

func rateLimitKey(c *gin.Context) string {
	ip := c.ClientIP()
	if c.Request == nil || c.Request.Body == nil {
		return ip
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return ip
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if len(bodyBytes) == 0 {
		return ip
	}

	var req loginRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return ip
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return ip
	}

	return ip + ":" + email
}
