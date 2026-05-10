package api

import (
	"sync"
	"time"
)

type WAFTrafficSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	RequestsPerMin float64   `json:"requests_per_minute"`
	BlockedPerMin  float64   `json:"blocked_per_minute"`
	AllowedPerMin  float64   `json:"allowed_per_minute"`
}

type wafRequestEntry struct {
	ts      time.Time
	blocked bool
}

type wafRequestStats struct {
	mu      sync.Mutex
	entries []wafRequestEntry
}

func newWAFRequestStats() *wafRequestStats {
	return &wafRequestStats{}
}

var wafTrafficStats = newWAFRequestStats()

func RecordWAFRequest(ts time.Time, blocked bool) {
	wafTrafficStats.record(ts, blocked)
}

func GetWAFTrafficSnapshot(now time.Time) WAFTrafficSnapshot {
	total, blocked, allowed := wafTrafficStats.slidingRPM(now)
	return WAFTrafficSnapshot{
		Timestamp:      now.UTC(),
		RequestsPerMin: total,
		BlockedPerMin:  blocked,
		AllowedPerMin:  allowed,
	}
}

const slidingWindow = 60 * time.Second

func (s *wafRequestStats) record(ts time.Time, blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, wafRequestEntry{ts: ts, blocked: blocked})
}

func (s *wafRequestStats) slidingRPM(now time.Time) (float64, float64, float64) {
	cutoff := now.Add(-slidingWindow)

	s.mu.Lock()
	defer s.mu.Unlock()

	firstValid := 0
	for firstValid < len(s.entries) && s.entries[firstValid].ts.Before(cutoff) {
		firstValid++
	}
	s.entries = s.entries[firstValid:]

	n := len(s.entries)
	if n == 0 {
		return 0, 0, 0
	}

	nBlocked := 0
	for _, e := range s.entries {
		if e.blocked {
			nBlocked++
		}
	}
	nAllowed := n - nBlocked

	factor := 60.0 / slidingWindow.Seconds()
	return float64(n) * factor, float64(nBlocked) * factor, float64(nAllowed) * factor
}
