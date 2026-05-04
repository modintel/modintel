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

type wafRequestBucket struct {
	Total   uint64
	Blocked uint64
	Allowed uint64
}

type wafRequestStats struct {
	mu      sync.Mutex
	buckets map[int64]*wafRequestBucket
}

func newWAFRequestStats() *wafRequestStats {
	return &wafRequestStats{buckets: make(map[int64]*wafRequestBucket)}
}

var wafTrafficStats = newWAFRequestStats()

func RecordWAFRequest(ts time.Time, blocked bool) {
	wafTrafficStats.record(ts, blocked)
}

func GetWAFTrafficSnapshot(now time.Time) WAFTrafficSnapshot {
	total, blocked, allowed := wafTrafficStats.liveRPM(now)
	return WAFTrafficSnapshot{
		Timestamp:      now.UTC(),
		RequestsPerMin: total,
		BlockedPerMin:  blocked,
		AllowedPerMin:  allowed,
	}
}

func (s *wafRequestStats) record(ts time.Time, blocked bool) {
	minute := ts.UTC().Truncate(time.Minute).Unix()
	cutoff := minute - int64((24*time.Hour)/time.Minute)

	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.buckets[minute]
	if !ok {
		bucket = &wafRequestBucket{}
		s.buckets[minute] = bucket
	}

	bucket.Total++
	if blocked {
		bucket.Blocked++
	} else {
		bucket.Allowed++
	}

	for key := range s.buckets {
		if key < cutoff {
			delete(s.buckets, key)
		}
	}
}

func (s *wafRequestStats) liveRPM(now time.Time) (float64, float64, float64) {
	currentMinute := now.UTC().Truncate(time.Minute).Unix()
	var total uint64
	var blocked uint64
	var allowed uint64
	var count int

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := int64(1); i <= 2; i++ {
		minute := currentMinute - i*60
		if bucket, ok := s.buckets[minute]; ok {
			total += bucket.Total
			blocked += bucket.Blocked
			allowed += bucket.Allowed
			count++
		}
	}

	if count == 0 {
		return 0, 0, 0
	}

	denom := float64(count)
	return float64(total) / denom, float64(blocked) / denom, float64(allowed) / denom
}
