package smbfs

import (
	"sync"
	"time"
)

// RateLimiterConfig configures rate limiting behavior
type RateLimiterConfig struct {
	// Enabled enables rate limiting
	Enabled bool

	// GlobalRate is the maximum requests per second across all connections
	GlobalRate float64

	// PerIPRate is the maximum requests per second per client IP
	PerIPRate float64

	// PerConnectionRate is the maximum requests per second per connection
	PerConnectionRate float64

	// BurstSize is the maximum burst size (token bucket capacity)
	BurstSize int

	// CleanupInterval is how often to clean up expired per-IP entries
	CleanupInterval time.Duration
}

// DefaultRateLimiterConfig returns sensible default rate limiting configuration
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Enabled:           false,
		GlobalRate:        10000,
		PerIPRate:         1000,
		PerConnectionRate: 500,
		BurstSize:         50,
		CleanupInterval:   time.Minute,
	}
}

// RateLimiter implements token-bucket rate limiting at multiple granularities
type RateLimiter struct {
	config RateLimiterConfig

	mu       sync.Mutex
	global   *tokenBucket
	perIP    map[string]*tokenBucket
	perConn  map[string]*tokenBucket
	lastCleanup time.Time
}

// tokenBucket implements a simple token bucket algorithm
type tokenBucket struct {
	rate       float64
	burst      int
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		config:      config,
		perIP:       make(map[string]*tokenBucket),
		perConn:     make(map[string]*tokenBucket),
		lastCleanup: time.Now(),
	}
	if config.GlobalRate > 0 {
		rl.global = newTokenBucket(config.GlobalRate, config.BurstSize)
	}
	return rl
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	if burst <= 0 {
		burst = int(rate)
		if burst < 1 {
			burst = 1
		}
	}
	return &tokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// Allow checks if a request should be allowed through
func (rl *RateLimiter) Allow(clientIP, connID string) bool {
	if !rl.config.Enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup
	if time.Since(rl.lastCleanup) > rl.config.CleanupInterval {
		rl.cleanup()
		rl.lastCleanup = time.Now()
	}

	// Check global limit
	if rl.global != nil && !rl.global.allow() {
		return false
	}

	// Check per-IP limit
	if rl.config.PerIPRate > 0 && clientIP != "" {
		bucket, ok := rl.perIP[clientIP]
		if !ok {
			bucket = newTokenBucket(rl.config.PerIPRate, rl.config.BurstSize)
			rl.perIP[clientIP] = bucket
		}
		if !bucket.allow() {
			return false
		}
	}

	// Check per-connection limit
	if rl.config.PerConnectionRate > 0 && connID != "" {
		bucket, ok := rl.perConn[connID]
		if !ok {
			bucket = newTokenBucket(rl.config.PerConnectionRate, rl.config.BurstSize)
			rl.perConn[connID] = bucket
		}
		if !bucket.allow() {
			return false
		}
	}

	return true
}

// RemoveConnection removes rate limit state for a disconnected connection
func (rl *RateLimiter) RemoveConnection(connID string) {
	if !rl.config.Enabled {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.perConn, connID)
}

// allow consumes a token from the bucket, refilling based on elapsed time
func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	// Refill tokens
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.burst) {
		tb.tokens = float64(tb.burst)
	}

	// Check if we have tokens
	if tb.tokens < 1.0 {
		return false
	}

	tb.tokens -= 1.0
	return true
}

// cleanup removes stale per-IP and per-connection entries
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-5 * time.Minute)
	for ip, bucket := range rl.perIP {
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.perIP, ip)
		}
	}
	for conn, bucket := range rl.perConn {
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.perConn, conn)
		}
	}
}

// Stats returns rate limiter statistics
func (rl *RateLimiter) Stats() RateLimitStats {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return RateLimitStats{
		Enabled:         rl.config.Enabled,
		TrackedIPs:      len(rl.perIP),
		TrackedConns:    len(rl.perConn),
		GlobalTokens:    rl.globalTokens(),
	}
}

func (rl *RateLimiter) globalTokens() float64 {
	if rl.global == nil {
		return 0
	}
	return rl.global.tokens
}

// RateLimitStats provides statistics about rate limiting
type RateLimitStats struct {
	Enabled      bool
	TrackedIPs   int
	TrackedConns int
	GlobalTokens float64
}
