package smbfs

import "testing"

func TestRateLimiter_Disabled(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{Enabled: false})

	// Should always allow when disabled
	for i := 0; i < 1000; i++ {
		if !rl.Allow("127.0.0.1", "conn1") {
			t.Fatal("expected allow when disabled")
		}
	}
}

func TestRateLimiter_GlobalLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:    true,
		GlobalRate: 10,
		BurstSize:  5,
	})

	// Should allow burst
	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow("127.0.0.1", "conn1") {
			allowed++
		}
	}

	// Should have allowed approximately burst size
	if allowed < 3 || allowed > 7 {
		t.Errorf("expected ~5 allowed (burst), got %d", allowed)
	}
}

func TestRateLimiter_PerIPLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:   true,
		PerIPRate: 5,
		BurstSize: 3,
	})

	// Exhaust IP1's burst
	for i := 0; i < 10; i++ {
		rl.Allow("192.168.1.1", "conn1")
	}

	// IP2 should still have burst available
	if !rl.Allow("192.168.1.2", "conn2") {
		t.Fatal("expected different IP to be allowed")
	}
}

func TestRateLimiter_PerConnectionLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:           true,
		PerConnectionRate: 5,
		BurstSize:         3,
	})

	// Exhaust conn1's burst
	for i := 0; i < 10; i++ {
		rl.Allow("127.0.0.1", "conn1")
	}

	// conn2 should still have burst available
	if !rl.Allow("127.0.0.1", "conn2") {
		t.Fatal("expected different connection to be allowed")
	}
}

func TestRateLimiter_RemoveConnection(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:           true,
		PerConnectionRate: 100,
		BurstSize:         5,
	})

	rl.Allow("127.0.0.1", "conn1")
	rl.RemoveConnection("conn1")

	stats := rl.Stats()
	if stats.TrackedConns != 0 {
		t.Errorf("expected 0 tracked connections after remove, got %d", stats.TrackedConns)
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Enabled:   true,
		PerIPRate: 100,
		BurstSize: 10,
	})

	rl.Allow("192.168.1.1", "conn1")
	rl.Allow("192.168.1.2", "conn2")

	stats := rl.Stats()
	if !stats.Enabled {
		t.Error("expected enabled")
	}
	if stats.TrackedIPs != 2 {
		t.Errorf("expected 2 tracked IPs, got %d", stats.TrackedIPs)
	}
}
