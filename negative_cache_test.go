package smbfs

import (
	"testing"
	"time"
)

func TestNegativeCache_Basic(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     time.Second,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	// Path should not be negatively cached initially
	if cache.isNegativelyCached("/nonexistent") {
		t.Fatal("expected path not to be negatively cached initially")
	}

	// Put negative entry
	cache.putNegative("/nonexistent")

	// Should now be negatively cached
	if !cache.isNegativelyCached("/nonexistent") {
		t.Fatal("expected path to be negatively cached")
	}
}

func TestNegativeCache_Expiry(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     50 * time.Millisecond,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	cache.putNegative("/expired")

	// Should be cached initially
	if !cache.isNegativelyCached("/expired") {
		t.Fatal("expected path to be negatively cached")
	}

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Should no longer be cached
	if cache.isNegativelyCached("/expired") {
		t.Fatal("expected negative cache entry to expire")
	}
}

func TestNegativeCache_Invalidation(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     5 * time.Second,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	cache.putNegative("/will-exist")

	// Should be cached
	if !cache.isNegativelyCached("/will-exist") {
		t.Fatal("expected path to be negatively cached")
	}

	// Invalidate (simulates file creation)
	cache.invalidate("/will-exist")

	// Should no longer be cached
	if cache.isNegativelyCached("/will-exist") {
		t.Fatal("expected negative cache entry to be invalidated")
	}
}

func TestNegativeCache_Disabled(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     false,
		NegativeTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	// Should not cache when disabled
	cache.putNegative("/test")
	if cache.isNegativelyCached("/test") {
		t.Fatal("expected negative cache to be inactive when cache disabled")
	}
}

func TestNegativeCache_ZeroTTL(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     0,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	// NegativeTTL=0 gets default (2s), so this should actually work
	// But if explicitly set to disable, it should be handled
	cache.putNegative("/test")
	// With default TTL applied, this should be cached
	if !cache.isNegativelyCached("/test") {
		t.Fatal("expected negative cache with default TTL")
	}
}

func TestCacheStats_WithNegativeCache(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     5 * time.Second,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	cache.putNegative("/neg1")
	cache.putNegative("/neg2")

	stats := cache.Stats()
	if stats.NegativeCacheEntries != 2 {
		t.Errorf("expected 2 negative entries, got %d", stats.NegativeCacheEntries)
	}
	if stats.TotalEntries != 2 {
		t.Errorf("expected 2 total entries, got %d", stats.TotalEntries)
	}
}

func TestCacheStats_HitRate(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     5 * time.Second,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	// Miss
	cache.getStatInfo("/nonexistent")

	// Put and hit
	cache.putNegative("/neg")
	cache.isNegativelyCached("/neg")

	stats := cache.Stats()
	if stats.Hits < 1 {
		t.Errorf("expected at least 1 hit, got %d", stats.Hits)
	}
	if stats.Misses < 1 {
		t.Errorf("expected at least 1 miss, got %d", stats.Misses)
	}
	if stats.HitRate <= 0 || stats.HitRate >= 1 {
		t.Errorf("expected hit rate between 0 and 1, got %f", stats.HitRate)
	}
}

func TestInvalidateAll_ClearsNegativeCache(t *testing.T) {
	cache := newMetadataCache(CacheConfig{
		EnableCache:     true,
		NegativeTTL:     5 * time.Second,
		StatCacheTTL:    5 * time.Second,
		DirCacheTTL:     5 * time.Second,
		MaxCacheEntries: 100,
	})

	cache.putNegative("/neg1")
	cache.putNegative("/neg2")

	cache.invalidateAll()

	if cache.isNegativelyCached("/neg1") {
		t.Fatal("expected negative cache to be cleared")
	}
	if cache.isNegativelyCached("/neg2") {
		t.Fatal("expected negative cache to be cleared")
	}
}
