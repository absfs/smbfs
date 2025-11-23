package smbfs

import (
	"io/fs"
	"testing"
	"time"
)

func TestMetadataCache_DirEntries(t *testing.T) {
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     100 * time.Millisecond,
		StatCacheTTL:    100 * time.Millisecond,
		MaxCacheEntries: 10,
	}
	cache := newMetadataCache(config)

	// Test cache miss
	entries, ok := cache.getDirEntries("/test")
	if ok {
		t.Error("Expected cache miss, got hit")
	}
	if entries != nil {
		t.Error("Expected nil entries on miss")
	}

	// Test cache put and hit
	testEntries := []fs.DirEntry{}
	cache.putDirEntries("/test", testEntries)

	entries, ok = cache.getDirEntries("/test")
	if !ok {
		t.Error("Expected cache hit, got miss")
	}
	if entries == nil {
		t.Error("Expected entries, got nil")
	}

	// Test expiration
	time.Sleep(150 * time.Millisecond)
	entries, ok = cache.getDirEntries("/test")
	if ok {
		t.Error("Expected cache miss after expiration, got hit")
	}
}

func TestMetadataCache_StatInfo(t *testing.T) {
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     100 * time.Millisecond,
		StatCacheTTL:    100 * time.Millisecond,
		MaxCacheEntries: 10,
	}
	cache := newMetadataCache(config)

	// Test cache miss
	info, ok := cache.getStatInfo("/test.txt")
	if ok {
		t.Error("Expected cache miss, got hit")
	}
	if info != nil {
		t.Error("Expected nil info on miss")
	}

	// Test cache put and hit
	testInfo := &fileInfo{name: "test.txt"}
	cache.putStatInfo("/test.txt", testInfo)

	info, ok = cache.getStatInfo("/test.txt")
	if !ok {
		t.Error("Expected cache hit, got miss")
	}
	if info == nil {
		t.Error("Expected info, got nil")
	}
	if info.Name() != "test.txt" {
		t.Errorf("Expected name test.txt, got %s", info.Name())
	}

	// Test expiration
	time.Sleep(150 * time.Millisecond)
	info, ok = cache.getStatInfo("/test.txt")
	if ok {
		t.Error("Expected cache miss after expiration, got hit")
	}
}

func TestMetadataCache_Invalidate(t *testing.T) {
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 10,
	}
	cache := newMetadataCache(config)

	// Add entries
	cache.putDirEntries("/dir", []fs.DirEntry{})
	cache.putStatInfo("/dir/file.txt", &fileInfo{name: "file.txt"})

	// Verify they're cached
	_, ok := cache.getDirEntries("/dir")
	if !ok {
		t.Error("Expected /dir to be cached")
	}
	_, ok = cache.getStatInfo("/dir/file.txt")
	if !ok {
		t.Error("Expected /dir/file.txt to be cached")
	}

	// Invalidate file (should also invalidate parent directory)
	cache.invalidate("/dir/file.txt")

	// File should be gone
	_, ok = cache.getStatInfo("/dir/file.txt")
	if ok {
		t.Error("Expected /dir/file.txt to be invalidated")
	}

	// Parent directory should be gone
	_, ok = cache.getDirEntries("/dir")
	if ok {
		t.Error("Expected /dir to be invalidated")
	}
}

func TestMetadataCache_Eviction(t *testing.T) {
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 5,
	}
	cache := newMetadataCache(config)

	// Add 10 entries (exceeds max of 5)
	for i := 0; i < 10; i++ {
		path := "/file" + string(rune('0'+i)) + ".txt"
		cache.putStatInfo(path, &fileInfo{name: path})
	}

	stats := cache.Stats()
	if stats.TotalEntries > 5 {
		t.Errorf("Expected max 5 entries, got %d", stats.TotalEntries)
	}

	// Oldest entries should be evicted
	// Last 5 should still be present
	for i := 5; i < 10; i++ {
		path := "/file" + string(rune('0'+i)) + ".txt"
		_, ok := cache.getStatInfo(path)
		if !ok {
			t.Errorf("Expected %s to be cached (recent entry)", path)
		}
	}
}

func TestMetadataCache_Disabled(t *testing.T) {
	config := CacheConfig{
		EnableCache:     false,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 10,
	}
	cache := newMetadataCache(config)

	// Try to cache
	cache.putStatInfo("/test.txt", &fileInfo{name: "test.txt"})

	// Should not be cached
	_, ok := cache.getStatInfo("/test.txt")
	if ok {
		t.Error("Cache should be disabled, but got a hit")
	}

	stats := cache.Stats()
	if stats.Enabled {
		t.Error("Cache should be disabled")
	}
}

func TestMetadataCache_InvalidateAll(t *testing.T) {
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 10,
	}
	cache := newMetadataCache(config)

	// Add entries
	cache.putDirEntries("/dir1", []fs.DirEntry{})
	cache.putDirEntries("/dir2", []fs.DirEntry{})
	cache.putStatInfo("/file1.txt", &fileInfo{name: "file1.txt"})
	cache.putStatInfo("/file2.txt", &fileInfo{name: "file2.txt"})

	stats := cache.Stats()
	if stats.TotalEntries != 4 {
		t.Errorf("Expected 4 entries, got %d", stats.TotalEntries)
	}

	// Invalidate all
	cache.invalidateAll()

	stats = cache.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 entries after invalidateAll, got %d", stats.TotalEntries)
	}

	// Verify nothing is cached
	_, ok := cache.getDirEntries("/dir1")
	if ok {
		t.Error("Expected cache miss after invalidateAll")
	}
	_, ok = cache.getStatInfo("/file1.txt")
	if ok {
		t.Error("Expected cache miss after invalidateAll")
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	if config.EnableCache {
		t.Error("Expected cache to be disabled by default")
	}
	if config.DirCacheTTL != 5*time.Second {
		t.Errorf("Expected DirCacheTTL 5s, got %v", config.DirCacheTTL)
	}
	if config.StatCacheTTL != 5*time.Second {
		t.Errorf("Expected StatCacheTTL 5s, got %v", config.StatCacheTTL)
	}
	if config.MaxCacheEntries != 1000 {
		t.Errorf("Expected MaxCacheEntries 1000, got %d", config.MaxCacheEntries)
	}
}

func TestMetadataCache_GetParentPath(t *testing.T) {
	cache := newMetadataCache(DefaultCacheConfig())

	tests := []struct {
		path   string
		parent string
	}{
		{"/file.txt", "/"},
		{"/dir/file.txt", "/dir"},
		{"/dir/subdir/file.txt", "/dir/subdir"},
		{"/", "/"},
		{"", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			parent := cache.getParentPath(tt.path)
			if parent != tt.parent {
				t.Errorf("getParentPath(%q) = %q, want %q", tt.path, parent, tt.parent)
			}
		})
	}
}
