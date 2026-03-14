package smbfs

import (
	"io/fs"
	"sync"
	"time"
)

// CacheConfig configures the metadata cache behavior.
type CacheConfig struct {
	// EnableCache enables metadata caching. Default: false for safety.
	EnableCache bool

	// DirCacheTTL is the time-to-live for directory listings.
	// Default: 5 seconds. Set to 0 to disable directory caching.
	DirCacheTTL time.Duration

	// StatCacheTTL is the time-to-live for file stat results.
	// Default: 5 seconds. Set to 0 to disable stat caching.
	StatCacheTTL time.Duration

	// NegativeTTL is the time-to-live for negative cache entries
	// (paths known not to exist). Default: 2 seconds.
	NegativeTTL time.Duration

	// MaxCacheEntries is the maximum number of cache entries.
	// When exceeded, oldest entries are evicted. Default: 1000.
	MaxCacheEntries int
}

// DefaultCacheConfig returns a cache configuration with reasonable defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		EnableCache:     false, // Disabled by default for consistency
		DirCacheTTL:     5 * time.Second,
		StatCacheTTL:    5 * time.Second,
		MaxCacheEntries: 1000,
	}
}

// metadataCache provides caching for directory listings and file stats.
// This significantly improves performance for repeated metadata operations.
type metadataCache struct {
	mu            sync.RWMutex
	config        CacheConfig
	dirCache      map[string]*dirCacheEntry
	statCache     map[string]*statCacheEntry
	negativeCache map[string]time.Time // paths known not to exist
	accessOrder   []string // LRU tracking
	enabled       bool

	// Cache hit/miss stats
	hits   int64
	misses int64
}

type dirCacheEntry struct {
	entries  []fs.DirEntry
	cachedAt time.Time
}

type statCacheEntry struct {
	info     fs.FileInfo
	cachedAt time.Time
}

// newMetadataCache creates a new metadata cache with the given configuration.
func newMetadataCache(config CacheConfig) *metadataCache {
	if config.MaxCacheEntries == 0 {
		config.MaxCacheEntries = 1000
	}
	if config.DirCacheTTL == 0 {
		config.DirCacheTTL = 5 * time.Second
	}
	if config.StatCacheTTL == 0 {
		config.StatCacheTTL = 5 * time.Second
	}
	if config.NegativeTTL == 0 {
		config.NegativeTTL = 2 * time.Second
	}

	return &metadataCache{
		config:        config,
		dirCache:      make(map[string]*dirCacheEntry),
		statCache:     make(map[string]*statCacheEntry),
		negativeCache: make(map[string]time.Time),
		accessOrder:   make([]string, 0, config.MaxCacheEntries),
		enabled:       config.EnableCache,
	}
}

// getDirEntries retrieves cached directory entries if available and not expired.
func (c *metadataCache) getDirEntries(path string) ([]fs.DirEntry, bool) {
	if !c.enabled || c.config.DirCacheTTL == 0 {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.dirCache[path]
	if !ok {
		c.misses++
		return nil, false
	}

	// Check if expired
	if time.Since(entry.cachedAt) > c.config.DirCacheTTL {
		c.misses++
		return nil, false
	}

	c.hits++
	return entry.entries, true
}

// putDirEntries stores directory entries in the cache.
func (c *metadataCache) putDirEntries(path string, entries []fs.DirEntry) {
	if !c.enabled || c.config.DirCacheTTL == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.dirCache[path] = &dirCacheEntry{
		entries:  entries,
		cachedAt: time.Now(),
	}

	c.trackAccess(path)
	c.evictIfNeeded()
}

// getStatInfo retrieves cached file info if available and not expired.
func (c *metadataCache) getStatInfo(path string) (fs.FileInfo, bool) {
	if !c.enabled || c.config.StatCacheTTL == 0 {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.statCache[path]
	if !ok {
		c.misses++
		return nil, false
	}

	// Check if expired
	if time.Since(entry.cachedAt) > c.config.StatCacheTTL {
		c.misses++
		return nil, false
	}

	c.hits++
	return entry.info, true
}

// isNegativelyCached returns true if the path is known not to exist.
func (c *metadataCache) isNegativelyCached(path string) bool {
	if !c.enabled || c.config.NegativeTTL == 0 {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cachedAt, ok := c.negativeCache[path]
	if !ok {
		return false
	}

	if time.Since(cachedAt) > c.config.NegativeTTL {
		return false
	}

	c.hits++
	return true
}

// putNegative records that a path does not exist.
func (c *metadataCache) putNegative(path string) {
	if !c.enabled || c.config.NegativeTTL == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.negativeCache[path] = time.Now()
	c.trackAccess("neg:" + path)
	c.evictIfNeeded()
}

// putStatInfo stores file info in the cache.
func (c *metadataCache) putStatInfo(path string, info fs.FileInfo) {
	if !c.enabled || c.config.StatCacheTTL == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.statCache[path] = &statCacheEntry{
		info:     info,
		cachedAt: time.Now(),
	}

	c.trackAccess(path)
	c.evictIfNeeded()
}

// invalidate removes cache entries for a specific path and its parent directory.
// This should be called after any write operation.
func (c *metadataCache) invalidate(path string) {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Invalidate the path itself
	delete(c.dirCache, path)
	delete(c.statCache, path)
	delete(c.negativeCache, path)

	// Invalidate parent directory (since its listing has changed)
	parentPath := c.getParentPath(path)
	delete(c.dirCache, parentPath)
}

// invalidateAll clears all cache entries.
func (c *metadataCache) invalidateAll() {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.dirCache = make(map[string]*dirCacheEntry)
	c.statCache = make(map[string]*statCacheEntry)
	c.negativeCache = make(map[string]time.Time)
	c.accessOrder = c.accessOrder[:0]
}

// trackAccess tracks access order for LRU eviction.
func (c *metadataCache) trackAccess(path string) {
	// Remove if exists
	for i, p := range c.accessOrder {
		if p == path {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}

	// Add to end (most recently used)
	c.accessOrder = append(c.accessOrder, path)
}

// evictIfNeeded evicts oldest entries if cache is full.
func (c *metadataCache) evictIfNeeded() {
	totalEntries := len(c.dirCache) + len(c.statCache)
	if totalEntries <= c.config.MaxCacheEntries {
		return
	}

	// Evict oldest entries until we're under the limit
	entriesToEvict := totalEntries - c.config.MaxCacheEntries
	for i := 0; i < entriesToEvict && len(c.accessOrder) > 0; i++ {
		oldestPath := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]

		delete(c.dirCache, oldestPath)
		delete(c.statCache, oldestPath)
	}
}

// getParentPath returns the parent directory path.
func (c *metadataCache) getParentPath(path string) string {
	if path == "/" || path == "" {
		return "/"
	}

	// Find last separator
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}

	return "/"
}

// CacheStats provides statistics about cache usage.
type CacheStats struct {
	Enabled              bool
	DirCacheEntries      int
	StatCacheEntries     int
	NegativeCacheEntries int
	TotalEntries         int
	MaxEntries           int
	Hits                 int64
	Misses               int64
	HitRate              float64
}

// Stats returns cache statistics.
func (c *metadataCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Enabled:              c.enabled,
		DirCacheEntries:      len(c.dirCache),
		StatCacheEntries:     len(c.statCache),
		NegativeCacheEntries: len(c.negativeCache),
		TotalEntries:         len(c.dirCache) + len(c.statCache) + len(c.negativeCache),
		MaxEntries:           c.config.MaxCacheEntries,
		Hits:                 c.hits,
		Misses:               c.misses,
		HitRate:              hitRate,
	}
}
