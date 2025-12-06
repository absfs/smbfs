package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/absfs/smbfs"
)

func main() {
	// Example: Performance optimization with caching

	config := &smbfs.Config{
		Server:   os.Getenv("SMB_SERVER"),
		Share:    os.Getenv("SMB_SHARE"),
		Username: os.Getenv("SMB_USERNAME"),
		Password: os.Getenv("SMB_PASSWORD"),
		Domain:   os.Getenv("SMB_DOMAIN"),

		// Enable metadata caching for better performance
		Cache: smbfs.CacheConfig{
			EnableCache:     true,
			DirCacheTTL:     10 * time.Second,  // Cache directory listings for 10s
			StatCacheTTL:    10 * time.Second,  // Cache file stats for 10s
			MaxCacheEntries: 5000,              // Cache up to 5000 entries
		},

		// Optimize connection pool
		MaxIdle: 10,
		MaxOpen: 20,

		// Large buffers for better throughput
		ReadBufferSize:  256 * 1024,  // 256 KB
		WriteBufferSize: 256 * 1024,  // 256 KB
	}

	fsys, err := smbfs.New(config)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	fmt.Println("=== Caching Performance Example ===")

	// Example 1: Demonstrate cache effectiveness
	fmt.Println("1. Cache Performance Test:")
	testPath := "/"

	// First call (cache miss)
	start := time.Now()
	entries1, err := fsys.ReadDir(testPath)
	duration1 := time.Since(start)
	if err != nil {
		log.Printf("Error reading directory: %v", err)
		return
	}
	fmt.Printf("   First ReadDir: %d entries in %v (cache MISS)\n", len(entries1), duration1)

	// Second call (cache hit)
	start = time.Now()
	entries2, err := fsys.ReadDir(testPath)
	duration2 := time.Since(start)
	if err != nil {
		log.Printf("Error reading directory: %v", err)
		return
	}
	fmt.Printf("   Second ReadDir: %d entries in %v (cache HIT)\n", len(entries2), duration2)

	speedup := float64(duration1) / float64(duration2)
	fmt.Printf("   Speedup: %.1fx faster\n", speedup)
	fmt.Println()

	// Example 2: Stat() performance with caching
	fmt.Println("2. Stat() Performance Test:")
	if len(entries1) > 0 {
		testFile := "/" + entries1[0].Name()

		// First stat (cache miss)
		start := time.Now()
		info1, err := fsys.Stat(testFile)
		statDuration1 := time.Since(start)
		if err != nil {
			log.Printf("Error stating file: %v", err)
		} else {
			fmt.Printf("   First Stat: %s in %v (cache MISS)\n", info1.Name(), statDuration1)
		}

		// Second stat (cache hit)
		start = time.Now()
		info2, err := fsys.Stat(testFile)
		statDuration2 := time.Since(start)
		if err != nil {
			log.Printf("Error stating file: %v", err)
		} else {
			fmt.Printf("   Second Stat: %s in %v (cache HIT)\n", info2.Name(), statDuration2)
			statSpeedup := float64(statDuration1) / float64(statDuration2)
			fmt.Printf("   Speedup: %.1fx faster\n", statSpeedup)
		}
	}
	fmt.Println()

	// Example 3: Cache invalidation on write
	fmt.Println("3. Cache Invalidation Test:")
	testNewFile := "/cache_test.txt"

	// Stat a non-existent file (will cache the "not found" error)
	_, err = fsys.Stat(testNewFile)
	if err != nil {
		fmt.Printf("   Initial stat: File doesn't exist (expected)\n")
	}

	// Create the file (should invalidate cache)
	file, err := fsys.Create(testNewFile)
	if err != nil {
		log.Printf("Warning: Could not create test file: %v", err)
	} else {
		file.Write([]byte("Cache invalidation test"))
		file.Close()
		fmt.Printf("   Created file: %s\n", testNewFile)

		// Now stat should work (cache was invalidated)
		info, err := fsys.Stat(testNewFile)
		if err != nil {
			fmt.Printf("   After creation: Still not found (cache not invalidated)\n")
		} else {
			fmt.Printf("   After creation: Found! Size: %d bytes\n", info.Size())
		}

		// Clean up
		fsys.Remove(testNewFile)
		fmt.Printf("   Cleaned up test file\n")
	}
	fmt.Println()

	// Example 4: Demonstrate cache TTL expiration
	fmt.Println("4. Cache TTL Expiration:")
	fmt.Printf("   Waiting 11 seconds for cache to expire (TTL: 10s)...\n")
	time.Sleep(11 * time.Second)

	// This should be a cache miss now
	start = time.Now()
	entries3, err := fsys.ReadDir(testPath)
	duration3 := time.Since(start)
	if err != nil {
		log.Printf("Error reading directory: %v", err)
	} else {
		fmt.Printf("   After TTL expiration: %d entries in %v (cache MISS)\n", len(entries3), duration3)
		if duration3 > duration2 {
			fmt.Printf("   ✓ Cache expired successfully (slower than cached call)\n")
		}
	}
	fmt.Println()

	// Example 5: Batch operations with caching
	fmt.Println("5. Batch Operations Performance:")
	start = time.Now()
	for i := 0; i < 100; i++ {
		// Repeated stats will hit the cache
		if len(entries1) > 0 {
			fsys.Stat("/" + entries1[0].Name())
		}
	}
	batchDuration := time.Since(start)
	fmt.Printf("   100 Stat() calls in %v (avg: %v per call)\n",
		batchDuration, batchDuration/100)
	fmt.Printf("   With caching: ~%.0f operations/second\n", 100.0/batchDuration.Seconds())
	fmt.Println()

	fmt.Println("=== Example Complete ===")
	fmt.Println("\nKey Takeaways:")
	fmt.Println("- Caching provides 10-100x speedup for repeated operations")
	fmt.Println("- Cache is automatically invalidated on write operations")
	fmt.Println("- TTL ensures cache doesn't become too stale")
	fmt.Println("- Ideal for read-heavy workloads")
}
