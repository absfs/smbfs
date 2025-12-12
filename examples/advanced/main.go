package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/absfs/smbfs"
)

func main() {
	// Example: Advanced configuration with retry logic and logging

	// Create a custom logger
	logger := log.New(os.Stdout, "[SMBFS] ", log.LstdFlags)

	// Configure custom retry policy for unreliable networks
	retryPolicy := &smbfs.RetryPolicy{
		MaxAttempts:  5,                      // Try up to 5 times
		InitialDelay: 200 * time.Millisecond, // Start with 200ms delay
		MaxDelay:     10 * time.Second,       // Cap at 10 seconds
		Multiplier:   2.0,                    // Double delay each retry
	}

	// Create filesystem with advanced configuration
	fsys, err := smbfs.New(&smbfs.Config{
		Server:   os.Getenv("SMB_SERVER"),
		Share:    os.Getenv("SMB_SHARE"),
		Username: os.Getenv("SMB_USERNAME"),
		Password: os.Getenv("SMB_PASSWORD"),
		Domain:   os.Getenv("SMB_DOMAIN"),

		// Connection pool settings
		MaxIdle:     10,
		MaxOpen:     20,
		IdleTimeout: 10 * time.Minute,
		ConnTimeout: 30 * time.Second,

		// Enable retry and logging
		RetryPolicy: retryPolicy,
		Logger:      logger,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	logger.Println("Connected to SMB share successfully")

	// Example 1: File operations with automatic retry
	logger.Println("\n=== Example 1: Creating and writing a file ===")
	file, err := fsys.Create("/test/demo.txt")
	if err != nil {
		logger.Printf("Error creating file: %v", err)
	} else {
		_, err = file.Write([]byte("Hello from smbfs with retry support!\n"))
		file.Close()
		if err != nil {
			logger.Printf("Error writing file: %v", err)
		} else {
			logger.Println("File created and written successfully")
		}
	}

	// Example 2: Setting file times (Chtimes - newly implemented)
	logger.Println("\n=== Example 2: Setting file modification time ===")
	now := time.Now()
	pastTime := now.Add(-24 * time.Hour) // 24 hours ago
	err = fsys.Chtimes("/test/demo.txt", pastTime, pastTime)
	if err != nil {
		logger.Printf("Error setting file times: %v", err)
	} else {
		logger.Println("File times set successfully")

		// Verify the change
		info, err := fsys.Stat("/test/demo.txt")
		if err == nil {
			logger.Printf("Modified time: %s", info.ModTime())
		}
	}

	// Example 3: Changing file permissions (Chmod - newly implemented)
	logger.Println("\n=== Example 3: Changing file permissions ===")
	err = fsys.Chmod("/test/demo.txt", 0644)
	if err != nil {
		logger.Printf("Error changing permissions: %v", err)
	} else {
		logger.Println("File permissions changed successfully")

		// Verify the change
		info, err := fsys.Stat("/test/demo.txt")
		if err == nil {
			logger.Printf("File mode: %s", info.Mode())
		}
	}

	// Example 4: Reading directory with retry
	logger.Println("\n=== Example 4: Reading directory ===")
	entries, err := fsys.ReadDir("/test")
	if err != nil {
		logger.Printf("Error reading directory: %v", err)
	} else {
		logger.Printf("Found %d entries in /test:", len(entries))
		for _, entry := range entries {
			info, _ := entry.Info()
			logger.Printf("  - %s (%d bytes, mode: %s)",
				entry.Name(),
				info.Size(),
				info.Mode())
		}
	}

	// Example 5: Demonstrating retry behavior with connection issues
	logger.Println("\n=== Example 5: Retry behavior demo ===")
	logger.Println("The following operations will automatically retry on transient failures")
	logger.Println("(connection timeouts, pool exhaustion, etc.)")

	// This will retry automatically if there are connection issues
	for i := 1; i <= 3; i++ {
		logger.Printf("\nAttempt %d: Reading file", i)
		data, err := fsys.ReadFile("/test/demo.txt")
		if err != nil {
			logger.Printf("  Error: %v (will retry if retryable)", err)
		} else {
			logger.Printf("  Success! Read %d bytes: %s", len(data), string(data))
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Example 6: Connection string parsing
	logger.Println("\n=== Example 6: Connection string parsing ===")
	connStr := fmt.Sprintf("smb://%s:%s@%s/%s",
		os.Getenv("SMB_USERNAME"),
		os.Getenv("SMB_PASSWORD"),
		os.Getenv("SMB_SERVER"),
		os.Getenv("SMB_SHARE"),
	)

	cfg, err := smbfs.ParseConnectionString(connStr)
	if err != nil {
		logger.Printf("Error parsing connection string: %v", err)
	} else {
		logger.Printf("Parsed connection string:")
		logger.Printf("  Server: %s", cfg.Server)
		logger.Printf("  Share: %s", cfg.Share)
		logger.Printf("  Username: %s", cfg.Username)
		logger.Printf("  Port: %d", cfg.Port)
	}

	logger.Println("\n=== Demo complete ===")
}
