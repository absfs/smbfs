package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/absfs/memfs"
	"github.com/absfs/smbfs"
)

func main() {
	// Command line flags
	port := flag.Int("port", 4450, "Port to listen on (default 4450 to avoid needing root)")
	shareName := flag.String("share", "myshare", "Share name")
	hostname := flag.String("host", "0.0.0.0", "Hostname/IP to bind to")
	readOnly := flag.Bool("readonly", false, "Export share as read-only")
	debug := flag.Bool("debug", false, "Enable debug logging")
	smb2Only := flag.Bool("smb2", false, "Limit to SMB 2.x (disable SMB 3.1.1)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SMB Server Example - Serve an in-memory filesystem via SMB\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample Usage:\n")
		fmt.Fprintf(os.Stderr, "  # Run the server\n")
		fmt.Fprintf(os.Stderr, "  go run main.go -port 4450 -share myshare\n\n")
		fmt.Fprintf(os.Stderr, "Client Connection Examples:\n")
		fmt.Fprintf(os.Stderr, "  # macOS/Linux using smbclient\n")
		fmt.Fprintf(os.Stderr, "  smbclient //localhost/myshare -p 4450 -U guest -N\n\n")
		fmt.Fprintf(os.Stderr, "  # macOS Finder\n")
		fmt.Fprintf(os.Stderr, "  smb://guest@localhost:4450/myshare\n\n")
		fmt.Fprintf(os.Stderr, "  # Windows (PowerShell as Administrator)\n")
		fmt.Fprintf(os.Stderr, "  net use X: \\\\localhost@4450\\myshare /user:guest \"\"\n\n")
		fmt.Fprintf(os.Stderr, "  # Linux mount\n")
		fmt.Fprintf(os.Stderr, "  sudo mount -t cifs //localhost/myshare /mnt/share -o port=4450,guest,username=guest\n\n")
	}

	flag.Parse()

	log.Printf("[INFO] Starting SMB server example...")

	// Step 1: Create an in-memory filesystem
	log.Printf("[INFO] Creating in-memory filesystem...")
	fs, err := memfs.NewFS()
	if err != nil {
		log.Fatalf("[ERROR] Failed to create filesystem: %v", err)
	}

	// Step 2: Populate the filesystem with sample files and directories
	log.Printf("[INFO] Creating sample files and directories...")
	if err := populateFilesystem(fs); err != nil {
		log.Fatalf("[ERROR] Failed to populate filesystem: %v", err)
	}

	// Step 3: Configure server options
	log.Printf("[INFO] Configuring SMB server on %s:%d...", *hostname, *port)
	serverOpts := smbfs.ServerOptions{
		Port:            *port,
		Hostname:        *hostname,
		Debug:           *debug,
		ServerName:      "SMBSERVER",
		AllowGuest:      true, // Allow guest access
		SigningRequired: true, // Required for Windows 11 24H2 compatibility
		// Add a test user for Windows clients that don't support guest
		Users: map[string]string{
			"testuser": "testpass",
			"admin":    "admin",
		},
	}

	// Optionally limit to SMB 2.x (avoid SMB 3.1.1 negotiate context issues)
	if *smb2Only {
		serverOpts.MaxDialect = smbfs.SMB2_1
		log.Printf("[INFO] Limiting to SMB 2.x dialects")
	}

	// Step 4: Create the SMB server
	server, err := smbfs.NewServer(serverOpts)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create server: %v", err)
	}

	// Step 5: Configure and add a share
	log.Printf("[INFO] Adding share '%s'...", *shareName)
	shareOpts := smbfs.ShareOptions{
		ShareName:  *shareName,
		SharePath:  "/",
		ReadOnly:   *readOnly,
		AllowGuest: true, // Allow anonymous access
		Comment:    "Example in-memory share",
	}

	if err := server.AddShare(fs, shareOpts); err != nil {
		log.Fatalf("[ERROR] Failed to add share: %v", err)
	}

	// Step 6: Start the server
	log.Printf("[INFO] Starting SMB server...")
	if err := server.Listen(); err != nil {
		log.Fatalf("[ERROR] Failed to start server: %v", err)
	}

	// Print connection information
	printConnectionInfo(*hostname, *port, *shareName, *readOnly)

	// Step 7: Set up graceful shutdown on SIGINT/SIGTERM or stop file
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stop file path - creating this file triggers shutdown
	stopFile := "/tmp/smb-server.stop"
	// Remove any existing stop file on startup
	os.Remove(stopFile)

	// Wait for shutdown signal
	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Received signal %v, shutting down gracefully...", sig)
		cancel()
	}()

	// Watch for stop file (allows unprivileged stop)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if _, err := os.Stat(stopFile); err == nil {
					log.Printf("[INFO] Stop file detected (%s), shutting down...", stopFile)
					os.Remove(stopFile)
					cancel()
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	// Block until shutdown signal
	log.Printf("[INFO] SMB server is running. Press Ctrl+C or 'touch %s' to stop.", stopFile)
	<-ctx.Done()

	// Graceful shutdown
	log.Printf("[INFO] Stopping SMB server...")
	if err := server.Stop(); err != nil {
		log.Printf("[ERROR] Error during shutdown: %v", err)
	}

	log.Printf("[INFO] SMB server stopped successfully")
}

// populateFilesystem creates sample files and directories in the filesystem
func populateFilesystem(fs *memfs.FileSystem) error {
	// Create directory structure
	dirs := []string{
		"/documents",
		"/documents/reports",
		"/documents/presentations",
		"/photos",
		"/photos/vacation",
		"/music",
	}

	for _, dir := range dirs {
		if err := fs.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create sample files with content
	files := map[string]string{
		"/README.txt": `Welcome to the SMB Server Example!

This is an in-memory filesystem served via SMB protocol.

Features:
- Full read/write support (unless running with -readonly flag)
- Standard SMB2/SMB3 protocol compatibility
- Works with Windows, macOS, and Linux clients
- Backed by absfs/memfs (in-memory filesystem)

Try creating, editing, and deleting files to see it in action!

Generated: ` + time.Now().Format(time.RFC3339),

		"/documents/report.txt": `Annual Report 2024

Executive Summary:
This is a sample document demonstrating file serving via SMB.

The filesystem is entirely in-memory, so changes will be lost
when the server stops.
`,

		"/documents/reports/q1-2024.txt": `Q1 2024 Report

Revenue: $1,234,567
Expenses: $987,654
Profit: $246,913

Status: Preliminary
`,

		"/documents/presentations/demo.txt": `Product Demo Notes

1. Introduction
2. Key Features
3. Live Demonstration
4. Q&A Session
`,

		"/photos/README.txt": `Photos Directory

This directory can contain image files.
In this demo, we're using text files for simplicity.
`,

		"/photos/vacation/itinerary.txt": `Vacation Itinerary

Day 1: Beach
Day 2: Hiking
Day 3: City Tour
Day 4: Relaxation
`,

		"/music/playlist.txt": `Favorite Playlist

1. Song One
2. Song Two
3. Song Three
4. Song Four
5. Song Five
`,
	}

	for filepath, content := range files {
		file, err := fs.Create(filepath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", filepath, err)
		}

		if _, err := file.Write([]byte(content)); err != nil {
			file.Close()
			return fmt.Errorf("failed to write to file %s: %w", filepath, err)
		}

		if err := file.Close(); err != nil {
			return fmt.Errorf("failed to close file %s: %w", filepath, err)
		}

		// Set a reasonable modification time
		if err := fs.Chtimes(filepath, time.Now(), time.Now()); err != nil {
			return fmt.Errorf("failed to set times for %s: %w", filepath, err)
		}
	}

	// Create an empty directory to show directory support
	if err := fs.MkdirAll("/empty", 0755); err != nil {
		return fmt.Errorf("failed to create empty directory: %w", err)
	}

	log.Printf("[INFO] Created %d sample files in directory structure", len(files))
	return nil
}

// printConnectionInfo displays information about how to connect to the server
func printConnectionInfo(hostname string, port int, shareName string, readOnly bool) {
	fmt.Println("\n" + strings("=", 70))
	fmt.Println("  SMB SERVER READY")
	fmt.Println(strings("=", 70))
	fmt.Printf("\nServer Address: %s:%d\n", hostname, port)
	fmt.Printf("Share Name:     %s\n", shareName)
	fmt.Printf("Access Mode:    %s\n", accessMode(readOnly))
	fmt.Printf("Authentication: Guest (anonymous)\n")

	fmt.Println("\n" + strings("-", 70))
	fmt.Println("  CONNECTION EXAMPLES")
	fmt.Println(strings("-", 70))

	// Determine the hostname to use in examples
	connectHost := hostname
	if hostname == "0.0.0.0" || hostname == "" {
		connectHost = "localhost"
	}

	// smbclient (Linux/macOS)
	fmt.Println("\n1. Using smbclient (Linux/macOS):")
	fmt.Printf("   smbclient //%s/%s -p %d -U guest -N\n", connectHost, shareName, port)

	// macOS Finder
	fmt.Println("\n2. Using macOS Finder:")
	fmt.Printf("   Command-K in Finder, then enter:\n")
	fmt.Printf("   smb://guest@%s:%d/%s\n", connectHost, port, shareName)

	// Windows net use
	fmt.Println("\n3. Using Windows (PowerShell as Administrator):")
	fmt.Printf("   net use X: \\\\%s@%d\\%s /user:guest \"\"\n", connectHost, port, shareName)

	// Linux mount
	fmt.Println("\n4. Using Linux mount:")
	fmt.Printf("   sudo mount -t cifs //%s/%s /mnt/share -o port=%d,guest,username=guest\n",
		connectHost, shareName, port)

	// smbfs client example
	fmt.Println("\n5. Using absfs/smbfs (Go code):")
	fmt.Printf("   fs, err := smbfs.New(&smbfs.Config{\n")
	fmt.Printf("       Server:      \"%s\",\n", connectHost)
	fmt.Printf("       Port:        %d,\n", port)
	fmt.Printf("       Share:       \"%s\",\n", shareName)
	fmt.Printf("       GuestAccess: true,\n")
	fmt.Printf("   })\n")

	fmt.Println("\n" + strings("=", 70))
	fmt.Println()
}

// strings creates a string by repeating s n times
func strings(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

// accessMode returns a human-readable access mode string
func accessMode(readOnly bool) string {
	if readOnly {
		return "Read-Only"
	}
	return "Read-Write"
}
