//go:build integration
// +build integration

package smbfs

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"
	"time"
)

// getTestConfig returns a configuration for integration tests.
func getTestConfig(t *testing.T) *Config {
	t.Helper()

	server := os.Getenv("SMB_SERVER")
	if server == "" {
		server = "localhost"
	}

	share := os.Getenv("SMB_SHARE")
	if share == "" {
		share = "testshare"
	}

	username := os.Getenv("SMB_USERNAME")
	if username == "" {
		username = "testuser"
	}

	password := os.Getenv("SMB_PASSWORD")
	if password == "" {
		password = "testpass123"
	}

	domain := os.Getenv("SMB_DOMAIN")
	if domain == "" {
		domain = "TESTGROUP"
	}

	return &Config{
		Server:   server,
		Share:    share,
		Username: username,
		Password: password,
		Domain:   domain,
	}
}

// setupTestFS creates a test filesystem instance.
func setupTestFS(t *testing.T) *FileSystem {
	t.Helper()

	config := getTestConfig(t)
	fsys, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}

	t.Cleanup(func() {
		fsys.Close()
	})

	return fsys
}

// setupBenchFS creates a test filesystem instance for benchmarks.
func setupBenchFS(b *testing.B) *FileSystem {
	b.Helper()

	config := &Config{
		Server:   getEnvOrDefault("SMB_SERVER", "localhost"),
		Share:    getEnvOrDefault("SMB_SHARE", "testshare"),
		Username: getEnvOrDefault("SMB_USERNAME", "testuser"),
		Password: getEnvOrDefault("SMB_PASSWORD", "testpass123"),
		Domain:   getEnvOrDefault("SMB_DOMAIN", "TESTGROUP"),
	}

	fsys, err := New(config)
	if err != nil {
		b.Fatalf("Failed to create filesystem: %v", err)
	}

	b.Cleanup(func() {
		fsys.Close()
	})

	return fsys
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func TestIntegration_BasicConnection(t *testing.T) {
	fsys := setupTestFS(t)

	// Just verify we can connect and close
	if fsys == nil {
		t.Fatal("Expected filesystem instance, got nil")
	}
}

func TestIntegration_CreateAndReadFile(t *testing.T) {
	fsys := setupTestFS(t)

	testContent := []byte("Hello, Integration Test!")
	testPath := "/test_integration_file.txt"

	// Clean up any existing test file
	_ = fsys.Remove(testPath)

	// Create and write file
	file, err := fsys.Create(testPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	n, err := file.Write(testContent)
	if err != nil {
		file.Close()
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(testContent) {
		file.Close()
		t.Fatalf("Write returned %d, want %d", n, len(testContent))
	}

	err = file.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read file back
	data, err := fs.ReadFile(fsys, testPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !bytes.Equal(data, testContent) {
		t.Fatalf("Read content = %q, want %q", data, testContent)
	}

	// Clean up
	err = fsys.Remove(testPath)
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
}

func TestIntegration_StatFile(t *testing.T) {
	fsys := setupTestFS(t)

	testContent := []byte("Test content for stat")
	testPath := "/test_stat_file.txt"

	// Clean up any existing test file
	_ = fsys.Remove(testPath)

	// Create file
	file, err := fsys.Create(testPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write(testContent)
	file.Close()

	// Stat the file
	info, err := fsys.Stat(testPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Name() != "test_stat_file.txt" {
		t.Errorf("Name = %q, want %q", info.Name(), "test_stat_file.txt")
	}

	if info.Size() != int64(len(testContent)) {
		t.Errorf("Size = %d, want %d", info.Size(), len(testContent))
	}

	if info.IsDir() {
		t.Errorf("IsDir = true, want false")
	}

	// Clean up
	fsys.Remove(testPath)
}

func TestIntegration_DirectoryOperations(t *testing.T) {
	fsys := setupTestFS(t)

	testDir := "/test_integration_dir"

	// Clean up any existing test directory
	_ = fsys.RemoveAll(testDir)

	// Create directory
	err := fsys.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	// Stat the directory
	info, err := fsys.Stat(testDir)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if !info.IsDir() {
		t.Errorf("IsDir = false, want true")
	}

	// Create a file in the directory
	filePath := testDir + "/test_file.txt"
	file, err := fsys.Create(filePath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	// Read directory
	entries, err := fsys.ReadDir(testDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("ReadDir returned %d entries, want 1", len(entries))
	}

	if entries[0].Name() != "test_file.txt" {
		t.Errorf("Entry name = %q, want %q", entries[0].Name(), "test_file.txt")
	}

	// Clean up
	err = fsys.RemoveAll(testDir)
	if err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	// Verify removal
	_, err = fsys.Stat(testDir)
	if !os.IsNotExist(err) {
		t.Errorf("Directory still exists after RemoveAll")
	}
}

func TestIntegration_MkdirAll(t *testing.T) {
	fsys := setupTestFS(t)

	testPath := "/test_mkdir_all/sub1/sub2/sub3"

	// Clean up any existing test directories
	_ = fsys.RemoveAll("/test_mkdir_all")

	// Create nested directories
	err := fsys.MkdirAll(testPath, 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Verify each level exists
	levels := []string{
		"/test_mkdir_all",
		"/test_mkdir_all/sub1",
		"/test_mkdir_all/sub1/sub2",
		"/test_mkdir_all/sub1/sub2/sub3",
	}

	for _, path := range levels {
		info, err := fsys.Stat(path)
		if err != nil {
			t.Errorf("Stat(%q) failed: %v", path, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("Stat(%q).IsDir() = false, want true", path)
		}
	}

	// Clean up
	fsys.RemoveAll("/test_mkdir_all")
}

func TestIntegration_Rename(t *testing.T) {
	fsys := setupTestFS(t)

	oldPath := "/test_rename_old.txt"
	newPath := "/test_rename_new.txt"

	// Clean up any existing test files
	_ = fsys.Remove(oldPath)
	_ = fsys.Remove(newPath)

	// Create file
	testContent := []byte("Rename test content")
	file, err := fsys.Create(oldPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write(testContent)
	file.Close()

	// Rename
	err = fsys.Rename(oldPath, newPath)
	if err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	// Verify old path doesn't exist
	_, err = fsys.Stat(oldPath)
	if !os.IsNotExist(err) {
		t.Errorf("Old path still exists after rename")
	}

	// Verify new path exists with same content
	data, err := fs.ReadFile(fsys, newPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !bytes.Equal(data, testContent) {
		t.Errorf("Content mismatch after rename")
	}

	// Clean up
	fsys.Remove(newPath)
}

func TestIntegration_Chtimes(t *testing.T) {
	fsys := setupTestFS(t)

	testPath := "/test_chtimes_file.txt"

	// Clean up any existing test file
	_ = fsys.Remove(testPath)

	// Create file
	file, err := fsys.Create(testPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("chtimes test"))
	file.Close()

	// Set specific times
	atime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mtime := time.Date(2024, 6, 15, 15, 30, 0, 0, time.UTC)

	err = fsys.Chtimes(testPath, atime, mtime)
	if err != nil {
		t.Fatalf("Chtimes failed: %v", err)
	}

	// Verify modification time changed
	info, err := fsys.Stat(testPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	// Check modification time (allowing for some precision loss)
	modTime := info.ModTime().UTC()
	diff := modTime.Sub(mtime)
	if diff < 0 {
		diff = -diff
	}

	// Allow up to 2 seconds difference (SMB may not preserve exact times)
	if diff > 2*time.Second {
		t.Errorf("ModTime = %v, want ~%v (diff: %v)", modTime, mtime, diff)
	}

	// Clean up
	fsys.Remove(testPath)
}

func TestIntegration_Chmod(t *testing.T) {
	fsys := setupTestFS(t)

	testPath := "/test_chmod_file.txt"

	// Clean up any existing test file
	_ = fsys.Remove(testPath)

	// Create file
	file, err := fsys.Create(testPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("chmod test"))
	file.Close()

	// Change permissions
	err = fsys.Chmod(testPath, 0644)
	if err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	// Verify (note: SMB may not preserve exact Unix permissions)
	info, err := fsys.Stat(testPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	t.Logf("File mode after Chmod: %v", info.Mode())

	// Clean up
	fsys.Remove(testPath)
}

func TestIntegration_LargeFile(t *testing.T) {
	fsys := setupTestFS(t)

	testPath := "/test_large_file.bin"

	// Clean up any existing test file
	_ = fsys.Remove(testPath)

	// Create a 10MB file
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Write large file
	file, err := fsys.Create(testPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	written := 0
	chunkSize := 64 * 1024 // 64KB chunks
	for written < size {
		end := written + chunkSize
		if end > size {
			end = size
		}

		n, err := file.Write(data[written:end])
		if err != nil {
			file.Close()
			t.Fatalf("Write failed at offset %d: %v", written, err)
		}
		written += n
	}

	file.Close()

	// Verify file size
	info, err := fsys.Stat(testPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Size() != int64(size) {
		t.Errorf("File size = %d, want %d", info.Size(), size)
	}

	// Read and verify content
	readFile, err := fsys.Open(testPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer readFile.Close()

	readData, err := io.ReadAll(readFile)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(readData) != size {
		t.Errorf("Read size = %d, want %d", len(readData), size)
	}

	// Verify first and last kilobytes match
	if !bytes.Equal(readData[:1024], data[:1024]) {
		t.Errorf("First 1KB doesn't match")
	}

	if !bytes.Equal(readData[size-1024:], data[size-1024:]) {
		t.Errorf("Last 1KB doesn't match")
	}

	// Clean up
	fsys.Remove(testPath)
}

func TestIntegration_ConcurrentOperations(t *testing.T) {
	fsys := setupTestFS(t)

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			testPath := fmt.Sprintf("/test_concurrent_%d.txt", id)
			testContent := []byte(fmt.Sprintf("Concurrent test %d", id))

			// Clean up
			defer fsys.Remove(testPath)

			// Create and write
			file, err := fsys.Create(testPath)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			_, err = file.Write(testContent)
			if err != nil {
				file.Close()
				errors <- err
				done <- false
				return
			}
			file.Close()

			// Read back
			data, err := fs.ReadFile(fsys, testPath)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			if !bytes.Equal(data, testContent) {
				errors <- fmt.Errorf("content mismatch for goroutine %d", id)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errors:
			t.Errorf("Goroutine error: %v", err)
		case success := <-done:
			if success {
				successCount++
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}

	if successCount != numGoroutines {
		t.Errorf("Only %d/%d goroutines succeeded", successCount, numGoroutines)
	}
}
