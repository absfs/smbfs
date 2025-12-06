package smbfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"testing"
	"time"
)

// testConfig returns a valid config for testing.
func testConfig() *Config {
	return &Config{
		Server:      "test-server",
		Share:       "testshare",
		Username:    "testuser",
		Password:    "testpass",
		MaxIdle:     5,
		MaxOpen:     10,
		IdleTimeout: 5 * time.Minute,
		ConnTimeout: 30 * time.Second,
	}
}

// setupMockFS creates a FileSystem with a mock backend for testing.
func setupMockFS(t *testing.T) (*FileSystem, *MockSMBBackend, *MockConnectionFactory) {
	t.Helper()

	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()

	fsys, err := NewWithFactory(config, factory)
	if err != nil {
		t.Fatalf("NewWithFactory() error = %v", err)
	}

	return fsys, backend, factory
}

// =============================================================================
// Connection Pool Unit Tests
// =============================================================================

func TestConnectionPool_GetAndPut(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("pool.get() error = %v", err)
	}
	if conn == nil {
		t.Fatal("pool.get() returned nil connection")
	}

	stats := pool.Stats()
	if stats.ActiveConnections != 1 {
		t.Errorf("ActiveConnections = %d, want 1", stats.ActiveConnections)
	}

	// Return connection
	pool.put(conn)

	stats = pool.Stats()
	if stats.IdleConnections != 1 {
		t.Errorf("IdleConnections = %d, want 1", stats.IdleConnections)
	}
}

func TestConnectionPool_ConnectionReuse(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Get and return a connection
	conn1, _ := pool.get(ctx)
	pool.put(conn1)

	// Get again - should reuse
	conn2, _ := pool.get(ctx)
	pool.put(conn2)

	// Should be the same connection
	if conn1 != conn2 {
		t.Error("Connection not reused from pool")
	}

	if factory.ConnectionsMade() != 1 {
		t.Errorf("ConnectionsMade = %d, want 1", factory.ConnectionsMade())
	}
}

func TestConnectionPool_MaxOpenLimit(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.MaxOpen = 2
	config.ConnTimeout = 50 * time.Millisecond
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Get max connections
	conn1, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("First get() error = %v", err)
	}
	conn2, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Second get() error = %v", err)
	}

	// Third get should timeout (pool exhausted)
	_, err = pool.get(ctx)
	if err != ErrPoolExhausted {
		t.Errorf("Expected ErrPoolExhausted, got %v", err)
	}

	// Clean up
	pool.put(conn1)
	pool.put(conn2)
}

func TestConnectionPool_WaiterGetsConnection(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.MaxOpen = 1
	config.ConnTimeout = 5 * time.Second
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Get the only connection
	conn1, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("First get() error = %v", err)
	}

	// Start a goroutine waiting for connection
	gotConn := make(chan *pooledConn, 1)
	go func() {
		conn, err := pool.get(ctx)
		if err == nil {
			gotConn <- conn
		}
	}()

	// Give goroutine time to start waiting
	time.Sleep(50 * time.Millisecond)

	// Return connection - waiting goroutine should get it
	pool.put(conn1)

	select {
	case conn := <-gotConn:
		if conn == nil {
			t.Error("Waiter received nil connection")
		}
		pool.put(conn)
	case <-time.After(1 * time.Second):
		t.Error("Waiter did not receive connection in time")
	}
}

func TestConnectionPool_Close(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	pool := newConnectionPoolWithFactory(config, factory)

	ctx := context.Background()

	// Create some connections
	conn1, _ := pool.get(ctx)
	conn2, _ := pool.get(ctx)
	pool.put(conn1)
	pool.put(conn2)

	// Close pool
	pool.Close()

	stats := pool.Stats()
	if !stats.IsClosed {
		t.Error("Pool should be closed")
	}

	// Get should fail after close
	_, err := pool.get(ctx)
	if err != ErrConnectionClosed {
		t.Errorf("Expected ErrConnectionClosed after close, got %v", err)
	}
}

func TestConnectionPool_ContextCancellation(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.MaxOpen = 1
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Take the only connection
	conn, _ := pool.get(ctx)

	// Try to get with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := pool.get(cancelCtx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}

	pool.put(conn)
}

func TestConnectionPool_Cleanup(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.IdleTimeout = 50 * time.Millisecond
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()

	// Create and release a connection
	conn, _ := pool.get(ctx)
	pool.put(conn)

	stats := pool.Stats()
	if stats.IdleConnections != 1 {
		t.Errorf("IdleConnections = %d, want 1", stats.IdleConnections)
	}

	// Wait for idle timeout and run cleanup
	time.Sleep(100 * time.Millisecond)
	pool.cleanup()

	stats = pool.Stats()
	if stats.IdleConnections != 0 {
		t.Errorf("IdleConnections after cleanup = %d, want 0", stats.IdleConnections)
	}
}

func TestConnectionPool_ConcurrentAccess(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.MaxOpen = 5
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	// Spawn 20 goroutines each getting and putting connections
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				conn, err := pool.get(ctx)
				if err != nil {
					errCh <- err
					return
				}
				time.Sleep(time.Millisecond) // Simulate work
				pool.put(conn)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// =============================================================================
// File Operations Unit Tests
// =============================================================================

func TestFileSystem_OpenFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	// Add test file
	backend.AddFile("/test.txt", []byte("Hello, World!"), 0644)

	// Open existing file
	f, err := fsys.Open("/test.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	// Read content
	content := make([]byte, 100)
	n, err := f.Read(content)
	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}

	if string(content[:n]) != "Hello, World!" {
		t.Errorf("Read() = %q, want %q", content[:n], "Hello, World!")
	}
}

func TestFileSystem_OpenFile_NotExists(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	_, err := fsys.Open("/nonexistent.txt")
	if err == nil {
		t.Error("Open() expected error for nonexistent file, got nil")
	}
}

func TestFileSystem_Create(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	// Create new file
	f, err := fsys.Create("/newfile.txt")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Write content
	content := []byte("New file content")
	n, err := f.Write(content)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(content) {
		t.Errorf("Write() = %d bytes, want %d", n, len(content))
	}

	f.Close()

	// Verify file exists
	if !backend.FileExists("/newfile.txt") {
		t.Error("File not created in backend")
	}

	// Verify content
	savedContent, ok := backend.GetFile("/newfile.txt")
	if !ok {
		t.Fatal("File not found in backend")
	}
	if string(savedContent) != string(content) {
		t.Errorf("Saved content = %q, want %q", savedContent, content)
	}
}

func TestFile_ReadWrite(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/rw.txt", []byte("initial"), 0644)

	// Open for read/write
	f, err := fsys.OpenFile("/rw.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	// Read initial content
	buf := make([]byte, 100)
	n, _ := f.Read(buf)
	if string(buf[:n]) != "initial" {
		t.Errorf("Initial Read() = %q, want %q", buf[:n], "initial")
	}
}

func TestFile_Seek(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/seek.txt", []byte("0123456789"), 0644)

	f, err := fsys.OpenFile("/seek.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	// Seek to middle
	smbFile := f.(*File)
	pos, err := smbFile.Seek(5, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek() error = %v", err)
	}
	if pos != 5 {
		t.Errorf("Seek() position = %d, want 5", pos)
	}

	// Read from current position
	buf := make([]byte, 5)
	n, _ := smbFile.Read(buf)
	if string(buf[:n]) != "56789" {
		t.Errorf("Read after seek = %q, want %q", buf[:n], "56789")
	}
}

func TestFile_Close(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/close.txt", []byte("test"), 0644)

	f, _ := fsys.Open("/close.txt")
	f.Close()

	// Operations after close should fail
	file := f.(*File)
	_, err := file.Read(make([]byte, 10))
	if err != fs.ErrClosed {
		t.Errorf("Read after close expected fs.ErrClosed, got %v", err)
	}
}

func TestFile_DoubleClose(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/dblclose.txt", []byte("test"), 0644)

	f, _ := fsys.Open("/dblclose.txt")
	f.Close()

	// Second close should be idempotent
	err := f.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v, want nil", err)
	}
}

// =============================================================================
// Directory Operations Unit Tests
// =============================================================================

func TestFileSystem_Mkdir(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	err := fsys.Mkdir("/newdir", 0755)
	if err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	// Verify directory exists
	if !backend.FileExists("/newdir") {
		t.Error("Directory not created in backend")
	}
}

func TestFileSystem_MkdirAll(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	err := fsys.MkdirAll("/a/b/c/d", 0755)
	if err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Verify all directories exist
	for _, dir := range []string{"/a", "/a/b", "/a/b/c", "/a/b/c/d"} {
		if !backend.FileExists(dir) {
			t.Errorf("Directory %s not created", dir)
		}
	}
}

func TestFileSystem_ReadDir(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	// Create directory structure
	backend.AddDir("/testdir", 0755)
	backend.AddFile("/testdir/file1.txt", []byte("1"), 0644)
	backend.AddFile("/testdir/file2.txt", []byte("2"), 0644)
	backend.AddDir("/testdir/subdir", 0755)

	entries, err := fsys.ReadDir("/testdir")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("ReadDir() returned %d entries, want 3", len(entries))
	}
}

func TestFileSystem_Remove(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/todelete.txt", []byte("delete me"), 0644)

	err := fsys.Remove("/todelete.txt")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	if backend.FileExists("/todelete.txt") {
		t.Error("File still exists after Remove()")
	}
}

func TestFileSystem_RemoveAll(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	// Create structure
	backend.AddDir("/rmall", 0755)
	backend.AddFile("/rmall/file1.txt", []byte("1"), 0644)
	backend.AddDir("/rmall/sub", 0755)
	backend.AddFile("/rmall/sub/file2.txt", []byte("2"), 0644)

	err := fsys.RemoveAll("/rmall")
	if err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	// Verify all removed
	for _, path := range []string{"/rmall", "/rmall/file1.txt", "/rmall/sub", "/rmall/sub/file2.txt"} {
		if backend.FileExists(path) {
			t.Errorf("Path %s still exists after RemoveAll()", path)
		}
	}
}

func TestFileSystem_Rename(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/oldname.txt", []byte("content"), 0644)

	err := fsys.Rename("/oldname.txt", "/newname.txt")
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}

	if backend.FileExists("/oldname.txt") {
		t.Error("Old file still exists")
	}
	if !backend.FileExists("/newname.txt") {
		t.Error("New file does not exist")
	}

	// Verify content preserved
	content, _ := backend.GetFile("/newname.txt")
	if string(content) != "content" {
		t.Errorf("Content after rename = %q, want %q", content, "content")
	}
}

// =============================================================================
// Metadata Operations Unit Tests
// =============================================================================

func TestFileSystem_Stat(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	content := []byte("test content")
	backend.AddFile("/stat.txt", content, 0644)

	info, err := fsys.Stat("/stat.txt")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Name() != "stat.txt" {
		t.Errorf("Name() = %q, want %q", info.Name(), "stat.txt")
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("Size() = %d, want %d", info.Size(), len(content))
	}
	if info.IsDir() {
		t.Error("IsDir() = true, want false")
	}
}

func TestFileSystem_Stat_Directory(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/statdir", 0755)

	info, err := fsys.Stat("/statdir")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if !info.IsDir() {
		t.Error("IsDir() = false, want true")
	}
}

func TestFileSystem_Chmod(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/chmod.txt", []byte("test"), 0644)

	err := fsys.Chmod("/chmod.txt", 0755)
	if err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	// Verify mode changed
	info, _ := fsys.Stat("/chmod.txt")
	if info.Mode().Perm() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode().Perm(), 0755)
	}
}

func TestFileSystem_Chtimes(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/chtimes.txt", []byte("test"), 0644)

	newTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	err := fsys.Chtimes("/chtimes.txt", newTime, newTime)
	if err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	// Verify time changed
	info, _ := fsys.Stat("/chtimes.txt")
	if !info.ModTime().Equal(newTime) {
		t.Errorf("ModTime() = %v, want %v", info.ModTime(), newTime)
	}
}

func TestFileSystem_Lstat(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/lstat.txt", []byte("test"), 0644)

	info, err := fsys.Lstat("/lstat.txt")
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}

	if info.Name() != "lstat.txt" {
		t.Errorf("Lstat().Name() = %q, want %q", info.Name(), "lstat.txt")
	}
}

// =============================================================================
// Error Injection Tests
// =============================================================================

func TestFileSystem_ErrorOnStat(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/error.txt", []byte("test"), 0644)
	backend.SetError("/error.txt", errors.New("injected error"))

	_, err := fsys.Stat("/error.txt")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestFileSystem_ErrorOnOpen(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/error.txt", []byte("test"), 0644)
	backend.SetError("/error.txt", errors.New("injected error"))

	_, err := fsys.Open("/error.txt")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestConnectionPool_ConnectError(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	factory.ConnectError = errors.New("connection failed")

	config := testConfig()
	pool := newConnectionPoolWithFactory(config, factory)
	defer pool.Close()

	_, err := pool.get(context.Background())
	if err == nil {
		t.Error("Expected connection error, got nil")
	}
}

// =============================================================================
// Cache Interaction Tests
// =============================================================================

func TestFileSystem_CacheHit(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.Cache = CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 100,
	}

	fsys, err := NewWithFactory(config, factory)
	if err != nil {
		t.Fatalf("NewWithFactory() error = %v", err)
	}
	defer fsys.Close()

	backend.AddFile("/cached.txt", []byte("test"), 0644)

	// First stat (cache miss)
	_, err = fsys.Stat("/cached.txt")
	if err != nil {
		t.Fatalf("First Stat() error = %v", err)
	}

	// Second stat (cache hit) - should not call backend
	backend.ClearOperations()
	_, err = fsys.Stat("/cached.txt")
	if err != nil {
		t.Fatalf("Second Stat() error = %v", err)
	}

	// Verify no stat operations (cache hit)
	ops := backend.GetOperations()
	for _, op := range ops {
		if op.Op == "stat" {
			t.Error("Cache miss - stat called on backend")
		}
	}
}

func TestFileSystem_CacheInvalidation(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)
	config := testConfig()
	config.Cache = CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     1 * time.Hour,
		StatCacheTTL:    1 * time.Hour,
		MaxCacheEntries: 100,
	}

	fsys, err := NewWithFactory(config, factory)
	if err != nil {
		t.Fatalf("NewWithFactory() error = %v", err)
	}
	defer fsys.Close()

	backend.AddFile("/invalidate.txt", []byte("test"), 0644)

	// Populate cache
	fsys.Stat("/invalidate.txt")

	// Modify file (should invalidate cache)
	fsys.Chmod("/invalidate.txt", 0755)

	// Next stat should go to backend (cache invalidated)
	backend.ClearOperations()
	fsys.Stat("/invalidate.txt")

	ops := backend.GetOperations()
	statFound := false
	for _, op := range ops {
		if op.Op == "stat" {
			statFound = true
			break
		}
	}
	if !statFound {
		t.Error("Expected stat call after cache invalidation")
	}
}

// =============================================================================
// Concurrent File Operations Tests
// =============================================================================

func TestFileSystem_ConcurrentReads(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	content := []byte("concurrent test content")
	backend.AddFile("/concurrent.txt", content, 0644)

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := fsys.Open("/concurrent.txt")
			if err != nil {
				errCh <- err
				return
			}
			defer f.Close()

			buf := make([]byte, 100)
			n, err := f.Read(buf)
			if err != nil && err != io.EOF {
				errCh <- err
				return
			}

			if string(buf[:n]) != string(content) {
				errCh <- errors.New("content mismatch")
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent read error: %v", err)
	}
}

func TestFileSystem_ConcurrentWrites(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			filename := "/concurrent_" + string(rune('0'+idx)) + ".txt"
			f, err := fsys.Create(filename)
			if err != nil {
				errCh <- err
				return
			}
			defer f.Close()

			_, err = f.Write([]byte("content"))
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent write error: %v", err)
	}
}
