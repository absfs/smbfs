package smbfs

import (
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/absfs/smbfs/absfs"
)

func TestFileSystem_InterfaceCompliance(t *testing.T) {
	// Verify FileSystem implements absfs.FileSystem
	var _ absfs.FileSystem = (*FileSystem)(nil)
}

func TestNew_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing server",
			config: &Config{
				Share:    "myshare",
				Username: "user",
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "missing share",
			config: &Config{
				Server:   "server.example.com",
				Username: "user",
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			config: &Config{
				Server:   "server.example.com",
				Share:    "myshare",
				Username: "user",
				Password: "pass",
				Port:     70000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys, err := New(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("New() expected error, got nil")
					if fsys != nil {
						fsys.Close()
					}
				}
			} else {
				if err != nil {
					t.Errorf("New() unexpected error = %v", err)
				}
				if fsys != nil {
					fsys.Close()
				}
			}
		})
	}
}

func TestNew_ValidConfig(t *testing.T) {
	// This test validates that New() creates a filesystem with valid config
	// but doesn't attempt to connect
	config := &Config{
		Server:   "server.example.com",
		Share:    "myshare",
		Username: "user",
		Password: "pass",
	}

	fsys, err := New(config)
	if err != nil {
		t.Fatalf("New() unexpected error = %v", err)
	}
	defer fsys.Close()

	// Verify internal state
	if fsys.config == nil {
		t.Error("FileSystem.config is nil")
	}
	if fsys.pool == nil {
		t.Error("FileSystem.pool is nil")
	}
	if fsys.pathNorm == nil {
		t.Error("FileSystem.pathNorm is nil")
	}
	if fsys.ctx == nil {
		t.Error("FileSystem.ctx is nil")
	}

	// Verify config defaults were set
	if fsys.config.Port != 445 {
		t.Errorf("config.Port = %d, want 445", fsys.config.Port)
	}
	if fsys.config.MaxIdle != 5 {
		t.Errorf("config.MaxIdle = %d, want 5", fsys.config.MaxIdle)
	}
}

func TestConvertFlags(t *testing.T) {
	tests := []struct {
		name                      string
		flag                      int
		wantAccessMode            uint32
		wantCreateDisposition     uint32
	}{
		{
			name:                  "read-only",
			flag:                  os.O_RDONLY,
			wantAccessMode:        0x80000000, // GENERIC_READ
			wantCreateDisposition: 3,          // OPEN_EXISTING
		},
		{
			name:                  "write-only",
			flag:                  os.O_WRONLY,
			wantAccessMode:        0x40000000, // GENERIC_WRITE
			wantCreateDisposition: 3,          // OPEN_EXISTING
		},
		{
			name:                  "read-write",
			flag:                  os.O_RDWR,
			wantAccessMode:        0xC0000000, // GENERIC_READ | GENERIC_WRITE
			wantCreateDisposition: 3,          // OPEN_EXISTING
		},
		{
			name:                  "create new",
			flag:                  os.O_CREATE | os.O_EXCL | os.O_RDWR,
			wantAccessMode:        0xC0000000, // GENERIC_READ | GENERIC_WRITE
			wantCreateDisposition: 1,          // CREATE_NEW
		},
		{
			name:                  "create or truncate",
			flag:                  os.O_CREATE | os.O_TRUNC | os.O_WRONLY,
			wantAccessMode:        0x40000000, // GENERIC_WRITE
			wantCreateDisposition: 2,          // CREATE_ALWAYS
		},
		{
			name:                  "create if not exists",
			flag:                  os.O_CREATE | os.O_RDWR,
			wantAccessMode:        0xC0000000, // GENERIC_READ | GENERIC_WRITE
			wantCreateDisposition: 4,          // OPEN_ALWAYS
		},
		{
			name:                  "truncate existing",
			flag:                  os.O_TRUNC | os.O_WRONLY,
			wantAccessMode:        0x40000000, // GENERIC_WRITE
			wantCreateDisposition: 5,          // TRUNCATE_EXISTING
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessMode, createDisposition := convertFlags(tt.flag)

			if accessMode != tt.wantAccessMode {
				t.Errorf("accessMode = 0x%X, want 0x%X", accessMode, tt.wantAccessMode)
			}
			if createDisposition != tt.wantCreateDisposition {
				t.Errorf("createDisposition = %d, want %d", createDisposition, tt.wantCreateDisposition)
			}
		})
	}
}

func TestFileSystem_Separator(t *testing.T) {
	config := &Config{
		Server:   "server.example.com",
		Share:    "myshare",
		Username: "user",
		Password: "pass",
	}

	fsys, err := New(config)
	if err != nil {
		t.Fatalf("New() unexpected error = %v", err)
	}
	defer fsys.Close()

	if sep := fsys.Separator(); sep != '/' {
		t.Errorf("Separator() = %c, want %c", sep, '/')
	}
}

func TestFileSystem_ListSeparator(t *testing.T) {
	config := &Config{
		Server:   "server.example.com",
		Share:    "myshare",
		Username: "user",
		Password: "pass",
	}

	fsys, err := New(config)
	if err != nil {
		t.Fatalf("New() unexpected error = %v", err)
	}
	defer fsys.Close()

	if sep := fsys.ListSeparator(); sep != ':' {
		t.Errorf("ListSeparator() = %c, want %c", sep, ':')
	}
}

func TestFileSystem_PathValidation(t *testing.T) {
	config := &Config{
		Server:   "server.example.com",
		Share:    "myshare",
		Username: "user",
		Password: "pass",
	}

	fsys, err := New(config)
	if err != nil {
		t.Fatalf("New() unexpected error = %v", err)
	}
	defer fsys.Close()

	tests := []struct {
		name     string
		path     string
		wantErr  bool
		checkErr func(error) bool
	}{
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
			checkErr: func(err error) bool {
				var pathErr *fs.PathError
				return err != nil &&
					errors.As(err, &pathErr) &&
					errors.Is(pathErr.Err, ErrInvalidPath)
			},
		},
		{
			name:    "path with null byte",
			path:    "/path/to\x00/file",
			wantErr: true,
			checkErr: func(err error) bool {
				var pathErr *fs.PathError
				return err != nil &&
					errors.As(err, &pathErr) &&
					errors.Is(pathErr.Err, ErrInvalidPath)
			},
		},
		{
			name:    "path traversal",
			path:    "../../etc/passwd",
			wantErr: true,
			checkErr: func(err error) bool {
				var pathErr *fs.PathError
				return err != nil &&
					errors.As(err, &pathErr) &&
					errors.Is(pathErr.Err, ErrInvalidPath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Try to stat the invalid path - should fail validation
			_, err := fsys.Stat(tt.path)

			if tt.wantErr {
				if err == nil {
					t.Error("Stat() expected error, got nil")
					return
				}
				if tt.checkErr != nil && !tt.checkErr(err) {
					t.Errorf("Stat() error type check failed: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Stat() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestFileSystem_NotImplemented(t *testing.T) {
	config := &Config{
		Server:   "server.example.com",
		Share:    "myshare",
		Username: "user",
		Password: "pass",
	}

	fsys, err := New(config)
	if err != nil {
		t.Fatalf("New() unexpected error = %v", err)
	}
	defer fsys.Close()

	// Test Chmod (now implemented, but will fail without real SMB server)
	t.Run("Chmod", func(t *testing.T) {
		err := fsys.Chmod("/test", 0644)
		// Without a real SMB server, this will fail with connection error
		if err == nil {
			t.Errorf("Chmod() expected error without server, got nil")
		}
	})

	// Test Chown (still not implemented)
	t.Run("Chown", func(t *testing.T) {
		err := fsys.Chown("/test", 1000, 1000)
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("Chown() error = %v, want ErrNotImplemented", err)
		}
	})

	// Test Chtimes (now implemented, but will fail without real SMB server)
	t.Run("Chtimes", func(t *testing.T) {
		now := time.Now()
		err := fsys.Chtimes("/test", now, now)
		// Without a real SMB server, this will fail with connection error
		if err == nil {
			t.Errorf("Chtimes() expected error without server, got nil")
		}
	})
}
