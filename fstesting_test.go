package smbfs

import (
	"io/fs"
	"testing"

	absfsCore "github.com/absfs/absfs"
	"github.com/absfs/fstesting"
	"github.com/absfs/smbfs/absfs"
)

// fsAdapter adapts smbfs.FileSystem to absfs.FileSystem (github.com/absfs/absfs)
type fsAdapter struct {
	*FileSystem
}

func (a *fsAdapter) Open(name string) (absfsCore.File, error) {
	f, err := a.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	return &fileAdapter{f.(*File)}, nil
}

func (a *fsAdapter) OpenFile(name string, flag int, perm fs.FileMode) (absfsCore.File, error) {
	f, err := a.FileSystem.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &fileAdapter{f.(*File)}, nil
}

func (a *fsAdapter) Create(name string) (absfsCore.File, error) {
	f, err := a.FileSystem.Create(name)
	if err != nil {
		return nil, err
	}
	return &fileAdapter{f.(*File)}, nil
}

// fileAdapter adapts smbfs.File to absfs.File (github.com/absfs/absfs)
type fileAdapter struct {
	*File
}

func (f *fileAdapter) Name() string {
	return f.File.path
}

func (f *fileAdapter) Stat() (fs.FileInfo, error) {
	return f.File.Stat()
}

func (f *fileAdapter) Read(p []byte) (int, error) {
	return f.File.Read(p)
}

func (f *fileAdapter) Write(p []byte) (int, error) {
	return f.File.Write(p)
}

func (f *fileAdapter) Seek(offset int64, whence int) (int64, error) {
	return f.File.Seek(offset, whence)
}

func (f *fileAdapter) Close() error {
	return f.File.Close()
}

func (f *fileAdapter) ReadDir(n int) ([]fs.DirEntry, error) {
	return f.File.ReadDir(n)
}

func (f *fileAdapter) Truncate(size int64) error {
	return f.File.Truncate(size)
}

func (f *fileAdapter) ReadAt(p []byte, off int64) (n int, err error) {
	// Save current offset
	currentOffset, err := f.File.Seek(0, 1) // SEEK_CUR
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = f.File.Seek(currentOffset, 0) }() // SEEK_SET

	// Seek to offset and read
	_, err = f.File.Seek(off, 0) // SEEK_SET
	if err != nil {
		return 0, err
	}

	return f.File.Read(p)
}

func (f *fileAdapter) WriteAt(p []byte, off int64) (n int, err error) {
	// Save current offset
	currentOffset, err := f.File.Seek(0, 1) // SEEK_CUR
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = f.File.Seek(currentOffset, 0) }() // SEEK_SET

	// Seek to offset and write
	_, err = f.File.Seek(off, 0) // SEEK_SET
	if err != nil {
		return 0, err
	}

	return f.File.Write(p)
}

func (f *fileAdapter) WriteString(s string) (n int, err error) {
	return f.File.Write([]byte(s))
}

func (f *fileAdapter) Readdirnames(n int) (names []string, err error) {
	entries, err := f.File.ReadDir(n)
	if err != nil {
		return nil, err
	}

	names = make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names, nil
}

func (f *fileAdapter) Readdir(n int) ([]fs.FileInfo, error) {
	entries, err := f.File.ReadDir(n)
	if err != nil {
		return nil, err
	}

	infos := make([]fs.FileInfo, len(entries))
	for i, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		infos[i] = info
	}
	return infos, nil
}

func (f *fileAdapter) Sync() error {
	// SMB doesn't have explicit sync, but writes are typically synchronous
	return nil
}

// TestFSTestingSuite runs the fstesting suite against smbfs using a mock backend.
func TestFSTestingSuite(t *testing.T) {
	// Create mock backend
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)

	// Create filesystem with mock
	config := &Config{
		Server:   "localhost",
		Port:     445,
		Share:    "testshare",
		Username: "testuser",
		Password: "testpass",
	}

	smbFS, err := NewWithFactory(config, factory)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}
	defer smbFS.Close()

	// Wrap with adapter
	fs := &fsAdapter{smbFS}

	// Configure suite
	suite := &fstesting.Suite{
		FS: fs,
		Features: fstesting.Features{
			Symlinks:      false, // SMB doesn't support symlinks in the absfs sense
			HardLinks:     false, // SMB doesn't support hard links
			Permissions:   true,  // SMB supports basic permissions via Chmod
			Timestamps:    true,  // SMB supports timestamps via Chtimes
			CaseSensitive: false, // SMB is typically case-insensitive
			AtomicRename:  true,  // SMB rename is atomic
			SparseFiles:   false, // Not testing sparse file support
			LargeFiles:    true,  // SMB supports large files
		},
		TestDir:     "/fstesting",
		KeepTestDir: false,
	}

	// Run the suite
	suite.Run(t)
}

// TestFSTestingQuickCheck runs a quick sanity check.
func TestFSTestingQuickCheck(t *testing.T) {
	// Create mock backend
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)

	// Create filesystem with mock
	config := &Config{
		Server:   "localhost",
		Port:     445,
		Share:    "testshare",
		Username: "testuser",
		Password: "testpass",
	}

	smbFS, err := NewWithFactory(config, factory)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}
	defer smbFS.Close()

	// Wrap with adapter
	fs := &fsAdapter{smbFS}

	// Configure suite
	suite := &fstesting.Suite{
		FS: fs,
	}

	// Run quick check
	suite.QuickCheck(t)
}

// Ensure adapter implements absfsCore.FileSystem
var _ absfsCore.FileSystem = (*fsAdapter)(nil)
var _ absfs.FileSystem = (*FileSystem)(nil)
var _ absfsCore.File = (*fileAdapter)(nil)
var _ absfs.File = (*File)(nil)
