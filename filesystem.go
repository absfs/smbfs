package smbfs

import (
	"context"
	"io/fs"
	"os"
	"time"

	"github.com/absfs/smbfs/absfs"
)

// FileSystem implements absfs.FileSystem for SMB/CIFS network shares.
type FileSystem struct {
	config   *Config
	pool     *connectionPool
	pathNorm *pathNormalizer
	ctx      context.Context
	cancel   context.CancelFunc
}

// Ensure FileSystem implements absfs.FileSystem.
var _ absfs.FileSystem = (*FileSystem)(nil)

// New creates a new SMB filesystem.
func New(config *Config) (*FileSystem, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}

	// Set defaults and validate
	config.setDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	fs := &FileSystem{
		config:   config,
		pool:     newConnectionPool(config),
		pathNorm: newPathNormalizer(config.CaseSensitive),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start background cleanup
	fs.pool.startCleanup(ctx)

	return fs, nil
}

// Open opens a file for reading.
func (fsys *FileSystem) Open(name string) (fs.File, error) {
	return fsys.OpenFile(name, os.O_RDONLY, 0)
}

// OpenFile opens a file with the specified flags and mode.
func (fsys *FileSystem) OpenFile(name string, flag int, perm fs.FileMode) (absfs.File, error) {
	// Validate and normalize path
	if err := validatePath(name); err != nil {
		return nil, wrapPathError("open", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	var resultFile *File
	err := fsys.withRetry(fsys.ctx, func() error {
		// Get a connection from the pool
		conn, err := fsys.pool.get(fsys.ctx)
		if err != nil {
			return err
		}

		// Convert flags to os flags for go-smb2
		openFlag := flag
		if flag&os.O_CREATE != 0 {
			openFlag = flag
		}

		// Open the file
		file, err := conn.share.OpenFile(smbPath, openFlag, perm)
		if err != nil {
			fsys.pool.put(conn)
			return convertError(err)
		}

		resultFile = &File{
			fs:   fsys,
			conn: conn,
			file: file,
			path: name,
		}
		return nil
	})

	if err != nil {
		return nil, wrapPathError("open", name, err)
	}

	return resultFile, nil
}

// Create creates a new file for writing.
func (fsys *FileSystem) Create(name string) (absfs.File, error) {
	return fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

// Stat returns file information.
func (fsys *FileSystem) Stat(name string) (fs.FileInfo, error) {
	if err := validatePath(name); err != nil {
		return nil, wrapPathError("stat", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	var info *fileInfo
	err := fsys.withRetry(fsys.ctx, func() error {
		conn, err := fsys.pool.get(fsys.ctx)
		if err != nil {
			return err
		}
		defer fsys.pool.put(conn)

		stat, err := conn.share.Stat(smbPath)
		if err != nil {
			return convertError(err)
		}

		info = &fileInfo{
			stat: stat,
			name: fsys.pathNorm.base(name),
		}
		return nil
	})

	if err != nil {
		return nil, wrapPathError("stat", name, err)
	}

	return info, nil
}

// Lstat returns file information (same as Stat for SMB).
func (fsys *FileSystem) Lstat(name string) (fs.FileInfo, error) {
	return fsys.Stat(name)
}

// ReadDir reads the directory and returns directory entries.
func (fsys *FileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := validatePath(name); err != nil {
		return nil, wrapPathError("readdir", name, err)
	}

	name = fsys.pathNorm.normalize(name)

	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Check if it's a directory
	info, err := f.Stat()
	if err != nil {
		return nil, wrapPathError("readdir", name, err)
	}

	if !info.IsDir() {
		return nil, wrapPathError("readdir", name, ErrNotDirectory)
	}

	// Read directory entries
	file := f.(*File)
	return file.ReadDir(-1)
}

// Mkdir creates a directory.
func (fsys *FileSystem) Mkdir(name string, perm fs.FileMode) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("mkdir", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	conn, err := fsys.pool.get(fsys.ctx)
	if err != nil {
		return wrapPathError("mkdir", name, err)
	}
	defer fsys.pool.put(conn)

	err = conn.share.Mkdir(smbPath, perm)
	if err != nil {
		return wrapPathError("mkdir", name, convertError(err))
	}

	return nil
}

// MkdirAll creates a directory and all parent directories.
func (fsys *FileSystem) MkdirAll(name string, perm fs.FileMode) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("mkdir", name, err)
	}

	name = fsys.pathNorm.normalize(name)

	// Check if directory already exists
	if stat, err := fsys.Stat(name); err == nil {
		if !stat.IsDir() {
			return wrapPathError("mkdir", name, ErrNotDirectory)
		}
		return nil
	}

	// Create parent directory first
	parent := fsys.pathNorm.dir(name)
	if parent != "/" && parent != "." {
		if err := fsys.MkdirAll(parent, perm); err != nil {
			return err
		}
	}

	// Create this directory
	return fsys.Mkdir(name, perm)
}

// Remove removes a file or empty directory.
func (fsys *FileSystem) Remove(name string) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("remove", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	conn, err := fsys.pool.get(fsys.ctx)
	if err != nil {
		return wrapPathError("remove", name, err)
	}
	defer fsys.pool.put(conn)

	err = conn.share.Remove(smbPath)
	if err != nil {
		return wrapPathError("remove", name, convertError(err))
	}

	return nil
}

// RemoveAll removes a path and all children.
func (fsys *FileSystem) RemoveAll(name string) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("remove", name, err)
	}

	name = fsys.pathNorm.normalize(name)

	// Check if it exists
	info, err := fsys.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already removed
		}
		return err
	}

	// If it's a file, just remove it
	if !info.IsDir() {
		return fsys.Remove(name)
	}

	// Read directory contents
	entries, err := fsys.ReadDir(name)
	if err != nil {
		return err
	}

	// Remove all children first
	for _, entry := range entries {
		childPath := fsys.pathNorm.join(name, entry.Name())
		if err := fsys.RemoveAll(childPath); err != nil {
			return err
		}
	}

	// Remove the directory itself
	return fsys.Remove(name)
}

// Rename renames (moves) a file or directory.
func (fsys *FileSystem) Rename(oldname, newname string) error {
	if err := validatePath(oldname); err != nil {
		return wrapPathError("rename", oldname, err)
	}
	if err := validatePath(newname); err != nil {
		return wrapPathError("rename", newname, err)
	}

	oldname = fsys.pathNorm.normalize(oldname)
	newname = fsys.pathNorm.normalize(newname)

	oldSMBPath := toSMBPath(oldname)
	newSMBPath := toSMBPath(newname)

	conn, err := fsys.pool.get(fsys.ctx)
	if err != nil {
		return wrapPathError("rename", oldname, err)
	}
	defer fsys.pool.put(conn)

	err = conn.share.Rename(oldSMBPath, newSMBPath)
	if err != nil {
		return wrapPathError("rename", oldname, convertError(err))
	}

	return nil
}

// Chmod changes the mode of a file.
func (fsys *FileSystem) Chmod(name string, mode fs.FileMode) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("chmod", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	conn, err := fsys.pool.get(fsys.ctx)
	if err != nil {
		return wrapPathError("chmod", name, err)
	}
	defer fsys.pool.put(conn)

	err = conn.share.Chmod(smbPath, mode)
	if err != nil {
		return wrapPathError("chmod", name, convertError(err))
	}

	return nil
}

// Chown changes the owner of a file.
func (fsys *FileSystem) Chown(name string, uid, gid int) error {
	// SMB doesn't directly support Unix ownership
	// This would require SID manipulation which is complex
	return wrapPathError("chown", name, ErrNotImplemented)
}

// Chtimes changes the access and modification times of a file.
func (fsys *FileSystem) Chtimes(name string, atime, mtime time.Time) error {
	if err := validatePath(name); err != nil {
		return wrapPathError("chtimes", name, err)
	}

	name = fsys.pathNorm.normalize(name)
	smbPath := toSMBPath(name)

	conn, err := fsys.pool.get(fsys.ctx)
	if err != nil {
		return wrapPathError("chtimes", name, err)
	}
	defer fsys.pool.put(conn)

	err = conn.share.Chtimes(smbPath, atime, mtime)
	if err != nil {
		return wrapPathError("chtimes", name, convertError(err))
	}

	return nil
}

// Close closes the filesystem and releases all resources.
func (fsys *FileSystem) Close() error {
	fsys.cancel()
	return fsys.pool.Close()
}

// convertFlags converts os.O_* flags to SMB access mode and create disposition.
func convertFlags(flag int) (accessMode uint32, createDisposition uint32) {
	// Access mode
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		accessMode = 0x80000000 // GENERIC_READ
	case os.O_WRONLY:
		accessMode = 0x40000000 // GENERIC_WRITE
	case os.O_RDWR:
		accessMode = 0xC0000000 // GENERIC_READ | GENERIC_WRITE
	}

	// Create disposition
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		createDisposition = 1 // CREATE_NEW (fail if exists)
	case flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0:
		createDisposition = 2 // CREATE_ALWAYS (overwrite)
	case flag&os.O_CREATE != 0:
		createDisposition = 4 // OPEN_ALWAYS (create if not exists)
	case flag&os.O_TRUNC != 0:
		createDisposition = 5 // TRUNCATE_EXISTING
	default:
		createDisposition = 3 // OPEN_EXISTING
	}

	return accessMode, createDisposition
}

// Separator returns the path separator for this filesystem.
func (fsys *FileSystem) Separator() uint8 {
	return '/'
}

// ListSeparator returns the list separator for this filesystem.
func (fsys *FileSystem) ListSeparator() uint8 {
	return ':'
}
