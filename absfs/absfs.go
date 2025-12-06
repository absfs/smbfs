// Package absfs provides abstract filesystem interfaces.
package absfs

import (
	"io"
	"io/fs"
	"time"
)

// FileSystem is the interface that wraps the filesystem operations.
// It extends the standard library's fs.FS interface with additional methods
// for writing, modifying, and manipulating files and directories.
type FileSystem interface {
	fs.FS

	// OpenFile opens a file with the specified flags and mode.
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)

	// Create creates or truncates the named file.
	Create(name string) (File, error)

	// Mkdir creates a new directory with the specified name and permission bits.
	Mkdir(name string, perm fs.FileMode) error

	// MkdirAll creates a directory named path, along with any necessary parents.
	MkdirAll(path string, perm fs.FileMode) error

	// Remove removes the named file or (empty) directory.
	Remove(name string) error

	// RemoveAll removes path and any children it contains.
	RemoveAll(path string) error

	// Rename renames (moves) oldpath to newpath.
	Rename(oldname, newname string) error

	// Stat returns a FileInfo describing the named file.
	Stat(name string) (fs.FileInfo, error)

	// Lstat returns a FileInfo describing the named file.
	// If the file is a symbolic link, the returned FileInfo describes the link itself.
	Lstat(name string) (fs.FileInfo, error)

	// Chmod changes the mode of the named file to mode.
	Chmod(name string, mode fs.FileMode) error

	// Chown changes the numeric uid and gid of the named file.
	Chown(name string, uid, gid int) error

	// Chtimes changes the access and modification times of the named file.
	Chtimes(name string, atime time.Time, mtime time.Time) error

	// ReadDir reads the named directory and returns all its directory entries.
	ReadDir(name string) ([]fs.DirEntry, error)

	// Separator returns the OS-specific path separator.
	Separator() uint8

	// ListSeparator returns the OS-specific path list separator.
	ListSeparator() uint8

	// Chdir changes the current working directory.
	Chdir(dir string) error

	// Getwd returns the current working directory.
	Getwd() (dir string, err error)

	// TempDir returns the default directory for temporary files.
	TempDir() string

	// Truncate changes the size of the named file.
	Truncate(name string, size int64) error
}

// File is the interface that wraps file operations.
type File interface {
	fs.File
	io.Reader
	io.Writer
	io.Seeker
	io.Closer

	// ReadDir reads the contents of the directory and returns
	// a slice of up to n DirEntry values in directory order.
	// If n > 0, ReadDir returns at most n DirEntry structures.
	// If n <= 0, ReadDir returns all the DirEntry values from the directory.
	ReadDir(n int) ([]fs.DirEntry, error)

	// Truncate changes the size of the file.
	Truncate(size int64) error
}
