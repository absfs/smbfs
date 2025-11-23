package smbfs

import (
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// File represents an open file on an SMB share.
type File struct {
	fs       *FileSystem
	conn     *pooledConn
	file     *smb2.File
	path     string
	offset   int64
	dirEntry []fs.DirEntry
	dirPos   int
}

// Read reads up to len(p) bytes into p.
func (f *File) Read(p []byte) (n int, err error) {
	if f.file == nil {
		return 0, fs.ErrClosed
	}

	n, err = f.file.Read(p)
	if err != nil && err != io.EOF {
		return n, wrapPathError("read", f.path, err)
	}

	f.offset += int64(n)
	return n, err
}

// Write writes len(p) bytes from p to the file.
func (f *File) Write(p []byte) (n int, err error) {
	if f.file == nil {
		return 0, fs.ErrClosed
	}

	n, err = f.file.Write(p)
	if err != nil {
		return n, wrapPathError("write", f.path, err)
	}

	f.offset += int64(n)
	return n, nil
}

// Seek sets the offset for the next Read or Write on the file.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	if f.file == nil {
		return 0, fs.ErrClosed
	}

	newOffset, err := f.file.Seek(offset, whence)
	if err != nil {
		return 0, wrapPathError("seek", f.path, err)
	}

	f.offset = newOffset
	return newOffset, nil
}

// Close closes the file.
func (f *File) Close() error {
	if f.file == nil {
		return nil
	}

	err := f.file.Close()
	f.file = nil

	// Return connection to pool
	if f.conn != nil {
		f.fs.pool.put(f.conn)
		f.conn = nil
	}

	if err != nil {
		return wrapPathError("close", f.path, err)
	}

	return nil
}

// Stat returns file information.
func (f *File) Stat() (fs.FileInfo, error) {
	if f.file == nil {
		return nil, fs.ErrClosed
	}

	stat, err := f.file.Stat()
	if err != nil {
		return nil, wrapPathError("stat", f.path, err)
	}

	return &fileInfo{
		stat: stat,
		name: f.fs.pathNorm.base(f.path),
	}, nil
}

// ReadDir reads the contents of the directory.
func (f *File) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.file == nil {
		return nil, fs.ErrClosed
	}

	// Read all entries on first call
	if f.dirEntry == nil {
		entries, err := f.file.Readdir(-1)
		if err != nil {
			return nil, wrapPathError("readdir", f.path, err)
		}

		f.dirEntry = make([]fs.DirEntry, 0, len(entries))
		for _, entry := range entries {
			// Skip "." and ".."
			if entry.Name() == "." || entry.Name() == ".." {
				continue
			}

			f.dirEntry = append(f.dirEntry, &dirEntry{
				info: &fileInfo{
					stat: entry,
					name: entry.Name(),
				},
			})
		}
		f.dirPos = 0
	}

	// Return n entries or all remaining
	if n <= 0 {
		entries := f.dirEntry[f.dirPos:]
		f.dirPos = len(f.dirEntry)
		if len(entries) == 0 {
			return nil, io.EOF
		}
		return entries, nil
	}

	if f.dirPos >= len(f.dirEntry) {
		return nil, io.EOF
	}

	end := f.dirPos + n
	if end > len(f.dirEntry) {
		end = len(f.dirEntry)
	}

	entries := f.dirEntry[f.dirPos:end]
	f.dirPos = end

	return entries, nil
}

// fileInfo implements fs.FileInfo for SMB files.
type fileInfo struct {
	stat os.FileInfo
	name string
}

func (fi *fileInfo) Name() string {
	return fi.name
}

func (fi *fileInfo) Size() int64 {
	return fi.stat.Size()
}

func (fi *fileInfo) Mode() fs.FileMode {
	return fi.stat.Mode()
}

func (fi *fileInfo) ModTime() time.Time {
	return fi.stat.ModTime()
}

func (fi *fileInfo) IsDir() bool {
	return fi.stat.IsDir()
}

func (fi *fileInfo) Sys() any {
	return fi.stat.Sys()
}

// WindowsAttributes returns the Windows file attributes if available.
// Returns nil if attributes cannot be determined.
func (fi *fileInfo) WindowsAttributes() *WindowsAttributes {
	// Try to extract Windows attributes from the underlying stat
	if sys := fi.stat.Sys(); sys != nil {
		// The go-smb2 library may provide attributes through Sys()
		// This is a placeholder for actual extraction
		// In practice, we would need to check the concrete type
	}
	return nil
}

// dirEntry implements fs.DirEntry.
type dirEntry struct {
	info *fileInfo
}

func (de *dirEntry) Name() string {
	return de.info.Name()
}

func (de *dirEntry) IsDir() bool {
	return de.info.IsDir()
}

func (de *dirEntry) Type() fs.FileMode {
	return de.info.Mode().Type()
}

func (de *dirEntry) Info() (fs.FileInfo, error) {
	return de.info, nil
}
