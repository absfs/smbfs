//go:build integration
// +build integration

package smbfs

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"testing"
	"time"
)

// BenchmarkFileCreation measures file creation performance.
func BenchmarkFileCreation(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/bench_create_%d.txt", i)
		file, err := fsys.Create(path)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}
		file.Close()

		// Clean up
		fsys.Remove(path)
	}
}

// BenchmarkSmallFileWrite measures writing small files (1KB).
func BenchmarkSmallFileWrite(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 1024) // 1KB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/bench_small_write_%d.txt", i)
		file, err := fsys.Create(path)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		_, err = file.Write(data)
		if err != nil {
			file.Close()
			b.Fatalf("Write failed: %v", err)
		}
		file.Close()

		// Clean up
		fsys.Remove(path)
	}
}

// BenchmarkMediumFileWrite measures writing medium files (64KB).
func BenchmarkMediumFileWrite(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 64*1024) // 64KB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/bench_medium_write_%d.txt", i)
		file, err := fsys.Create(path)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		_, err = file.Write(data)
		if err != nil {
			file.Close()
			b.Fatalf("Write failed: %v", err)
		}
		file.Close()

		// Clean up
		fsys.Remove(path)
	}
}

// BenchmarkLargeFileWrite measures writing large files (1MB).
func BenchmarkLargeFileWrite(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 1024*1024) // 1MB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/bench_large_write_%d.txt", i)
		file, err := fsys.Create(path)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		_, err = file.Write(data)
		if err != nil {
			file.Close()
			b.Fatalf("Write failed: %v", err)
		}
		file.Close()

		// Clean up
		fsys.Remove(path)
	}
}

// BenchmarkSmallFileRead measures reading small files (1KB).
func BenchmarkSmallFileRead(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 1024) // 1KB
	path := "/bench_read_small.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Write(data)
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := fs.ReadFile(fsys, path)
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
	}
}

// BenchmarkMediumFileRead measures reading medium files (64KB).
func BenchmarkMediumFileRead(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 64*1024) // 64KB
	path := "/bench_read_medium.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Write(data)
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := fs.ReadFile(fsys, path)
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
	}
}

// BenchmarkLargeFileRead measures reading large files (1MB).
func BenchmarkLargeFileRead(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
	path := "/bench_read_large.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Write(data)
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := fs.ReadFile(fsys, path)
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
	}
}

// BenchmarkStat measures file stat performance.
func BenchmarkStat(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	path := "/bench_stat.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Write([]byte("test"))
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := fsys.Stat(path)
		if err != nil {
			b.Fatalf("Stat failed: %v", err)
		}
	}
}

// BenchmarkReadDir measures directory reading performance.
func BenchmarkReadDir(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	dirPath := "/bench_readdir"

	// Setup: create directory with 100 files
	fsys.RemoveAll(dirPath)
	fsys.Mkdir(dirPath, 0755)

	for i := 0; i < 100; i++ {
		path := fmt.Sprintf("%s/file_%03d.txt", dirPath, i)
		file, err := fsys.Create(path)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}
		file.Write([]byte("test"))
		file.Close()
	}

	defer fsys.RemoveAll(dirPath)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entries, err := fsys.ReadDir(dirPath)
		if err != nil {
			b.Fatalf("ReadDir failed: %v", err)
		}
		if len(entries) != 100 {
			b.Fatalf("Expected 100 entries, got %d", len(entries))
		}
	}
}

// BenchmarkMkdir measures directory creation performance.
func BenchmarkMkdir(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/bench_mkdir_%d", i)
		err := fsys.Mkdir(path, 0755)
		if err != nil {
			b.Fatalf("Mkdir failed: %v", err)
		}

		// Clean up
		fsys.Remove(path)
	}
}

// BenchmarkRename measures file rename performance.
func BenchmarkRename(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		oldPath := fmt.Sprintf("/bench_rename_old_%d.txt", i)
		newPath := fmt.Sprintf("/bench_rename_new_%d.txt", i)

		// Create file
		file, err := fsys.Create(oldPath)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}
		file.Close()

		// Rename
		err = fsys.Rename(oldPath, newPath)
		if err != nil {
			b.Fatalf("Rename failed: %v", err)
		}

		// Clean up
		fsys.Remove(newPath)
	}
}

// BenchmarkChmod measures chmod performance.
func BenchmarkChmod(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	path := "/bench_chmod.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := fsys.Chmod(path, 0644)
		if err != nil {
			b.Fatalf("Chmod failed: %v", err)
		}
	}
}

// BenchmarkChtimes measures chtimes performance.
func BenchmarkChtimes(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	path := "/bench_chtimes.txt"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Close()

	defer fsys.Remove(path)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		now := time.Now()
		err := fsys.Chtimes(path, now, now)
		if err != nil {
			b.Fatalf("Chtimes failed: %v", err)
		}
	}
}

// BenchmarkSequentialRead measures sequential read performance.
func BenchmarkSequentialRead(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))
	data := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
	path := "/bench_sequential_read.bin"

	// Setup: create test file
	file, err := fsys.Create(path)
	if err != nil {
		b.Fatalf("Create failed: %v", err)
	}
	file.Write(data)
	file.Close()

	defer fsys.Remove(path)

	buf := make([]byte, 64*1024) // 64KB buffer

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		file, err := fsys.Open(path)
		if err != nil {
			b.Fatalf("Open failed: %v", err)
		}

		for {
			_, err := file.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				file.Close()
				b.Fatalf("Read failed: %v", err)
			}
		}

		file.Close()
	}
}

// BenchmarkConnectionPooling measures connection pool efficiency.
func BenchmarkConnectionPooling(b *testing.B) {
	fsys := setupTestFS(b.(*testing.T))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			path := fmt.Sprintf("/bench_pool_%d.txt", i)
			i++

			// Create, write, stat, delete - exercises pool
			file, err := fsys.Create(path)
			if err != nil {
				b.Fatalf("Create failed: %v", err)
			}
			file.Write([]byte("test"))
			file.Close()

			_, err = fsys.Stat(path)
			if err != nil {
				b.Fatalf("Stat failed: %v", err)
			}

			fsys.Remove(path)
		}
	})
}
