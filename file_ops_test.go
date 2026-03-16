package smbfs

import (
	"io"
	"os"
	"sort"
	"testing"
)

// TestFile_Name verifies that Name() returns the correct file path.
func TestFile_Name(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/myfile.txt", []byte("data"), 0644)

	f, err := fsys.Open("/myfile.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	if file.Name() != "/myfile.txt" {
		t.Errorf("Name() = %q, want %q", file.Name(), "/myfile.txt")
	}
}

// TestFile_ReadAt verifies ReadAt reads at various offsets correctly.
func TestFile_ReadAt(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	content := []byte("0123456789ABCDEF")
	backend.AddFile("/readat.txt", content, 0644)

	f, err := fsys.Open("/readat.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)

	tests := []struct {
		name   string
		offset int64
		size   int
		want   string
	}{
		{"start", 0, 4, "0123"},
		{"middle", 5, 5, "56789"},
		{"end", 12, 4, "CDEF"},
		{"single byte", 10, 1, "A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			n, err := file.ReadAt(buf, tt.offset)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt(%d) error = %v", tt.offset, err)
			}
			if string(buf[:n]) != tt.want {
				t.Errorf("ReadAt(%d) = %q, want %q", tt.offset, buf[:n], tt.want)
			}
		})
	}

	// Verify ReadAt does not change the file's current offset.
	// First Read should still start from position 0 (unchanged by ReadAt).
	file2, err := fsys.Open("/readat.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer file2.Close()

	f2 := file2.(*File)
	buf := make([]byte, 3)
	n, _ := f2.Read(buf)
	if string(buf[:n]) != "012" {
		t.Errorf("Read after ReadAt = %q, want %q", buf[:n], "012")
	}

	// Do a ReadAt at offset 8, then verify subsequent Read continues from
	// where the sequential Read left off (offset 3), not from 8.
	raBuf := make([]byte, 3)
	_, _ = f2.ReadAt(raBuf, 8)

	buf2 := make([]byte, 3)
	n2, _ := f2.Read(buf2)
	if string(buf2[:n2]) != "345" {
		t.Errorf("Read after ReadAt should continue from previous offset, got %q, want %q", buf2[:n2], "345")
	}
}

// TestFile_ReadAt_ClosedFile verifies ReadAt returns an error on a closed file.
func TestFile_ReadAt_ClosedFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/closed_readat.txt", []byte("data"), 0644)

	f, _ := fsys.Open("/closed_readat.txt")
	file := f.(*File)
	f.Close()

	buf := make([]byte, 4)
	_, err := file.ReadAt(buf, 0)
	if err == nil {
		t.Error("ReadAt on closed file should return error")
	}
}

// TestFile_WriteAt verifies WriteAt writes at the correct offset.
func TestFile_WriteAt(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/writeat.txt", []byte("AAAAAAAAAA"), 0644)

	f, err := fsys.OpenFile("/writeat.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)

	// WriteAt offset 3.
	n, err := file.WriteAt([]byte("XYZ"), 3)
	if err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if n != 3 {
		t.Errorf("WriteAt() wrote %d bytes, want 3", n)
	}

	// Verify the content was written at the correct position.
	saved, ok := backend.GetFile("/writeat.txt")
	if !ok {
		t.Fatal("File not found in backend")
	}
	if string(saved) != "AAAXYZAAAA" {
		t.Errorf("File content = %q, want %q", saved, "AAAXYZAAAA")
	}
}

// TestFile_WriteAt_ClosedFile verifies WriteAt returns an error on a closed file.
func TestFile_WriteAt_ClosedFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/closed_writeat.txt", []byte("data"), 0644)

	f, _ := fsys.OpenFile("/closed_writeat.txt", os.O_RDWR, 0)
	file := f.(*File)
	f.Close()

	_, err := file.WriteAt([]byte("X"), 0)
	if err == nil {
		t.Error("WriteAt on closed file should return error")
	}
}

// TestFile_WriteString verifies WriteString writes a string to the file.
func TestFile_WriteString(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	f, err := fsys.Create("/writestring.txt")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	file := f.(*File)
	n, err := file.WriteString("hello world")
	if err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if n != 11 {
		t.Errorf("WriteString() wrote %d bytes, want 11", n)
	}
	f.Close()

	// Verify content.
	saved, ok := backend.GetFile("/writestring.txt")
	if !ok {
		t.Fatal("File not found in backend")
	}
	if string(saved) != "hello world" {
		t.Errorf("Content = %q, want %q", saved, "hello world")
	}
}

// TestFile_WriteString_Empty verifies WriteString handles empty strings.
func TestFile_WriteString_Empty(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	f, err := fsys.Create("/empty_ws.txt")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	n, err := file.WriteString("")
	if err != nil {
		t.Fatalf("WriteString(\"\") error = %v", err)
	}
	if n != 0 {
		t.Errorf("WriteString(\"\") wrote %d bytes, want 0", n)
	}
}

// TestFile_Sync verifies Sync returns no error.
func TestFile_Sync(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/sync.txt", []byte("data"), 0644)

	f, err := fsys.Open("/sync.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	if err := file.Sync(); err != nil {
		t.Errorf("Sync() error = %v, want nil", err)
	}
}

// TestFile_Sync_ClosedFile verifies Sync returns an error on a closed file.
func TestFile_Sync_ClosedFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/sync_closed.txt", []byte("data"), 0644)

	f, _ := fsys.Open("/sync_closed.txt")
	file := f.(*File)
	f.Close()

	if err := file.Sync(); err == nil {
		t.Error("Sync on closed file should return error")
	}
}

// TestFile_Readdir verifies Readdir returns file info entries.
func TestFile_Readdir(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/dirtest", 0755)
	backend.AddFile("/dirtest/alpha.txt", []byte("a"), 0644)
	backend.AddFile("/dirtest/beta.txt", []byte("b"), 0644)
	backend.AddDir("/dirtest/gamma", 0755)

	f, err := fsys.Open("/dirtest")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	infos, err := file.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir(-1) error = %v", err)
	}

	if len(infos) != 3 {
		t.Fatalf("Readdir(-1) returned %d entries, want 3", len(infos))
	}

	// Sort for stable comparison.
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name() < infos[j].Name()
	})

	if infos[0].Name() != "alpha.txt" {
		t.Errorf("Entry[0].Name() = %q, want %q", infos[0].Name(), "alpha.txt")
	}
	if infos[1].Name() != "beta.txt" {
		t.Errorf("Entry[1].Name() = %q, want %q", infos[1].Name(), "beta.txt")
	}
	if infos[2].Name() != "gamma" {
		t.Errorf("Entry[2].Name() = %q, want %q", infos[2].Name(), "gamma")
	}
	if !infos[2].IsDir() {
		t.Error("gamma should be a directory")
	}
}

// TestFile_Readdir_ClosedFile verifies Readdir returns an error on a closed file.
func TestFile_Readdir_ClosedFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/closed_dir", 0755)

	f, _ := fsys.Open("/closed_dir")
	file := f.(*File)
	f.Close()

	_, err := file.Readdir(-1)
	if err == nil {
		t.Error("Readdir on closed file should return error")
	}
}

// TestFile_Readdirnames verifies Readdirnames returns entry names.
func TestFile_Readdirnames(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/namedir", 0755)
	backend.AddFile("/namedir/one.txt", []byte("1"), 0644)
	backend.AddFile("/namedir/two.txt", []byte("2"), 0644)
	backend.AddFile("/namedir/three.txt", []byte("3"), 0644)

	f, err := fsys.Open("/namedir")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	names, err := file.Readdirnames(-1)
	if err != nil {
		t.Fatalf("Readdirnames(-1) error = %v", err)
	}

	if len(names) != 3 {
		t.Fatalf("Readdirnames(-1) returned %d names, want 3", len(names))
	}

	sort.Strings(names)
	expected := []string{"one.txt", "three.txt", "two.txt"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("names[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

// TestFile_Readdirnames_ClosedFile verifies Readdirnames errors on a closed file.
func TestFile_Readdirnames_ClosedFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/closed_namedir", 0755)

	f, _ := fsys.Open("/closed_namedir")
	file := f.(*File)
	f.Close()

	_, err := file.Readdirnames(-1)
	if err == nil {
		t.Error("Readdirnames on closed file should return error")
	}
}

// TestFile_Stat verifies the Stat method on an open file.
func TestFile_Stat(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/filestat.txt", []byte("some content"), 0644)

	f, err := fsys.Open("/filestat.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Name() != "filestat.txt" {
		t.Errorf("Stat().Name() = %q, want %q", info.Name(), "filestat.txt")
	}
	if info.Size() != 12 {
		t.Errorf("Stat().Size() = %d, want 12", info.Size())
	}
	if info.IsDir() {
		t.Error("Stat().IsDir() = true, want false")
	}
}

// TestFileInfo_Sys verifies the Sys() method returns the underlying stat's Sys.
func TestFileInfo_Sys(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/sys_test.txt", []byte("x"), 0644)

	f, err := fsys.Open("/sys_test.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	// The mock backend's Sys() returns nil, so our wrapper should too.
	if info.Sys() != nil {
		t.Errorf("Sys() = %v, want nil (from mock)", info.Sys())
	}
}

// TestFileInfo_WindowsAttributes verifies the WindowsAttributes method.
func TestFileInfo_WindowsAttributes(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/winattr.txt", []byte("x"), 0644)

	f, err := fsys.Open("/winattr.txt")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	fi, ok := info.(*fileInfo)
	if !ok {
		t.Fatalf("info is %T, want *fileInfo", info)
	}

	// The mock backend does not populate Windows attributes, so expect nil.
	attrs := fi.WindowsAttributes()
	if attrs != nil {
		t.Errorf("WindowsAttributes() = %v, want nil", attrs)
	}
}

// TestSMB2Header_IsResponse verifies IsResponse flag detection.
func TestSMB2Header_IsResponse(t *testing.T) {
	h := &SMB2Header{Flags: 0}
	if h.IsResponse() {
		t.Error("IsResponse() should be false when flag not set")
	}

	h.Flags = SMB2_FLAGS_SERVER_TO_REDIR
	if !h.IsResponse() {
		t.Error("IsResponse() should be true when SERVER_TO_REDIR flag set")
	}
}

// TestSMB2Header_IsSigned verifies IsSigned flag detection.
func TestSMB2Header_IsSigned(t *testing.T) {
	h := &SMB2Header{Flags: 0}
	if h.IsSigned() {
		t.Error("IsSigned() should be false when flag not set")
	}

	h.Flags = SMB2_FLAGS_SIGNED
	if !h.IsSigned() {
		t.Error("IsSigned() should be true when SIGNED flag set")
	}
}

// TestNullLogger_Methods verifies NullLogger methods don't panic.
func TestNullLogger_Methods(t *testing.T) {
	l := &NullLogger{}
	l.Debug("test %s", "debug")
	l.Info("test %s", "info")
	l.Warn("test %s", "warn")
	l.Error("test %s", "error")
}

// TestMockSMBBackend_SetOperationError verifies operation-level error injection.
func TestMockSMBBackend_SetOperationError(t *testing.T) {
	backend := NewMockSMBBackend()

	testErr := io.ErrUnexpectedEOF
	backend.SetOperationError("read", testErr)

	backend.AddFile("/op_err.txt", []byte("data"), 0644)

	session := NewMockSMBSession(backend)
	share, err := session.Mount("testshare")
	if err != nil {
		t.Fatalf("Mount() error = %v", err)
	}

	f, err := share.OpenFile("/op_err.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	buf := make([]byte, 10)
	_, err = f.Read(buf)
	if err != testErr {
		t.Errorf("Read() error = %v, want %v", err, testErr)
	}
}

// TestMockSMBBackend_ClearErrors verifies error clearing.
func TestMockSMBBackend_ClearErrors(t *testing.T) {
	backend := NewMockSMBBackend()
	backend.SetError("/test", io.ErrClosedPipe)
	backend.SetOperationError("read", io.ErrUnexpectedEOF)

	backend.ClearErrors()

	backend.AddFile("/test", []byte("data"), 0644)

	session := NewMockSMBSession(backend)
	share, err := session.Mount("testshare")
	if err != nil {
		t.Fatalf("Mount() error = %v", err)
	}

	f, err := share.OpenFile("/test", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v (error was not cleared)", err)
	}

	buf := make([]byte, 10)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Read() error = %v (operation error was not cleared)", err)
	}
	if string(buf[:n]) != "data" {
		t.Errorf("Read() = %q, want %q", buf[:n], "data")
	}
}

// TestMockConnectionFactory_ConnectAttempts verifies attempt counting.
func TestMockConnectionFactory_ConnectAttempts(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)

	if factory.ConnectAttempts() != 0 {
		t.Errorf("ConnectAttempts() = %d, want 0", factory.ConnectAttempts())
	}

	config := testConfig()
	_, _, _ = factory.CreateConnection(config)

	if factory.ConnectAttempts() != 1 {
		t.Errorf("ConnectAttempts() after one call = %d, want 1", factory.ConnectAttempts())
	}
}

// TestMockConnectionFactory_Reset verifies counter reset.
func TestMockConnectionFactory_Reset(t *testing.T) {
	backend := NewMockSMBBackend()
	factory := NewMockConnectionFactory(backend)

	config := testConfig()
	_, _, _ = factory.CreateConnection(config)

	factory.Reset()

	if factory.ConnectionsMade() != 0 {
		t.Errorf("ConnectionsMade() after reset = %d, want 0", factory.ConnectionsMade())
	}
	if factory.ConnectAttempts() != 0 {
		t.Errorf("ConnectAttempts() after reset = %d, want 0", factory.ConnectAttempts())
	}
}

// TestWindowsAttributes_Attributes verifies Attributes() returns the raw value.
func TestWindowsAttributes_Attributes(t *testing.T) {
	wa := NewWindowsAttributes(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
	raw := wa.Attributes()

	if raw != FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM {
		t.Errorf("Attributes() = 0x%08x, want 0x%08x", raw, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)
	}
}

// TestMockFileInfo_Sys verifies the mock's Sys() returns nil.
func TestMockFileInfo_Sys(t *testing.T) {
	backend := NewMockSMBBackend()
	backend.AddFile("/syscheck.txt", []byte("x"), 0644)

	session := NewMockSMBSession(backend)
	share, _ := session.Mount("testshare")
	f, _ := share.OpenFile("/syscheck.txt", os.O_RDONLY, 0)
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Sys() != nil {
		t.Errorf("mock Sys() = %v, want nil", info.Sys())
	}
}
