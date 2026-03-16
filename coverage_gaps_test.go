package smbfs

import (
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"testing"
	"time"
)

// ===========================================================================
// Priority 1: subFS methods (filesystem.go:607-667) — all at 0%
// ===========================================================================

// newTestSubFS creates a subFS rooted at root for testing.
// The parent FileSystem is backed by a mock.
func newTestSubFS(t *testing.T) (*subFS, *FileSystem, *MockSMBBackend) {
	t.Helper()
	fsys, backend, _ := setupMockFS(t)

	// Create the subdirectory and files inside it.
	backend.AddDir("/subdir", 0755)
	backend.AddFile("/subdir/hello.txt", []byte("hello from sub"), 0644)
	backend.AddFile("/subdir/world.txt", []byte("world from sub"), 0644)
	backend.AddDir("/subdir/nested", 0755)
	backend.AddFile("/subdir/nested/deep.txt", []byte("deep"), 0644)

	sub := &subFS{parent: fsys, root: "/subdir"}
	return sub, fsys, backend
}

func TestSubFS_JoinPath(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"root", "/", "/subdir"},
		{"file", "/hello.txt", "/subdir/hello.txt"},
		{"nested", "/nested/deep.txt", "/subdir/nested/deep.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sub.joinPath(tt.path)
			if got != tt.want {
				t.Errorf("joinPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSubFS_OpenFile(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	f, err := sub.OpenFile("/hello.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	buf := make([]byte, 100)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf[:n]) != "hello from sub" {
		t.Errorf("Read() = %q, want %q", buf[:n], "hello from sub")
	}
}

func TestSubFS_Mkdir(t *testing.T) {
	sub, fsys, backend := newTestSubFS(t)
	defer fsys.Close()

	err := sub.Mkdir("/newdir", 0755)
	if err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	if !backend.FileExists("/subdir/newdir") {
		t.Error("Mkdir() did not create /subdir/newdir")
	}
}

func TestSubFS_Remove(t *testing.T) {
	sub, fsys, backend := newTestSubFS(t)
	defer fsys.Close()

	err := sub.Remove("/hello.txt")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	if backend.FileExists("/subdir/hello.txt") {
		t.Error("Remove() did not delete /subdir/hello.txt")
	}
}

func TestSubFS_Rename(t *testing.T) {
	sub, fsys, backend := newTestSubFS(t)
	defer fsys.Close()

	err := sub.Rename("/hello.txt", "/renamed.txt")
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}

	if backend.FileExists("/subdir/hello.txt") {
		t.Error("Rename() did not remove old file")
	}
	if !backend.FileExists("/subdir/renamed.txt") {
		t.Error("Rename() did not create new file")
	}
}

func TestSubFS_Stat(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	info, err := sub.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if info.Name() != "hello.txt" {
		t.Errorf("Stat().Name() = %q, want %q", info.Name(), "hello.txt")
	}
	if info.Size() != 14 {
		t.Errorf("Stat().Size() = %d, want 14", info.Size())
	}
}

func TestSubFS_Chmod(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	err := sub.Chmod("/hello.txt", 0755)
	if err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	info, err := sub.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat() after Chmod error = %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode().Perm(), 0755)
	}
}

func TestSubFS_Chtimes(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	newTime := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	err := sub.Chtimes("/hello.txt", newTime, newTime)
	if err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	info, err := sub.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat() after Chtimes error = %v", err)
	}
	if !info.ModTime().Equal(newTime) {
		t.Errorf("ModTime() = %v, want %v", info.ModTime(), newTime)
	}
}

func TestSubFS_Chown(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	// Chown always returns ErrNotImplemented on the parent FileSystem
	err := sub.Chown("/hello.txt", 1000, 1000)
	if err == nil {
		t.Error("Chown() expected error, got nil")
	}
}

func TestSubFS_ReadDir(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	entries, err := sub.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	// /subdir contains: hello.txt, world.txt, nested/
	if len(entries) != 3 {
		t.Errorf("ReadDir() returned %d entries, want 3", len(entries))
	}
}

func TestSubFS_ReadFile(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	data, err := sub.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if string(data) != "hello from sub" {
		t.Errorf("ReadFile() = %q, want %q", data, "hello from sub")
	}
}

func TestSubFS_Sub(t *testing.T) {
	sub, fsys, _ := newTestSubFS(t)
	defer fsys.Close()

	nestedFS, err := sub.Sub("/nested")
	if err != nil {
		t.Fatalf("Sub() error = %v", err)
	}

	if nestedFS == nil {
		t.Fatal("Sub() returned nil")
	}
}

// ===========================================================================
// Priority 2: queryFileInfo — additional info class branches (smb2_info.go:97)
// ===========================================================================

func TestQueryInfo_FileInternalInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileInternalInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 8 {
		t.Errorf("OutputBufferLength = %d, want 8", outputLen)
	}

	buffer := r.ReadBytes(int(outputLen))
	indexNumber := binary.LittleEndian.Uint64(buffer[0:8])
	// Index number should be the volatile file ID (non-zero)
	if indexNumber == 0 {
		t.Error("IndexNumber should not be zero")
	}
}

func TestQueryInfo_FileEaInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileEaInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 4 {
		t.Errorf("OutputBufferLength = %d, want 4", outputLen)
	}

	buffer := r.ReadBytes(int(outputLen))
	eaSize := binary.LittleEndian.Uint32(buffer[0:4])
	if eaSize != 0 {
		t.Errorf("EaSize = %d, want 0", eaSize)
	}
}

func TestQueryInfo_FileAccessInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileAccessInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 4 {
		t.Errorf("OutputBufferLength = %d, want 4", outputLen)
	}

	buffer := r.ReadBytes(int(outputLen))
	accessFlags := binary.LittleEndian.Uint32(buffer[0:4])
	// Access flags should be non-zero since we opened with read access
	if accessFlags == 0 {
		t.Error("AccessFlags should not be zero")
	}
}

func TestQueryInfo_FilePositionInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FilePositionInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 8 {
		t.Errorf("OutputBufferLength = %d, want 8", outputLen)
	}
}

func TestQueryInfo_FileNetworkOpenInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileNetworkOpenInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 56 {
		t.Errorf("OutputBufferLength = %d, want 56", outputLen)
	}
}

func TestQueryInfo_FileAttributeTagInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileAttributeTagInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 8 {
		t.Errorf("OutputBufferLength = %d, want 8", outputLen)
	}

	buffer := r.ReadBytes(int(outputLen))
	reparseTag := binary.LittleEndian.Uint32(buffer[4:8])
	if reparseTag != 0 {
		t.Errorf("ReparseTag = %d, want 0", reparseTag)
	}
}

func TestQueryInfo_UnsupportedFileInfoClass(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	// Use an unsupported class value (99)
	_, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, 99)

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

// ===========================================================================
// Priority 3: queryFilesystemInfo — FileFsFullSizeInformation (smb2_info.go:275)
// ===========================================================================

func TestQueryInfo_FileFsFullSizeInformation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open root directory for filesystem queries
	fileID := openFileViaCreate(t, env, sessionID, treeID, "",
		FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_DIRECTORY_FILE)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, FileFsFullSizeInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 32 {
		t.Errorf("OutputBufferLength = %d, want 32", outputLen)
	}
}

func TestQueryInfo_UnsupportedFilesystemClass(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "",
		FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_DIRECTORY_FILE)

	// Use an unsupported filesystem info class (99)
	_, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, 99)

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

// ===========================================================================
// Priority 4: NTStatus.String — cover all branches (smb2_types.go:111)
// ===========================================================================

func TestNTStatus_String_AllCases(t *testing.T) {
	tests := []struct {
		status NTStatus
		want   string
	}{
		{STATUS_SUCCESS, "STATUS_SUCCESS"},
		{STATUS_PENDING, "STATUS_PENDING"},
		{STATUS_BUFFER_OVERFLOW, "STATUS_BUFFER_OVERFLOW"},
		{STATUS_NO_MORE_FILES, "STATUS_NO_MORE_FILES"},
		{STATUS_INVALID_PARAMETER, "STATUS_INVALID_PARAMETER"},
		{STATUS_NO_SUCH_FILE, "STATUS_NO_SUCH_FILE"},
		{STATUS_END_OF_FILE, "STATUS_END_OF_FILE"},
		{STATUS_MORE_PROCESSING_REQUIRED, "STATUS_MORE_PROCESSING_REQUIRED"},
		{STATUS_ACCESS_DENIED, "STATUS_ACCESS_DENIED"},
		{STATUS_OBJECT_NAME_INVALID, "STATUS_OBJECT_NAME_INVALID"},
		{STATUS_OBJECT_NAME_NOT_FOUND, "STATUS_OBJECT_NAME_NOT_FOUND"},
		{STATUS_OBJECT_NAME_COLLISION, "STATUS_OBJECT_NAME_COLLISION"},
		{STATUS_OBJECT_PATH_NOT_FOUND, "STATUS_OBJECT_PATH_NOT_FOUND"},
		{STATUS_SHARING_VIOLATION, "STATUS_SHARING_VIOLATION"},
		{STATUS_LOGON_FAILURE, "STATUS_LOGON_FAILURE"},
		{STATUS_FILE_IS_A_DIRECTORY, "STATUS_FILE_IS_A_DIRECTORY"},
		{STATUS_BAD_NETWORK_NAME, "STATUS_BAD_NETWORK_NAME"},
		{STATUS_NOT_A_DIRECTORY, "STATUS_NOT_A_DIRECTORY"},
		{STATUS_FILE_CLOSED, "STATUS_FILE_CLOSED"},
		{STATUS_CANCELLED, "STATUS_CANCELLED"},
		{STATUS_NOT_FOUND, "STATUS_NOT_FOUND"},
		{STATUS_DIRECTORY_NOT_EMPTY, "STATUS_DIRECTORY_NOT_EMPTY"},
		{STATUS_NOT_SUPPORTED, "STATUS_NOT_SUPPORTED"},
		{NTStatus(0xDEADBEEF), "STATUS_UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("NTStatus(0x%08X).String() = %q, want %q", uint32(tt.status), got, tt.want)
			}
		})
	}
}

// ===========================================================================
// Priority 5: File.Truncate (file.go:110) — extend and shrink paths
// ===========================================================================

func TestFile_Truncate_Shrink(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/trunc_shrink.txt", []byte("0123456789"), 0644)

	f, err := fsys.OpenFile("/trunc_shrink.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	err = file.Truncate(5)
	if err != nil {
		t.Fatalf("Truncate(5) error = %v", err)
	}

	// Verify the file is now 5 bytes
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() after truncate error = %v", err)
	}
	if info.Size() != 5 {
		t.Errorf("Size() after Truncate(5) = %d, want 5", info.Size())
	}
}

func TestFile_Truncate_Expand(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/trunc_expand.txt", []byte("ABC"), 0644)

	f, err := fsys.OpenFile("/trunc_expand.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	err = file.Truncate(10)
	if err != nil {
		t.Fatalf("Truncate(10) error = %v", err)
	}

	// Verify the file expanded
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() after truncate error = %v", err)
	}
	if info.Size() != 10 {
		t.Errorf("Size() after Truncate(10) = %d, want 10", info.Size())
	}
}

func TestFile_Truncate_SameSize(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/trunc_same.txt", []byte("ABCDE"), 0644)

	f, err := fsys.OpenFile("/trunc_same.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)
	err = file.Truncate(5)
	if err != nil {
		t.Fatalf("Truncate(5) on 5-byte file error = %v", err)
	}

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Size() != 5 {
		t.Errorf("Size() = %d, want 5", info.Size())
	}
}

func TestFile_Truncate_Closed(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/trunc_closed.txt", []byte("data"), 0644)

	f, _ := fsys.Open("/trunc_closed.txt")
	file := f.(*File)
	f.Close()

	err := file.Truncate(0)
	if err == nil {
		t.Error("Truncate on closed file should return error")
	}
}

// ===========================================================================
// Priority 6: handleClose — POSTQUERY_ATTRIB flag and delete-on-close
// ===========================================================================

func buildCloseMsgWithFlags(sessionID uint64, treeID uint32, fileID FileID, flags uint16) *SMB2Message {
	w := NewByteWriter(24)
	w.WriteUint16(24)
	w.WriteUint16(flags)
	w.WriteUint32(0)
	w.WriteFileID(fileID)

	return &SMB2Message{
		Header:  makeHeader(SMB2_CLOSE, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func TestClose_PostQueryAttrib(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	// Close with POSTQUERY_ATTRIB flag (0x0001)
	closeMsg := buildCloseMsgWithFlags(sessionID, treeID, fileID, 0x0001)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CLOSE status = %s, want STATUS_SUCCESS", closeResp.Header.Status)
	}

	// Verify response contains file info (non-zero times)
	if len(closeResp.Payload) < 56 {
		t.Fatalf("CLOSE response too short: %d bytes", len(closeResp.Payload))
	}

	// Flags should echo back
	respFlags := binary.LittleEndian.Uint16(closeResp.Payload[2:4])
	if respFlags != 0x0001 {
		t.Errorf("Response flags = 0x%04x, want 0x0001", respFlags)
	}

	// CreationTime at offset 8 should be non-zero
	creationTime := binary.LittleEndian.Uint64(closeResp.Payload[8:16])
	if creationTime == 0 {
		t.Error("CreationTime should not be zero with POSTQUERY_ATTRIB")
	}

	// EndOfFile at offset 48 should be "hello world" = 11 bytes
	endOfFile := binary.LittleEndian.Uint64(closeResp.Payload[48:56])
	if endOfFile != 11 {
		t.Errorf("EndOfFile = %d, want 11", endOfFile)
	}
}

func TestClose_DeleteOnCloseViaSetInfo(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a temporary file
	fileID := openFileViaCreate(t, env, sessionID, treeID, "deleteme.txt",
		GENERIC_READ|GENERIC_WRITE|DELETE, FILE_CREATE, 0)

	// Set delete-on-close via SET_INFO
	buffer := []byte{1} // DeletePending = true
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileDispositionInformation, buffer)
	if status != STATUS_SUCCESS {
		t.Fatalf("SET_INFO status = %s, want STATUS_SUCCESS", status)
	}

	// Close the file - should trigger deletion
	closeMsg := buildCloseMsg(sessionID, treeID, fileID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CLOSE status = %s, want STATUS_SUCCESS", closeResp.Header.Status)
	}

	// Verify the file is gone
	openMsg := buildCreateMsg(sessionID, treeID, "deleteme.txt", GENERIC_READ, FILE_OPEN, 0)
	openResp, err := env.handler.HandleMessage(env.state, openMsg)
	if err != nil {
		t.Fatalf("HandleMessage(re-open) error: %v", err)
	}
	if openResp.Header.Status != STATUS_OBJECT_NAME_NOT_FOUND {
		t.Errorf("re-open status = %s, want STATUS_OBJECT_NAME_NOT_FOUND", openResp.Header.Status)
	}
}

// ===========================================================================
// Priority 7: setFileBasicInformation, setFileRenameInformation,
//             setFileEndOfFileInformation — uncovered error paths
// ===========================================================================

func TestSetInfo_FileBasicInformation_WithAttributes(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Set both time and attributes
	newTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newFT := TimeToFiletime(newTime)

	w := NewByteWriter(40)
	w.WriteUint64(0)                    // CreationTime (don't change)
	w.WriteUint64(0)                    // LastAccessTime (don't change)
	w.WriteUint64(newFT)               // LastWriteTime
	w.WriteUint64(0)                    // ChangeTime (don't change)
	w.WriteUint32(FILE_ATTRIBUTE_READONLY) // FileAttributes (set readonly)
	w.WriteUint32(0)                    // Reserved

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileBasicInformation, w.Bytes())

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}
}

func TestSetInfo_FileBasicInformation_ShortBuffer(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Buffer too short (< 40 bytes)
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileBasicInformation, make([]byte, 10))

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

func TestSetInfo_FileRenameInformation_NoReplace(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create target file first
	targetID := openFileViaCreate(t, env, sessionID, treeID, "target.txt",
		GENERIC_WRITE, FILE_CREATE, 0)
	closeMsg := buildCloseMsg(sessionID, treeID, targetID)
	_, _ = env.handler.HandleMessage(env.state, closeMsg)

	// Open source file
	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE, FILE_OPEN, 0)

	// Try to rename with ReplaceIfExists=false, target already exists
	newName := "target.txt"
	newNameUTF16 := EncodeStringToUTF16LE(newName)

	w := NewByteWriter(20 + len(newNameUTF16))
	w.WriteOneByte(0)                            // ReplaceIfExists = false
	w.WriteBytes(make([]byte, 7))                // Reserved
	w.WriteUint64(0)                             // RootDirectory
	w.WriteUint32(uint32(len(newNameUTF16)))     // FileNameLength
	w.WriteBytes(newNameUTF16)                   // FileName

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileRenameInformation, w.Bytes())

	if status != STATUS_OBJECT_NAME_COLLISION {
		t.Errorf("status = %s, want STATUS_OBJECT_NAME_COLLISION", status)
	}
}

func TestSetInfo_FileRenameInformation_ShortBuffer(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE, FILE_OPEN, 0)

	// Buffer too short (< 20 bytes)
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileRenameInformation, make([]byte, 5))

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

func TestSetInfo_FileEndOfFileInformation_TruncateToZero(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA, FILE_OPEN, 0)

	// Truncate to zero bytes
	w := NewByteWriter(8)
	w.WriteUint64(0)

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileEndOfFileInformation, w.Bytes())

	// memfs may not support Truncate; accept SUCCESS or NOT_SUPPORTED
	if status != STATUS_SUCCESS && status != STATUS_NOT_SUPPORTED {
		t.Fatalf("status = %s, want STATUS_SUCCESS or STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_FileEndOfFileInformation_ShortBuffer(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA, FILE_OPEN, 0)

	// Buffer too short (< 8 bytes)
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileEndOfFileInformation, make([]byte, 3))

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

func TestSetInfo_FileDispositionInformation_ShortBuffer(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE, FILE_OPEN, 0)

	// Buffer too short (< 1 byte)
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileDispositionInformation, []byte{})

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

func TestSetInfo_FilesystemInfoType(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Filesystem info is read-only
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, 0, make([]byte, 16))

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_SecurityInfoType(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Security info not supported
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_SECURITY, 0, make([]byte, 16))

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_QuotaInfoType(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Quota info not supported
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_QUOTA, 0, make([]byte, 16))

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_InvalidInfoType(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Invalid info type (0xFF)
	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		0xFF, 0, make([]byte, 16))

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

// ===========================================================================
// Priority 8: Chdir/Getwd (filesystem.go:492/514)
// ===========================================================================

func TestFileSystem_Chdir(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/testdir", 0755)

	// Chdir to existing directory should succeed
	err := fsys.Chdir("/testdir")
	if err != nil {
		t.Fatalf("Chdir(/testdir) error = %v", err)
	}

	// Chdir to non-existent directory should fail
	err = fsys.Chdir("/nonexistent")
	if err == nil {
		t.Error("Chdir(/nonexistent) expected error, got nil")
	}

	// Chdir to a file should fail with ErrNotDirectory
	backend.AddFile("/afile.txt", []byte("data"), 0644)
	err = fsys.Chdir("/afile.txt")
	if err == nil {
		t.Error("Chdir(/afile.txt) expected error, got nil")
	}
}

func TestFileSystem_Chdir_InvalidPath(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	err := fsys.Chdir("")
	if err == nil {
		t.Error("Chdir('') expected error, got nil")
	}
}

func TestFileSystem_Getwd(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	wd, err := fsys.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if wd != "/" {
		t.Errorf("Getwd() = %q, want %q", wd, "/")
	}
}

// ===========================================================================
// Priority 10: ListenAndServe (server.go:217)
// ===========================================================================

func TestListenAndServe(t *testing.T) {
	srv, err := NewServer(ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}
	srv.options.Port = 0
	srv.options.Hostname = "127.0.0.1"

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait briefly for the server to start listening
	time.Sleep(50 * time.Millisecond)

	// Stop the server
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	// ListenAndServe should return nil after context cancellation
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ListenAndServe() did not return after Stop()")
	}
}

// ===========================================================================
// Priority 11: createRealConnection error paths (connection.go:202)
// ===========================================================================

func TestCreateRealConnection_InvalidConfig(t *testing.T) {
	// createRealConnection is called indirectly when the filesystem tries to
	// get a connection. Using the real factory (not mock) with invalid server
	// should fail fast.
	config := &Config{
		Server:      "192.0.2.1", // RFC 5737 TEST-NET, guaranteed unreachable
		Share:       "testshare",
		Username:    "user",
		Password:    "pass",
		Port:        1, // invalid port, should fail fast
		ConnTimeout: 100 * time.Millisecond,
	}
	config.setDefaults()

	factory := &RealConnectionFactory{}
	_, _, err := factory.CreateConnection(config)
	if err == nil {
		t.Error("CreateConnection with unreachable server should return error")
	}
}

// ===========================================================================
// Additional coverage: handleLogoff and handleTreeDisconnect via HandleMessage
// ===========================================================================

func TestHandleLogoff(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	msg := buildLogoffMsg(sessionID)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(LOGOFF) error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Errorf("LOGOFF status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
}

func TestHandleTreeDisconnect(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildTreeDisconnectMsg(sessionID, treeID)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(TREE_DISCONNECT) error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Errorf("TREE_DISCONNECT status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
}

// ===========================================================================
// Additional coverage: QueryInfo with invalid infoType
// ===========================================================================

func TestQueryInfo_InvalidInfoType(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	// Use invalid info type (0xFF)
	_, status := sendQueryInfo(t, env, sessionID, treeID, fileID, 0xFF, 0)

	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", status)
	}
}

// ===========================================================================
// Additional: File.ReadDir with n>0 (file.go:285 — cover n>0 branch)
// ===========================================================================

func TestFile_ReadDir_Incremental(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/incdir", 0755)
	backend.AddFile("/incdir/a.txt", []byte("a"), 0644)
	backend.AddFile("/incdir/b.txt", []byte("b"), 0644)
	backend.AddFile("/incdir/c.txt", []byte("c"), 0644)

	f, err := fsys.Open("/incdir")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)

	// Read 2 entries at a time
	entries1, err := file.ReadDir(2)
	if err != nil {
		t.Fatalf("ReadDir(2) error = %v", err)
	}
	if len(entries1) != 2 {
		t.Errorf("ReadDir(2) returned %d entries, want 2", len(entries1))
	}

	// Read remaining
	entries2, err := file.ReadDir(2)
	if err != nil {
		t.Fatalf("ReadDir(2) second call error = %v", err)
	}
	if len(entries2) != 1 {
		t.Errorf("ReadDir(2) second call returned %d entries, want 1", len(entries2))
	}

	// Third call should return EOF
	_, err = file.ReadDir(2)
	if err != io.EOF {
		t.Errorf("ReadDir(2) third call error = %v, want io.EOF", err)
	}
}

func TestFile_ReadDir_AllAtOnce(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddDir("/alldir", 0755)
	backend.AddFile("/alldir/x.txt", []byte("x"), 0644)

	f, err := fsys.Open("/alldir")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	file := f.(*File)

	// Read all with n<=0
	entries, err := file.ReadDir(-1)
	if err != nil {
		t.Fatalf("ReadDir(-1) error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("ReadDir(-1) returned %d entries, want 1", len(entries))
	}

	// Second call with n<=0 should return EOF
	_, err = file.ReadDir(0)
	if err != io.EOF {
		t.Errorf("ReadDir(0) second call error = %v, want io.EOF", err)
	}
}

// ===========================================================================
// Additional: File operations on closed file (more branches in file.go)
// ===========================================================================

func TestFile_Write_Closed(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/wr_closed.txt", []byte("data"), 0644)

	f, _ := fsys.OpenFile("/wr_closed.txt", os.O_RDWR, 0)
	file := f.(*File)
	f.Close()

	_, err := file.Write([]byte("x"))
	if err != fs.ErrClosed {
		t.Errorf("Write on closed file error = %v, want fs.ErrClosed", err)
	}
}

func TestFile_Seek_Closed(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/seek_closed.txt", []byte("data"), 0644)

	f, _ := fsys.Open("/seek_closed.txt")
	file := f.(*File)
	f.Close()

	_, err := file.Seek(0, io.SeekStart)
	if err != fs.ErrClosed {
		t.Errorf("Seek on closed file error = %v, want fs.ErrClosed", err)
	}
}

func TestFile_Stat_Closed(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/stat_closed.txt", []byte("data"), 0644)

	f, _ := fsys.Open("/stat_closed.txt")
	file := f.(*File)
	f.Close()

	_, err := file.Stat()
	if err != fs.ErrClosed {
		t.Errorf("Stat on closed file error = %v, want fs.ErrClosed", err)
	}
}

// ===========================================================================
// Additional: filesystem.go ReadFile on directory (error branch)
// ===========================================================================

func TestFileSystem_ReadFile(t *testing.T) {
	fsys, backend, _ := setupMockFS(t)
	defer fsys.Close()

	backend.AddFile("/readfile.txt", []byte("contents"), 0644)

	data, err := fsys.ReadFile("/readfile.txt")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "contents" {
		t.Errorf("ReadFile() = %q, want %q", data, "contents")
	}
}

func TestFileSystem_ReadFile_InvalidPath(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	_, err := fsys.ReadFile("")
	if err == nil {
		t.Error("ReadFile('') expected error, got nil")
	}
}

// ===========================================================================
// Additional: filesystem.go Sub with invalid path
// ===========================================================================

func TestFileSystem_Sub_InvalidPath(t *testing.T) {
	fsys, _, _ := setupMockFS(t)
	defer fsys.Close()

	_, err := fsys.Sub("")
	if err == nil {
		t.Error("Sub('') expected error, got nil")
	}
}

// ===========================================================================
// Additional: FiletimeToTime zero-value branch (smb2_types.go:305)
// ===========================================================================

func TestFiletimeToTime_Zero(t *testing.T) {
	result := FiletimeToTime(0)
	if !result.IsZero() {
		t.Errorf("FiletimeToTime(0) = %v, want zero time", result)
	}
}

func TestFiletimeToTime_Nonzero(t *testing.T) {
	// Known timestamp: 2025-01-01 00:00:00 UTC
	expected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := TimeToFiletime(expected)
	result := FiletimeToTime(ft)

	if !result.Equal(expected) {
		t.Errorf("FiletimeToTime(TimeToFiletime(%v)) = %v", expected, result)
	}
}
