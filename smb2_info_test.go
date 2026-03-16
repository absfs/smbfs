package smbfs

import (
	"encoding/binary"
	"io/fs"
	"testing"
	"time"

	"github.com/absfs/memfs"
)

// ---------------------------------------------------------------------------
// Mock fs.FileInfo for build* method unit tests
// ---------------------------------------------------------------------------

type testFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (i *testFileInfo) Name() string      { return i.name }
func (i *testFileInfo) Size() int64       { return i.size }
func (i *testFileInfo) Mode() fs.FileMode { return i.mode }
func (i *testFileInfo) ModTime() time.Time { return i.modTime }
func (i *testFileInfo) IsDir() bool       { return i.isDir }
func (i *testFileInfo) Sys() interface{}  { return nil }

// ---------------------------------------------------------------------------
// Helper: open a file through the SMB2 CREATE handler and return the FileID
// ---------------------------------------------------------------------------

func openFileViaCreate(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, filename string, access, disposition, options uint32) FileID {
	t.Helper()
	msg := buildCreateMsg(sessionID, treeID, filename, access, disposition, options)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("openFileViaCreate(%s): HandleMessage error: %v", filename, err)
	}
	if resp == nil {
		t.Fatalf("openFileViaCreate(%s): nil response", filename)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("openFileViaCreate(%s): status = %s, want STATUS_SUCCESS", filename, resp.Header.Status)
	}
	return parseCreateResponse(t, resp.Payload)
}

// ---------------------------------------------------------------------------
// Helper: send a QUERY_INFO request through HandleMessage
// ---------------------------------------------------------------------------

func sendQueryInfo(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, fileID FileID, infoType, infoClass uint8) (*SMB2Message, NTStatus) {
	t.Helper()
	msg := buildQueryInfoMsg(sessionID, treeID, fileID, infoType, infoClass)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("sendQueryInfo: HandleMessage error: %v", err)
	}
	if resp == nil {
		t.Fatal("sendQueryInfo: nil response")
	}
	return resp, resp.Header.Status
}

// ---------------------------------------------------------------------------
// Helper: send a SET_INFO request through HandleMessage
// ---------------------------------------------------------------------------

func sendSetInfo(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, fileID FileID, infoType, infoClass uint8, buffer []byte) (*SMB2Message, NTStatus) {
	t.Helper()
	msg := buildSetInfoMsg(sessionID, treeID, fileID, infoType, infoClass, buffer)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("sendSetInfo: HandleMessage error: %v", err)
	}
	if resp == nil {
		t.Fatal("sendSetInfo: nil response")
	}
	return resp, resp.Header.Status
}

// ===========================================================================
// build* Method Tests (unit tests)
// ===========================================================================

func TestBuildFileBasicInformation(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	modTime := time.Date(2025, 3, 15, 10, 30, 0, 0, time.UTC)
	info := &testFileInfo{
		name:    "test.txt",
		size:    1024,
		mode:    0644,
		modTime: modTime,
		isDir:   false,
	}
	attrs := modeToAttributes(info.Mode())

	buf := env.handler.buildFileBasicInformation(info, attrs)

	if len(buf) != 40 {
		t.Fatalf("expected 40 bytes, got %d", len(buf))
	}

	r := NewByteReader(buf)
	creationTime := r.ReadUint64()
	lastAccessTime := r.ReadUint64()
	lastWriteTime := r.ReadUint64()
	changeTime := r.ReadUint64()
	fileAttrs := r.ReadUint32()
	reserved := r.ReadUint32()

	// CreationTime should be non-zero (uses time.Now which is fixed)
	if creationTime == 0 {
		t.Error("CreationTime should not be zero")
	}

	// LastAccessTime, LastWriteTime, ChangeTime should match modTime
	expectedFT := TimeToFiletime(modTime)
	if lastAccessTime != expectedFT {
		t.Errorf("LastAccessTime = %d, want %d", lastAccessTime, expectedFT)
	}
	if lastWriteTime != expectedFT {
		t.Errorf("LastWriteTime = %d, want %d", lastWriteTime, expectedFT)
	}
	if changeTime != expectedFT {
		t.Errorf("ChangeTime = %d, want %d", changeTime, expectedFT)
	}

	// Attributes should be FILE_ATTRIBUTE_NORMAL for 0644 mode file
	if fileAttrs != attrs {
		t.Errorf("FileAttributes = 0x%08x, want 0x%08x", fileAttrs, attrs)
	}
	if reserved != 0 {
		t.Errorf("Reserved = %d, want 0", reserved)
	}

	// Test with a directory
	dirInfo := &testFileInfo{
		name:    "subdir",
		size:    0,
		mode:    fs.ModeDir | 0755,
		modTime: modTime,
		isDir:   true,
	}
	dirAttrs := modeToAttributes(dirInfo.Mode())
	dirBuf := env.handler.buildFileBasicInformation(dirInfo, dirAttrs)
	if len(dirBuf) != 40 {
		t.Fatalf("directory: expected 40 bytes, got %d", len(dirBuf))
	}

	dirFileAttrs := binary.LittleEndian.Uint32(dirBuf[32:36])
	if dirFileAttrs&FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.Errorf("directory FileAttributes 0x%08x should include FILE_ATTRIBUTE_DIRECTORY", dirFileAttrs)
	}
}

func TestBuildFileStandardInformation(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	t.Run("regular file", func(t *testing.T) {
		info := &testFileInfo{
			name:    "test.txt",
			size:    5000,
			mode:    0644,
			modTime: time.Now(),
			isDir:   false,
		}

		buf := env.handler.buildFileStandardInformation(info)
		if len(buf) != 24 {
			t.Fatalf("expected 24 bytes, got %d", len(buf))
		}

		r := NewByteReader(buf)
		allocationSize := r.ReadUint64()
		endOfFile := r.ReadUint64()
		numberOfLinks := r.ReadUint32()
		deletePending := r.ReadOneByte()
		directory := r.ReadOneByte()

		// AllocationSize should be rounded up to 4KB
		expectedAlloc := uint64(((5000 + 4095) / 4096) * 4096)
		if allocationSize != expectedAlloc {
			t.Errorf("AllocationSize = %d, want %d", allocationSize, expectedAlloc)
		}
		if endOfFile != 5000 {
			t.Errorf("EndOfFile = %d, want 5000", endOfFile)
		}
		if numberOfLinks != 1 {
			t.Errorf("NumberOfLinks = %d, want 1", numberOfLinks)
		}
		if deletePending != 0 {
			t.Errorf("DeletePending = %d, want 0", deletePending)
		}
		if directory != 0 {
			t.Errorf("Directory = %d, want 0", directory)
		}
	})

	t.Run("directory", func(t *testing.T) {
		info := &testFileInfo{
			name:    "subdir",
			size:    0,
			mode:    fs.ModeDir | 0755,
			modTime: time.Now(),
			isDir:   true,
		}

		buf := env.handler.buildFileStandardInformation(info)
		if len(buf) != 24 {
			t.Fatalf("expected 24 bytes, got %d", len(buf))
		}

		r := NewByteReader(buf)
		allocationSize := r.ReadUint64()
		_ = r.ReadUint64() // EndOfFile
		_ = r.ReadUint32() // NumberOfLinks
		_ = r.ReadOneByte()   // DeletePending
		directory := r.ReadOneByte()

		if allocationSize != 0 {
			t.Errorf("AllocationSize = %d, want 0 for empty directory", allocationSize)
		}
		if directory != 1 {
			t.Errorf("Directory = %d, want 1", directory)
		}
	})

	t.Run("zero size file", func(t *testing.T) {
		info := &testFileInfo{
			name:    "empty.txt",
			size:    0,
			mode:    0644,
			modTime: time.Now(),
			isDir:   false,
		}

		buf := env.handler.buildFileStandardInformation(info)
		r := NewByteReader(buf)
		allocationSize := r.ReadUint64()
		if allocationSize != 0 {
			t.Errorf("AllocationSize = %d, want 0 for zero-size file", allocationSize)
		}
	})
}

func TestBuildFileInternalInformation(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	of := &OpenFile{
		ID: FileID{Persistent: 0, Volatile: 42},
	}

	buf := env.handler.buildFileInternalInformation(of)
	if len(buf) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(buf))
	}

	indexNumber := binary.LittleEndian.Uint64(buf[0:8])
	if indexNumber != 42 {
		t.Errorf("IndexNumber = %d, want 42", indexNumber)
	}
}

func TestBuildFileNetworkOpenInformation(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	modTime := time.Date(2025, 6, 1, 8, 0, 0, 0, time.UTC)
	info := &testFileInfo{
		name:    "doc.pdf",
		size:    10240,
		mode:    0444,
		modTime: modTime,
		isDir:   false,
	}
	attrs := modeToAttributes(info.Mode())

	buf := env.handler.buildFileNetworkOpenInformation(info, attrs)
	if len(buf) != 56 {
		t.Fatalf("expected 56 bytes, got %d", len(buf))
	}

	r := NewByteReader(buf)
	creationTime := r.ReadUint64()
	lastAccessTime := r.ReadUint64()
	lastWriteTime := r.ReadUint64()
	changeTime := r.ReadUint64()
	allocationSize := r.ReadUint64()
	endOfFile := r.ReadUint64()
	fileAttrs := r.ReadUint32()

	if creationTime == 0 {
		t.Error("CreationTime should not be zero")
	}

	expectedFT := TimeToFiletime(modTime)
	if lastAccessTime != expectedFT {
		t.Errorf("LastAccessTime = %d, want %d", lastAccessTime, expectedFT)
	}
	if lastWriteTime != expectedFT {
		t.Errorf("LastWriteTime = %d, want %d", lastWriteTime, expectedFT)
	}
	if changeTime != expectedFT {
		t.Errorf("ChangeTime = %d, want %d", changeTime, expectedFT)
	}

	expectedAlloc := uint64(((10240 + 4095) / 4096) * 4096)
	if allocationSize != expectedAlloc {
		t.Errorf("AllocationSize = %d, want %d", allocationSize, expectedAlloc)
	}
	if endOfFile != 10240 {
		t.Errorf("EndOfFile = %d, want 10240", endOfFile)
	}

	// 0444 is read-only, so attrs should include FILE_ATTRIBUTE_READONLY
	if fileAttrs&FILE_ATTRIBUTE_READONLY == 0 {
		t.Errorf("FileAttributes 0x%08x should include FILE_ATTRIBUTE_READONLY for 0444 mode", fileAttrs)
	}
}

func TestBuildFileFsVolumeInformation(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	buf := env.handler.buildFileFsVolumeInformation()

	// Should be at least 18 bytes (fixed fields) + label
	if len(buf) < 18 {
		t.Fatalf("response too short: %d bytes", len(buf))
	}

	r := NewByteReader(buf)
	volumeCreationTime := r.ReadUint64()
	volumeSerial := r.ReadUint32()
	labelLength := r.ReadUint32()
	supportsObjects := r.ReadOneByte()
	_ = r.ReadOneByte() // Reserved

	if volumeCreationTime == 0 {
		t.Error("VolumeCreationTime should not be zero")
	}
	if volumeSerial != 0x12345678 {
		t.Errorf("VolumeSerialNumber = 0x%08x, want 0x12345678", volumeSerial)
	}
	if labelLength == 0 {
		t.Error("VolumeLabelLength should not be zero")
	}
	if supportsObjects != 0 {
		t.Errorf("SupportsObjects = %d, want 0", supportsObjects)
	}

	// Read the label and verify it decodes
	labelBytes := r.ReadBytes(int(labelLength))
	label := DecodeUTF16LEToString(labelBytes)
	if label != "SMB Share" {
		t.Errorf("VolumeLabel = %q, want %q", label, "SMB Share")
	}
}

func TestBuildFileFsSizeInformation(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	buf := env.handler.buildFileFsSizeInformation()
	if len(buf) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(buf))
	}

	r := NewByteReader(buf)
	totalUnits := r.ReadUint64()
	availableUnits := r.ReadUint64()
	sectorsPerUnit := r.ReadUint32()
	bytesPerSector := r.ReadUint32()

	if totalUnits == 0 {
		t.Error("TotalAllocationUnits should not be zero")
	}
	if availableUnits == 0 {
		t.Error("AvailableAllocationUnits should not be zero")
	}
	if availableUnits > totalUnits {
		t.Errorf("AvailableAllocationUnits (%d) > TotalAllocationUnits (%d)", availableUnits, totalUnits)
	}
	if sectorsPerUnit != 8 {
		t.Errorf("SectorsPerAllocationUnit = %d, want 8", sectorsPerUnit)
	}
	if bytesPerSector != 512 {
		t.Errorf("BytesPerSector = %d, want 512", bytesPerSector)
	}
}

func TestBuildFileFsAttributeInformation(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	buf := env.handler.buildFileFsAttributeInformation()

	// Should be at least 12 bytes (fixed fields) + fs name
	if len(buf) < 12 {
		t.Fatalf("response too short: %d bytes", len(buf))
	}

	r := NewByteReader(buf)
	fsAttributes := r.ReadUint32()
	maxComponentLen := r.ReadUint32()
	fsNameLength := r.ReadUint32()

	if fsAttributes == 0 {
		t.Error("FileSystemAttributes should not be zero")
	}
	if maxComponentLen != 255 {
		t.Errorf("MaximumComponentNameLength = %d, want 255", maxComponentLen)
	}
	if fsNameLength == 0 {
		t.Error("FileSystemNameLength should not be zero")
	}

	// Read and verify the filesystem name
	fsNameBytes := r.ReadBytes(int(fsNameLength))
	fsName := DecodeUTF16LEToString(fsNameBytes)
	if fsName != "SMBFS" {
		t.Errorf("FileSystemName = %q, want %q", fsName, "SMBFS")
	}

	// Verify FILE_CASE_PRESERVED_NAMES is set
	if fsAttributes&0x00000002 == 0 {
		t.Error("FILE_CASE_PRESERVED_NAMES should be set")
	}
	// Verify FILE_UNICODE_ON_DISK is set
	if fsAttributes&0x00000004 == 0 {
		t.Error("FILE_UNICODE_ON_DISK should be set")
	}
}

func TestBuildFileFsFullSizeInformation(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	buf := env.handler.buildFileFsFullSizeInformation()
	if len(buf) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(buf))
	}

	r := NewByteReader(buf)
	totalUnits := r.ReadUint64()
	callerAvail := r.ReadUint64()
	actualAvail := r.ReadUint64()
	sectorsPerUnit := r.ReadUint32()
	bytesPerSector := r.ReadUint32()

	if totalUnits == 0 {
		t.Error("TotalAllocationUnits should not be zero")
	}
	if callerAvail == 0 {
		t.Error("CallerAvailableAllocationUnits should not be zero")
	}
	if actualAvail == 0 {
		t.Error("ActualAvailableAllocationUnits should not be zero")
	}
	if callerAvail != actualAvail {
		t.Errorf("CallerAvailable (%d) != ActualAvailable (%d)", callerAvail, actualAvail)
	}
	if callerAvail > totalUnits {
		t.Errorf("AvailableUnits (%d) > TotalUnits (%d)", callerAvail, totalUnits)
	}
	if sectorsPerUnit != 8 {
		t.Errorf("SectorsPerAllocationUnit = %d, want 8", sectorsPerUnit)
	}
	if bytesPerSector != 512 {
		t.Errorf("BytesPerSector = %d, want 512", bytesPerSector)
	}
}

// ===========================================================================
// handleQueryInfo Tests (require full state with open file)
// ===========================================================================

func TestQueryInfo_FileBasicInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileBasicInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	// Parse QUERY_INFO response: StructureSize(2) + OutputBufferOffset(2) + OutputBufferLength(4) + Buffer
	if len(resp.Payload) < 8 {
		t.Fatalf("response too short: %d bytes", len(resp.Payload))
	}
	r := NewByteReader(resp.Payload)
	structSize := r.ReadUint16()
	if structSize != 9 {
		t.Errorf("StructureSize = %d, want 9", structSize)
	}
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 40 {
		t.Errorf("OutputBufferLength = %d, want 40", outputLen)
	}

	// Read the buffer and verify times are non-zero
	buffer := r.ReadBytes(int(outputLen))
	br := NewByteReader(buffer)
	creationTime := br.ReadUint64()
	lastAccessTime := br.ReadUint64()
	lastWriteTime := br.ReadUint64()
	changeTime := br.ReadUint64()

	if creationTime == 0 {
		t.Error("CreationTime should not be zero")
	}
	if lastAccessTime == 0 {
		t.Error("LastAccessTime should not be zero")
	}
	if lastWriteTime == 0 {
		t.Error("LastWriteTime should not be zero")
	}
	if changeTime == 0 {
		t.Error("ChangeTime should not be zero")
	}
}

func TestQueryInfo_FileStandardInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileStandardInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 24 {
		t.Errorf("OutputBufferLength = %d, want 24", outputLen)
	}

	buffer := r.ReadBytes(int(outputLen))
	br := NewByteReader(buffer)
	_ = br.ReadUint64()    // AllocationSize
	endOfFile := br.ReadUint64()
	_ = br.ReadUint32()    // NumberOfLinks
	_ = br.ReadOneByte()      // DeletePending
	directory := br.ReadOneByte()

	// test.txt has "hello world" = 11 bytes
	if endOfFile != 11 {
		t.Errorf("EndOfFile = %d, want 11", endOfFile)
	}
	if directory != 0 {
		t.Errorf("Directory = %d, want 0 for a file", directory)
	}
}

func TestQueryInfo_FileAllInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileAllInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	// FileAllInformation is large: BasicInfo(40) + StandardInfo(24) +
	// InternalInfo(8) + EaInfo(4) + AccessInfo(4) + PositionInfo(8) +
	// ModeInfo(4) + AlignmentInfo(4) + NameInfo(4+variable)
	// Minimum is 100 bytes + name
	if outputLen < 100 {
		t.Errorf("OutputBufferLength = %d, expected at least 100", outputLen)
	}
}

func TestQueryInfo_FilesystemVolumeInfo(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	// Open root directory for filesystem queries
	fileID := openFileViaCreate(t, env, sessionID, treeID, "",
		FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_DIRECTORY_FILE)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, FileFsVolumeInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	structSize := r.ReadUint16()
	if structSize != 9 {
		t.Errorf("StructureSize = %d, want 9", structSize)
	}
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen < 18 {
		t.Errorf("OutputBufferLength = %d, expected at least 18", outputLen)
	}
}

func TestQueryInfo_FilesystemSizeInfo(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "",
		FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_DIRECTORY_FILE)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, FileFsSizeInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen != 24 {
		t.Errorf("OutputBufferLength = %d, want 24", outputLen)
	}
}

func TestQueryInfo_FilesystemAttributeInfo(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "",
		FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_DIRECTORY_FILE)

	resp, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILESYSTEM, FileFsAttributeInformation)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}

	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	outputLen := r.ReadUint32()

	if outputLen < 12 {
		t.Errorf("OutputBufferLength = %d, expected at least 12", outputLen)
	}
}

func TestQueryInfo_SecurityInfo(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	_, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_SECURITY, 0)

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

func TestQueryInfo_InvalidHandle(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	bogusFileID := FileID{Persistent: 0xDEADBEEF, Volatile: 0xCAFEBABE}

	_, status := sendQueryInfo(t, env, sessionID, treeID, bogusFileID,
		SMB2_0_INFO_FILE, FileBasicInformation)

	if status != STATUS_FILE_CLOSED {
		t.Errorf("status = %s, want STATUS_FILE_CLOSED", status)
	}
}

func TestQueryInfo_UnsupportedInfoType(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	_, status := sendQueryInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_QUOTA, 0)

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}

// ===========================================================================
// handleSetInfo Tests (require full state)
// ===========================================================================

func TestSetInfo_FileBasicInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Build FileBasicInformation buffer (40 bytes)
	newTime := time.Date(2025, 12, 25, 0, 0, 0, 0, time.UTC)
	newFT := TimeToFiletime(newTime)

	w := NewByteWriter(40)
	w.WriteUint64(0)     // CreationTime (0 = don't change)
	w.WriteUint64(0)     // LastAccessTime (0 = don't change)
	w.WriteUint64(newFT) // LastWriteTime
	w.WriteUint64(0)     // ChangeTime (0 = don't change)
	w.WriteUint32(0)     // FileAttributes (0 = don't change)
	w.WriteUint32(0)     // Reserved

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileBasicInformation, w.Bytes())

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}
}

func TestSetInfo_FileDispositionInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE, FILE_OPEN, 0)

	// FileDispositionInformation: 1 byte
	buffer := []byte{1} // DeletePending = true

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileDispositionInformation, buffer)

	if status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", status)
	}
}

func TestSetInfo_FileEndOfFileInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA, FILE_OPEN, 0)

	// FileEndOfFileInformation: 8 bytes
	w := NewByteWriter(8)
	w.WriteUint64(5) // Truncate to 5 bytes

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileEndOfFileInformation, w.Bytes())

	// memfs may or may not support Truncate, so accept SUCCESS or NOT_SUPPORTED
	if status != STATUS_SUCCESS && status != STATUS_NOT_SUPPORTED {
		t.Fatalf("status = %s, want STATUS_SUCCESS or STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_FileRenameInformation(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|DELETE, FILE_OPEN, 0)

	// Build FileRenameInformation buffer
	newName := "renamed.txt"
	newNameUTF16 := EncodeStringToUTF16LE(newName)

	w := NewByteWriter(20 + len(newNameUTF16))
	w.WriteOneByte(1)                           // ReplaceIfExists
	w.WriteBytes(make([]byte, 7))               // Reserved (7 bytes)
	w.WriteUint64(0)                            // RootDirectory
	w.WriteUint32(uint32(len(newNameUTF16)))    // FileNameLength
	w.WriteBytes(newNameUTF16)                  // FileName

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileRenameInformation, w.Bytes())

	// memfs may or may not support Rename, so accept SUCCESS or NOT_SUPPORTED
	if status != STATUS_SUCCESS && status != STATUS_NOT_SUPPORTED {
		t.Fatalf("status = %s, want STATUS_SUCCESS or STATUS_NOT_SUPPORTED", status)
	}
}

func TestSetInfo_ReadOnlyShare(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	// Add a read-only share with a file in it
	roFS, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("memfs.NewFS failed: %v", err)
	}
	f, err := roFS.Create("/readonly.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	_, _ = f.Write([]byte("read only content"))
	f.Close()

	if err := env.server.AddShare(roFS, ShareOptions{
		ShareName:  "roshare",
		SharePath:  "/",
		ReadOnly:   true,
		AllowGuest: true,
	}); err != nil {
		t.Fatalf("AddShare failed: %v", err)
	}

	roTreeID := connectTree(t, env, sessionID, "roshare")

	fileID := openFileViaCreate(t, env, sessionID, roTreeID, "readonly.txt",
		FILE_READ_DATA|FILE_READ_ATTRIBUTES, FILE_OPEN, 0)

	// Try to set basic info on a read-only share
	w := NewByteWriter(40)
	w.WriteUint64(0) // CreationTime
	w.WriteUint64(0) // LastAccessTime
	w.WriteUint64(TimeToFiletime(time.Now()))
	w.WriteUint64(0)     // ChangeTime
	w.WriteUint32(0)     // FileAttributes
	w.WriteUint32(0)     // Reserved

	_, status := sendSetInfo(t, env, sessionID, roTreeID, fileID,
		SMB2_0_INFO_FILE, FileBasicInformation, w.Bytes())

	if status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", status)
	}
}

func TestSetInfo_InvalidHandle(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	bogusFileID := FileID{Persistent: 0xDEADBEEF, Volatile: 0xCAFEBABE}

	w := NewByteWriter(40)
	for i := 0; i < 40; i++ {
		w.WriteOneByte(0)
	}

	_, status := sendSetInfo(t, env, sessionID, treeID, bogusFileID,
		SMB2_0_INFO_FILE, FileBasicInformation, w.Bytes())

	if status != STATUS_FILE_CLOSED {
		t.Errorf("status = %s, want STATUS_FILE_CLOSED", status)
	}
}

func TestSetInfo_UnsupportedClass(t *testing.T) {
	withFixedTime(t)
	env, sessionID, treeID := fullTestSetup(t)

	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES, FILE_OPEN, 0)

	// Use an unsupported file info class (e.g., FileStreamInformation = 22)
	buffer := make([]byte, 16)

	_, status := sendSetInfo(t, env, sessionID, treeID, fileID,
		SMB2_0_INFO_FILE, FileStreamInformation, buffer)

	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", status)
	}
}
