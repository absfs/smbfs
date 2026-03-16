package smbfs

import (
	"encoding/binary"
	"io/fs"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: dirTestFileInfo implements os.FileInfo for unit tests
// ---------------------------------------------------------------------------

type dirTestFileInfo struct {
	fname    string
	fsize    int64
	fmode    fs.FileMode
	fmodTime time.Time
	fisDir   bool
}

func (m *dirTestFileInfo) Name() string      { return m.fname }
func (m *dirTestFileInfo) Size() int64        { return m.fsize }
func (m *dirTestFileInfo) Mode() fs.FileMode  { return m.fmode }
func (m *dirTestFileInfo) ModTime() time.Time { return m.fmodTime }
func (m *dirTestFileInfo) IsDir() bool        { return m.fisDir }
func (m *dirTestFileInfo) Sys() any           { return nil }

func newDirTestFileInfo(name string, size int64, isDir bool) *dirTestFileInfo {
	mode := fs.FileMode(0644)
	if isDir {
		mode = fs.ModeDir | 0755
	}
	return &dirTestFileInfo{
		fname:    name,
		fsize:    size,
		fmode:    mode,
		fmodTime: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		fisDir:   isDir,
	}
}

// ---------------------------------------------------------------------------
// Pure function tests
// ---------------------------------------------------------------------------

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "anything", true},
		{"*.txt", "file.txt", true},
		{"*.txt", "file.doc", false},
		{"file.*", "file.txt", true},
		{"FILE.TXT", "file.txt", true},
		{"readme.md", "readme.md", true},
		{"*.*", "file.txt", true},
		{"?", "a", true},
		{"", "", true},
		{"nope.txt", "other.txt", false},
		{"*.go", "main.go", true},
		{"*.go", "main.c", false},
		{"test?", "test1", true},
		{"test?", "testAB", false},
		{"*", "", true},
		{"*.TXT", "readme.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := matchPattern(tt.name, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.name, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestFilterEntries(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	entries := []dirTestFileInfo{
		*newDirTestFileInfo("readme.txt", 100, false),
		*newDirTestFileInfo("main.go", 200, false),
		*newDirTestFileInfo("notes.txt", 50, false),
		*newDirTestFileInfo("subdir", 0, true),
		*newDirTestFileInfo("data.csv", 1024, false),
	}

	// Convert to []os.FileInfo
	toOSInfos := func(mocks []dirTestFileInfo) []os.FileInfo {
		out := make([]os.FileInfo, len(mocks))
		for i := range mocks {
			out[i] = &mocks[i]
		}
		return out
	}

	tests := []struct {
		name    string
		pattern string
		want    int
		names   []string
	}{
		{"wildcard_all", "*", 5, nil},
		{"txt_only", "*.txt", 2, []string{"readme.txt", "notes.txt"}},
		{"go_only", "*.go", 1, []string{"main.go"}},
		{"exact_match", "data.csv", 1, []string{"data.csv"}},
		{"no_match", "*.xyz", 0, nil},
		{"question_mark", "????.go", 1, []string{"main.go"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos := toOSInfos(entries)
			got := env.handler.filterEntries(infos, tt.pattern)
			if len(got) != tt.want {
				t.Errorf("filterEntries(%q): got %d entries, want %d", tt.pattern, len(got), tt.want)
			}
			if tt.names != nil {
				for i, name := range tt.names {
					if i >= len(got) {
						break
					}
					if got[i].Name() != name {
						t.Errorf("filterEntries(%q)[%d].Name() = %q, want %q", tt.pattern, i, got[i].Name(), name)
					}
				}
			}
		})
	}
}

func TestFormatDirEntry(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	fileInfo := newDirTestFileInfo("test.txt", 1234, false)
	dirInfo := newDirTestFileInfo("subdir", 0, true)

	nameUTF16Len := len(EncodeStringToUTF16LE("test.txt"))

	t.Run("FileDirectoryInformation", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, FileDirectoryInformation, 0)
		if data == nil {
			t.Fatal("formatDirEntry returned nil for FileDirectoryInformation")
		}
		// Base structure: 64 bytes + name
		expectedMinLen := 64 + nameUTF16Len
		if len(data) != expectedMinLen {
			t.Errorf("len = %d, want %d", len(data), expectedMinLen)
		}
		// NextEntryOffset should be 0 (backpatched later)
		nextOffset := binary.LittleEndian.Uint32(data[0:4])
		if nextOffset != 0 {
			t.Errorf("NextEntryOffset = %d, want 0", nextOffset)
		}
		// FileNameLength should match name
		fnLen := binary.LittleEndian.Uint32(data[60:64])
		if fnLen != uint32(nameUTF16Len) {
			t.Errorf("FileNameLength = %d, want %d", fnLen, nameUTF16Len)
		}
		// EndOfFile should be 1234
		eof := binary.LittleEndian.Uint64(data[40:48])
		if eof != 1234 {
			t.Errorf("EndOfFile = %d, want 1234", eof)
		}
	})

	t.Run("FileDirectoryInformation_directory", func(t *testing.T) {
		data := env.handler.formatDirEntry(dirInfo, FileDirectoryInformation, 0)
		if data == nil {
			t.Fatal("formatDirEntry returned nil")
		}
		// EndOfFile should be 0 for directory
		eof := binary.LittleEndian.Uint64(data[40:48])
		if eof != 0 {
			t.Errorf("EndOfFile = %d, want 0 for directory", eof)
		}
		// AllocationSize should be 0 for directory
		alloc := binary.LittleEndian.Uint64(data[48:56])
		if alloc != 0 {
			t.Errorf("AllocationSize = %d, want 0 for directory", alloc)
		}
	})

	t.Run("FileBothDirectoryInformation", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, FileBothDirectoryInformation, 1)
		if data == nil {
			t.Fatal("formatDirEntry returned nil for FileBothDirectoryInformation")
		}
		// Base structure: 94 bytes + name (includes ShortName area of 24 bytes)
		expectedMinLen := 94 + nameUTF16Len
		if len(data) != expectedMinLen {
			t.Errorf("len = %d, want %d", len(data), expectedMinLen)
		}
		// FileIndex should be 1
		fileIndex := binary.LittleEndian.Uint32(data[4:8])
		if fileIndex != 1 {
			t.Errorf("FileIndex = %d, want 1", fileIndex)
		}
		// ShortNameLength at offset 66 should be 0
		if data[66] != 0 {
			t.Errorf("ShortNameLength = %d, want 0", data[66])
		}
	})

	t.Run("FileNamesInformation", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, FileNamesInformation, 2)
		if data == nil {
			t.Fatal("formatDirEntry returned nil for FileNamesInformation")
		}
		// Minimal: 12 bytes header + name
		expectedLen := 12 + nameUTF16Len
		if len(data) != expectedLen {
			t.Errorf("len = %d, want %d", len(data), expectedLen)
		}
		// FileIndex at offset 4 should be 2
		fileIndex := binary.LittleEndian.Uint32(data[4:8])
		if fileIndex != 2 {
			t.Errorf("FileIndex = %d, want 2", fileIndex)
		}
		// FileNameLength
		fnLen := binary.LittleEndian.Uint32(data[8:12])
		if fnLen != uint32(nameUTF16Len) {
			t.Errorf("FileNameLength = %d, want %d", fnLen, nameUTF16Len)
		}
	})

	t.Run("FileIdBothDirectoryInformation", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, FileIdBothDirectoryInformation, 5)
		if data == nil {
			t.Fatal("formatDirEntry returned nil for FileIdBothDirectoryInformation")
		}
		// Base structure: 104 bytes + name
		expectedLen := 104 + nameUTF16Len
		if len(data) != expectedLen {
			t.Errorf("len = %d, want %d", len(data), expectedLen)
		}
		// FileId at offset 96 should equal fileIndex as uint64
		fileID := binary.LittleEndian.Uint64(data[96:104])
		if fileID != 5 {
			t.Errorf("FileId = %d, want 5", fileID)
		}
	})

	t.Run("FileFullDirectoryInformation", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, FileFullDirectoryInformation, 3)
		if data == nil {
			t.Fatal("formatDirEntry returned nil for FileFullDirectoryInformation")
		}
		// Base: 68 bytes + name
		expectedLen := 68 + nameUTF16Len
		if len(data) != expectedLen {
			t.Errorf("len = %d, want %d", len(data), expectedLen)
		}
		// EaSize at offset 64 should be 0
		eaSize := binary.LittleEndian.Uint32(data[64:68])
		if eaSize != 0 {
			t.Errorf("EaSize = %d, want 0", eaSize)
		}
	})

	t.Run("UnsupportedInfoClass", func(t *testing.T) {
		data := env.handler.formatDirEntry(fileInfo, 0xFF, 0)
		if data != nil {
			t.Errorf("formatDirEntry with unsupported info class returned non-nil data of len %d", len(data))
		}
	})
}

func TestGetStoreDirState(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{Logger: &NullLogger{}})

	t.Cleanup(func() {
		dirStatesMu.Lock()
		dirStates = make(map[FileID]*dirEnumState)
		dirStatesMu.Unlock()
	})

	of := &OpenFile{
		ID: FileID{Persistent: 42, Volatile: 99},
	}

	// Initially should be nil
	got := env.handler.getDirState(of)
	if got != nil {
		t.Fatalf("getDirState on fresh state: expected nil, got %+v", got)
	}

	// Store a state
	state := &dirEnumState{
		pattern:   "*.txt",
		position:  3,
		exhausted: false,
	}
	env.handler.storeDirState(of, state)

	// Retrieve it
	got = env.handler.getDirState(of)
	if got == nil {
		t.Fatal("getDirState after store: expected non-nil")
	}
	if got != state {
		t.Error("getDirState returned different object than what was stored")
	}
	if got.pattern != "*.txt" {
		t.Errorf("pattern = %q, want %q", got.pattern, "*.txt")
	}
	if got.position != 3 {
		t.Errorf("position = %d, want 3", got.position)
	}

	// Different FileID should return nil
	of2 := &OpenFile{
		ID: FileID{Persistent: 100, Volatile: 200},
	}
	got2 := env.handler.getDirState(of2)
	if got2 != nil {
		t.Errorf("getDirState for different FileID: expected nil, got %+v", got2)
	}
}

// ---------------------------------------------------------------------------
// Handler tests (full negotiate + auth + tree connect pipeline)
// ---------------------------------------------------------------------------

// openDir is a test helper that opens a directory via CREATE and returns the FileID.
func openDir(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, path string) FileID {
	t.Helper()
	msg := buildCreateMsg(sessionID, treeID, path,
		FILE_READ_DATA|FILE_READ_ATTRIBUTES,
		FILE_OPEN,
		FILE_DIRECTORY_FILE,
	)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("openDir(%q): HandleMessage error: %v", path, err)
	}
	if resp == nil {
		t.Fatalf("openDir(%q): nil response", path)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("openDir(%q): status = %s, want STATUS_SUCCESS", path, resp.Header.Status)
	}
	return parseCreateResponse(t, resp.Payload)
}

// openFile is a test helper that opens a regular file via CREATE and returns the FileID.
func openFile(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, path string) FileID {
	t.Helper()
	msg := buildCreateMsg(sessionID, treeID, path,
		FILE_READ_DATA|FILE_READ_ATTRIBUTES,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
	)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("openFile(%q): HandleMessage error: %v", path, err)
	}
	if resp == nil {
		t.Fatalf("openFile(%q): nil response", path)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("openFile(%q): status = %s, want STATUS_SUCCESS", path, resp.Header.Status)
	}
	return parseCreateResponse(t, resp.Payload)
}

// queryDir sends a QUERY_DIRECTORY and returns the response message.
func queryDir(t *testing.T, env *handlerEnv, sessionID uint64, treeID uint32, fileID FileID, pattern string, infoClass, flags uint8) *SMB2Message {
	t.Helper()
	msg := buildQueryDirMsg(sessionID, treeID, fileID, pattern, infoClass, flags)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("queryDir: HandleMessage error: %v", err)
	}
	if resp == nil {
		t.Fatal("queryDir: nil response")
	}
	return resp
}

// countDirEntries extracts the number of entries from a QUERY_DIRECTORY
// FileNamesInformation response by walking NextEntryOffset chains.
func countDirEntries(t *testing.T, payload []byte) int {
	t.Helper()
	if len(payload) < 9 {
		t.Fatalf("QUERY_DIRECTORY response too short: %d", len(payload))
	}

	r := NewByteReader(payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	bufLen := r.ReadUint32()

	if bufLen == 0 {
		return 0
	}

	buf := payload[8 : 8+bufLen]
	count := 0
	offset := 0
	for offset < len(buf) {
		count++
		if offset+4 > len(buf) {
			break
		}
		nextEntry := binary.LittleEndian.Uint32(buf[offset : offset+4])
		if nextEntry == 0 {
			break
		}
		offset += int(nextEntry)
	}
	return count
}

// extractDirNames extracts file names from a FileNamesInformation response.
func extractDirNames(t *testing.T, payload []byte) []string {
	t.Helper()
	if len(payload) < 9 {
		t.Fatalf("QUERY_DIRECTORY response too short: %d", len(payload))
	}

	r := NewByteReader(payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // OutputBufferOffset
	bufLen := r.ReadUint32()

	if bufLen == 0 {
		return nil
	}

	buf := payload[8 : 8+bufLen]
	var names []string
	offset := 0
	for offset < len(buf) {
		if offset+12 > len(buf) {
			break
		}
		nextEntry := binary.LittleEndian.Uint32(buf[offset : offset+4])
		// FileIndex at offset+4
		nameLen := binary.LittleEndian.Uint32(buf[offset+8 : offset+12])
		nameStart := offset + 12
		if nameStart+int(nameLen) > len(buf) {
			break
		}
		name := DecodeUTF16LEToString(buf[nameStart : nameStart+int(nameLen)])
		names = append(names, name)
		if nextEntry == 0 {
			break
		}
		offset += int(nextEntry)
	}
	return names
}

func cleanupDirStates(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		dirStatesMu.Lock()
		dirStates = make(map[FileID]*dirEnumState)
		dirStatesMu.Unlock()
	})
}

func TestQueryDirectory_ListRoot(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	resp := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, 0)
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("QUERY_DIRECTORY status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	names := extractDirNames(t, resp.Payload)
	if len(names) < 2 {
		t.Fatalf("expected at least 2 entries (test.txt, subdir), got %d: %v", len(names), names)
	}

	// Verify expected files are present
	found := make(map[string]bool)
	for _, n := range names {
		found[n] = true
	}
	if !found["test.txt"] {
		t.Errorf("test.txt not found in directory listing: %v", names)
	}
	if !found["subdir"] {
		t.Errorf("subdir not found in directory listing: %v", names)
	}
}

func TestQueryDirectory_Exhausted(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	// First query with SINGLE_ENTRY to step through one at a time
	seenNames := make(map[string]bool)
	for i := 0; i < 100; i++ { // safety limit
		var flags uint8
		if i == 0 {
			flags = SMB2_RETURN_SINGLE_ENTRY
		} else {
			flags = SMB2_RETURN_SINGLE_ENTRY
		}
		resp := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, flags)
		if resp.Header.Status == STATUS_NO_MORE_FILES {
			break
		}
		if resp.Header.Status != STATUS_SUCCESS {
			t.Fatalf("iteration %d: unexpected status %s", i, resp.Header.Status)
		}
		names := extractDirNames(t, resp.Payload)
		for _, n := range names {
			seenNames[n] = true
		}
	}

	if len(seenNames) < 2 {
		t.Errorf("expected at least 2 entries after exhaustion, got %d: %v", len(seenNames), seenNames)
	}

	// Next query should return NO_MORE_FILES
	resp := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, 0)
	if resp.Header.Status != STATUS_NO_MORE_FILES {
		t.Errorf("after exhaustion: status = %s, want STATUS_NO_MORE_FILES", resp.Header.Status)
	}
}

func TestQueryDirectory_SpecificPattern(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	resp := queryDir(t, env, sessionID, treeID, dirID, "*.txt", FileNamesInformation, 0)
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("QUERY_DIRECTORY status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	names := extractDirNames(t, resp.Payload)
	for _, n := range names {
		if len(n) < 4 || n[len(n)-4:] != ".txt" {
			t.Errorf("entry %q does not match *.txt pattern", n)
		}
	}

	// The memfs testshare root has exactly one .txt file: test.txt
	if len(names) != 1 {
		t.Errorf("expected 1 .txt entry, got %d: %v", len(names), names)
	}
	if len(names) > 0 && names[0] != "test.txt" {
		t.Errorf("expected test.txt, got %q", names[0])
	}
}

func TestQueryDirectory_NonDirectory(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	fileID := openFile(t, env, sessionID, treeID, "test.txt")

	resp := queryDir(t, env, sessionID, treeID, fileID, "*", FileNamesInformation, 0)
	if resp.Header.Status != STATUS_NOT_A_DIRECTORY {
		t.Errorf("QUERY_DIRECTORY on file: status = %s, want STATUS_NOT_A_DIRECTORY", resp.Header.Status)
	}
}

func TestQueryDirectory_InvalidHandle(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)

	bogusID := FileID{Persistent: 0xDEAD, Volatile: 0xBEEF}
	resp := queryDir(t, env, sessionID, treeID, bogusID, "*", FileNamesInformation, 0)
	if resp.Header.Status != STATUS_FILE_CLOSED {
		t.Errorf("QUERY_DIRECTORY with bogus handle: status = %s, want STATUS_FILE_CLOSED", resp.Header.Status)
	}
}

func TestQueryDirectory_RestartScan(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	// First query: get a single entry to populate the cache and advance position
	resp1 := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, SMB2_RETURN_SINGLE_ENTRY)
	if resp1.Header.Status != STATUS_SUCCESS {
		t.Fatalf("first QUERY_DIRECTORY status = %s, want STATUS_SUCCESS", resp1.Header.Status)
	}
	firstName := extractDirNames(t, resp1.Payload)
	if len(firstName) != 1 {
		t.Fatalf("expected 1 entry from SINGLE_ENTRY query, got %d", len(firstName))
	}

	// Second query: get another single entry to advance position further
	resp2 := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, SMB2_RETURN_SINGLE_ENTRY)
	if resp2.Header.Status != STATUS_SUCCESS {
		t.Fatalf("second QUERY_DIRECTORY status = %s, want STATUS_SUCCESS", resp2.Header.Status)
	}

	// Restart scan: should reset position to 0 and return entries from the beginning.
	// Note: RESTART_SCANS clears the cached entries, forcing a re-read. Since the
	// underlying file handle may have been consumed, open a fresh handle instead.
	dirID2 := openDir(t, env, sessionID, treeID, "")
	resp3 := queryDir(t, env, sessionID, treeID, dirID2, "*", FileNamesInformation, SMB2_RESTART_SCANS)
	if resp3.Header.Status != STATUS_SUCCESS {
		t.Fatalf("QUERY_DIRECTORY with RESTART_SCANS: status = %s, want STATUS_SUCCESS", resp3.Header.Status)
	}
	restartNames := extractDirNames(t, resp3.Payload)

	// Should get at least 2 entries (test.txt and subdir)
	if len(restartNames) < 2 {
		t.Errorf("after restart: got %d entries, want >= 2: %v", len(restartNames), restartNames)
	}

	// The first entry from the initial scan should appear in the restarted results
	found := false
	for _, n := range restartNames {
		if n == firstName[0] {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("after restart: first entry %q from initial scan not found in restarted results %v", firstName[0], restartNames)
	}
}

func TestQueryDirectory_MultipleInfoClasses(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)

	infoClasses := []struct {
		name  string
		class uint8
	}{
		{"FileDirectoryInformation", FileDirectoryInformation},
		{"FileFullDirectoryInformation", FileFullDirectoryInformation},
		{"FileBothDirectoryInformation", FileBothDirectoryInformation},
		{"FileNamesInformation", FileNamesInformation},
		{"FileIdBothDirectoryInformation", FileIdBothDirectoryInformation},
	}

	for _, ic := range infoClasses {
		t.Run(ic.name, func(t *testing.T) {
			// Clear dir states for a clean slate per subtest
			dirStatesMu.Lock()
			dirStates = make(map[FileID]*dirEnumState)
			dirStatesMu.Unlock()

			dirID := openDir(t, env, sessionID, treeID, "")
			resp := queryDir(t, env, sessionID, treeID, dirID, "*", ic.class, 0)
			if resp.Header.Status != STATUS_SUCCESS {
				t.Fatalf("QUERY_DIRECTORY with %s: status = %s", ic.name, resp.Header.Status)
			}
			count := countDirEntries(t, resp.Payload)
			if count < 2 {
				t.Errorf("QUERY_DIRECTORY with %s: got %d entries, want >= 2", ic.name, count)
			}
		})
	}
}

func TestQueryDirectory_UnsupportedInfoClass(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	resp := queryDir(t, env, sessionID, treeID, dirID, "*", 0xFF, 0)
	if resp.Header.Status != STATUS_NOT_SUPPORTED {
		t.Errorf("QUERY_DIRECTORY with unsupported info class: status = %s, want STATUS_NOT_SUPPORTED", resp.Header.Status)
	}
}

func TestQueryDirectory_InvalidPayload(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)

	// Send a QUERY_DIRECTORY with a truncated payload (too short)
	msg := &SMB2Message{
		Header:  makeHeader(SMB2_QUERY_DIRECTORY, sessionID, treeID),
		Payload: []byte{0x01, 0x02}, // way too short
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("short payload: status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestQueryDirectory_SingleEntry(t *testing.T) {
	cleanupDirStates(t)

	env, sessionID, treeID := fullTestSetup(t)
	dirID := openDir(t, env, sessionID, treeID, "")

	resp := queryDir(t, env, sessionID, treeID, dirID, "*", FileNamesInformation, SMB2_RETURN_SINGLE_ENTRY)
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("QUERY_DIRECTORY with SINGLE_ENTRY: status = %s", resp.Header.Status)
	}

	count := countDirEntries(t, resp.Payload)
	if count != 1 {
		t.Errorf("SINGLE_ENTRY: got %d entries, want 1", count)
	}
}
