package smbfs

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"testing"
)

// ---------------------------------------------------------------------------
// handleCreate tests
// ---------------------------------------------------------------------------

func TestCreate_OpenExistingFile(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	fileID := parseCreateResponse(t, resp.Payload)
	if fileID.IsZero() {
		t.Error("returned FileID is zero")
	}

	// Verify create action is FILE_OPENED
	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_OPENED {
		t.Errorf("CreateAction = %d, want FILE_OPENED (%d)", createAction, FILE_OPENED)
	}
}

func TestCreate_CreateNewFile(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "newfile.txt", GENERIC_WRITE, FILE_CREATE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	fileID := parseCreateResponse(t, resp.Payload)
	if fileID.IsZero() {
		t.Error("returned FileID is zero")
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}
}

func TestCreate_OpenIfExists(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	fileID := parseCreateResponse(t, resp.Payload)
	if fileID.IsZero() {
		t.Error("returned FileID is zero")
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_OPENED {
		t.Errorf("CreateAction = %d, want FILE_OPENED (%d)", createAction, FILE_OPENED)
	}
}

func TestCreate_OpenIfNotExists(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "brand_new.txt", GENERIC_WRITE, FILE_OPEN_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	fileID := parseCreateResponse(t, resp.Payload)
	if fileID.IsZero() {
		t.Error("returned FileID is zero")
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}
}

func TestCreate_OpenNonExistent(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "nosuchfile.txt", GENERIC_READ, FILE_OPEN, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_OBJECT_NAME_NOT_FOUND {
		t.Errorf("status = %s, want STATUS_OBJECT_NAME_NOT_FOUND", resp.Header.Status)
	}
}

func TestCreate_CreateDuplicate(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_WRITE, FILE_CREATE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_OBJECT_NAME_COLLISION {
		t.Errorf("status = %s, want STATUS_OBJECT_NAME_COLLISION", resp.Header.Status)
	}
}

func TestCreate_OpenDirectory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_READ, FILE_OPEN, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	fileID := parseCreateResponse(t, resp.Payload)
	if fileID.IsZero() {
		t.Error("returned FileID is zero")
	}

	// Verify file attributes include DIRECTORY
	attrs := binary.LittleEndian.Uint32(resp.Payload[56:60])
	if attrs&FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.Errorf("attributes = 0x%08x, expected FILE_ATTRIBUTE_DIRECTORY bit set", attrs)
	}
}

func TestCreate_DeleteOnClose(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a new file with DELETE_ON_CLOSE
	createMsg := buildCreateMsg(sessionID, treeID, "ephemeral.txt",
		GENERIC_READ|GENERIC_WRITE|DELETE, FILE_CREATE, FILE_DELETE_ON_CLOSE)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s, want STATUS_SUCCESS", createResp.Header.Status)
	}

	fileID := parseCreateResponse(t, createResp.Payload)

	// Close the file — this should trigger deletion
	closeMsg := buildCloseMsg(sessionID, treeID, fileID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CLOSE status = %s, want STATUS_SUCCESS", closeResp.Header.Status)
	}

	// Verify the file is gone by trying to open it
	openMsg := buildCreateMsg(sessionID, treeID, "ephemeral.txt", GENERIC_READ, FILE_OPEN, 0)
	openResp, err := env.handler.HandleMessage(env.state, openMsg)
	if err != nil {
		t.Fatalf("HandleMessage(re-open) error: %v", err)
	}
	if openResp.Header.Status != STATUS_OBJECT_NAME_NOT_FOUND {
		t.Errorf("re-open status = %s, want STATUS_OBJECT_NAME_NOT_FOUND", openResp.Header.Status)
	}
}

// ---------------------------------------------------------------------------
// handleClose tests
// ---------------------------------------------------------------------------

func TestClose_ValidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open a file first
	createMsg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s, want STATUS_SUCCESS", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Close it
	closeMsg := buildCloseMsg(sessionID, treeID, fileID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Errorf("CLOSE status = %s, want STATUS_SUCCESS", closeResp.Header.Status)
	}

	// Verify response structure size is 60
	if len(closeResp.Payload) >= 2 {
		structSize := binary.LittleEndian.Uint16(closeResp.Payload[0:2])
		if structSize != 60 {
			t.Errorf("CLOSE StructureSize = %d, want 60", structSize)
		}
	}
}

func TestClose_InvalidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	bogusID := FileID{Persistent: 0xDEAD, Volatile: 0xBEEF}
	closeMsg := buildCloseMsg(sessionID, treeID, bogusID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_FILE_CLOSED {
		t.Errorf("CLOSE status = %s, want STATUS_FILE_CLOSED", closeResp.Header.Status)
	}
}

// ---------------------------------------------------------------------------
// handleRead tests
// ---------------------------------------------------------------------------

func TestRead_FileContent(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open test.txt (contains "hello world")
	createMsg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Read full content
	readMsg := buildReadMsg(sessionID, treeID, fileID, 0, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("READ status = %s, want STATUS_SUCCESS", readResp.Header.Status)
	}

	// Parse READ response: StructureSize(2) + DataOffset(1) + Reserved(1) + DataLength(4) + DataRemaining(4) + Reserved2(4) = 16 bytes header, then data
	if len(readResp.Payload) < 16 {
		t.Fatalf("READ response too short: %d bytes", len(readResp.Payload))
	}
	dataLength := binary.LittleEndian.Uint32(readResp.Payload[4:8])
	if dataLength == 0 {
		t.Fatal("READ returned 0 bytes")
	}
	data := readResp.Payload[16 : 16+dataLength]
	if string(data) != "hello world" {
		t.Errorf("READ data = %q, want %q", string(data), "hello world")
	}
}

func TestRead_WithOffset(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open test.txt (contains "hello world")
	createMsg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Read from offset 6 — should get "world"
	readMsg := buildReadMsg(sessionID, treeID, fileID, 6, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("READ status = %s, want STATUS_SUCCESS", readResp.Header.Status)
	}

	dataLength := binary.LittleEndian.Uint32(readResp.Payload[4:8])
	data := readResp.Payload[16 : 16+dataLength]
	if string(data) != "world" {
		t.Errorf("READ data = %q, want %q", string(data), "world")
	}
}

func TestRead_PastEOF(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open test.txt (11 bytes: "hello world")
	createMsg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Read well past end of file
	readMsg := buildReadMsg(sessionID, treeID, fileID, 99999, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_END_OF_FILE {
		t.Errorf("READ status = %s, want STATUS_END_OF_FILE", readResp.Header.Status)
	}
}

func TestRead_InvalidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	bogusID := FileID{Persistent: 0xDEAD, Volatile: 0xBEEF}
	readMsg := buildReadMsg(sessionID, treeID, bogusID, 0, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_FILE_CLOSED {
		t.Errorf("READ status = %s, want STATUS_FILE_CLOSED", readResp.Header.Status)
	}
}

// ---------------------------------------------------------------------------
// handleWrite tests
// ---------------------------------------------------------------------------

func TestWrite_Data(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a new file
	createMsg := buildCreateMsg(sessionID, treeID, "writable.txt", GENERIC_READ|GENERIC_WRITE, FILE_CREATE, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Write data
	writeData := []byte("test write content")
	writeMsg := buildWriteMsg(sessionID, treeID, fileID, 0, writeData)
	writeResp, err := env.handler.HandleMessage(env.state, writeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(WRITE) error: %v", err)
	}
	if writeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("WRITE status = %s, want STATUS_SUCCESS", writeResp.Header.Status)
	}

	// Verify write count in response: StructureSize(2) + Reserved(2) + Count(4)
	if len(writeResp.Payload) < 8 {
		t.Fatalf("WRITE response too short: %d bytes", len(writeResp.Payload))
	}
	writeCount := binary.LittleEndian.Uint32(writeResp.Payload[4:8])
	if writeCount != uint32(len(writeData)) {
		t.Errorf("WRITE count = %d, want %d", writeCount, len(writeData))
	}

	// Close the file
	closeMsg := buildCloseMsg(sessionID, treeID, fileID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CLOSE status = %s", closeResp.Header.Status)
	}

	// Re-open and read back
	openMsg := buildCreateMsg(sessionID, treeID, "writable.txt", GENERIC_READ, FILE_OPEN, 0)
	openResp, err := env.handler.HandleMessage(env.state, openMsg)
	if err != nil {
		t.Fatalf("HandleMessage(re-open) error: %v", err)
	}
	if openResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("re-open status = %s", openResp.Header.Status)
	}
	fileID2 := parseCreateResponse(t, openResp.Payload)

	readMsg := buildReadMsg(sessionID, treeID, fileID2, 0, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("READ status = %s", readResp.Header.Status)
	}

	dataLength := binary.LittleEndian.Uint32(readResp.Payload[4:8])
	data := readResp.Payload[16 : 16+dataLength]
	if string(data) != "test write content" {
		t.Errorf("READ back data = %q, want %q", string(data), "test write content")
	}
}

func TestWrite_AtOffset(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a new file and write initial content
	createMsg := buildCreateMsg(sessionID, treeID, "offsetwrite.txt", GENERIC_READ|GENERIC_WRITE, FILE_CREATE, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Write "AAAAAAAAAA" (10 bytes of 'A') at offset 0
	initialData := []byte("AAAAAAAAAA")
	writeMsg := buildWriteMsg(sessionID, treeID, fileID, 0, initialData)
	writeResp, err := env.handler.HandleMessage(env.state, writeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(WRITE initial) error: %v", err)
	}
	if writeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("WRITE initial status = %s", writeResp.Header.Status)
	}

	// Write "BBB" at offset 5
	patchData := []byte("BBB")
	writeMsg2 := buildWriteMsg(sessionID, treeID, fileID, 5, patchData)
	writeResp2, err := env.handler.HandleMessage(env.state, writeMsg2)
	if err != nil {
		t.Fatalf("HandleMessage(WRITE offset) error: %v", err)
	}
	if writeResp2.Header.Status != STATUS_SUCCESS {
		t.Fatalf("WRITE offset status = %s", writeResp2.Header.Status)
	}

	// Read back full content
	readMsg := buildReadMsg(sessionID, treeID, fileID, 0, 4096)
	readResp, err := env.handler.HandleMessage(env.state, readMsg)
	if err != nil {
		t.Fatalf("HandleMessage(READ) error: %v", err)
	}
	if readResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("READ status = %s", readResp.Header.Status)
	}

	dataLength := binary.LittleEndian.Uint32(readResp.Payload[4:8])
	data := readResp.Payload[16 : 16+dataLength]
	expected := "AAAAABBBAA"
	if string(data) != expected {
		t.Errorf("READ data = %q, want %q", string(data), expected)
	}
}

// ---------------------------------------------------------------------------
// handleFlush tests
// ---------------------------------------------------------------------------

func TestFlush_ValidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open a file
	createMsg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, 0)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Flush
	flushMsg := buildFlushMsg(sessionID, treeID, fileID)
	flushResp, err := env.handler.HandleMessage(env.state, flushMsg)
	if err != nil {
		t.Fatalf("HandleMessage(FLUSH) error: %v", err)
	}
	if flushResp.Header.Status != STATUS_SUCCESS {
		t.Errorf("FLUSH status = %s, want STATUS_SUCCESS", flushResp.Header.Status)
	}

	// Verify response structure size is 4
	if len(flushResp.Payload) >= 2 {
		structSize := binary.LittleEndian.Uint16(flushResp.Payload[0:2])
		if structSize != 4 {
			t.Errorf("FLUSH StructureSize = %d, want 4", structSize)
		}
	}
}

func TestFlush_InvalidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	bogusID := FileID{Persistent: 0xDEAD, Volatile: 0xBEEF}
	flushMsg := buildFlushMsg(sessionID, treeID, bogusID)
	flushResp, err := env.handler.HandleMessage(env.state, flushMsg)
	if err != nil {
		t.Fatalf("HandleMessage(FLUSH) error: %v", err)
	}
	if flushResp.Header.Status != STATUS_FILE_CLOSED {
		t.Errorf("FLUSH status = %s, want STATUS_FILE_CLOSED", flushResp.Header.Status)
	}
}

// ---------------------------------------------------------------------------
// mapGenericAccess tests
// ---------------------------------------------------------------------------

func TestMapGenericAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		wantBits uint32 // bits that must be set in result
	}{
		{
			name:     "GENERIC_READ",
			input:    GENERIC_READ,
			wantBits: FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
		},
		{
			name:     "GENERIC_WRITE",
			input:    GENERIC_WRITE,
			wantBits: FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | SYNCHRONIZE,
		},
		{
			name:     "GENERIC_EXECUTE",
			input:    GENERIC_EXECUTE,
			wantBits: FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		},
		{
			name:  "GENERIC_ALL",
			input: GENERIC_ALL,
			wantBits: FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
				FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | FILE_DELETE_CHILD |
				FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | READ_CONTROL |
				WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,
		},
		{
			name:     "GENERIC_READ|GENERIC_WRITE combined",
			input:    GENERIC_READ | GENERIC_WRITE,
			wantBits: FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
		},
		{
			name:     "no generic flags passthrough",
			input:    FILE_READ_DATA | FILE_WRITE_DATA,
			wantBits: FILE_READ_DATA | FILE_WRITE_DATA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapGenericAccess(tt.input)
			if result&tt.wantBits != tt.wantBits {
				t.Errorf("mapGenericAccess(0x%08x) = 0x%08x, missing expected bits 0x%08x",
					tt.input, result, tt.wantBits&^result)
			}
		})
	}

	// Passthrough: when no generic flags are set, result should equal input
	t.Run("passthrough preserves input", func(t *testing.T) {
		input := FILE_READ_DATA | FILE_WRITE_DATA | DELETE
		result := mapGenericAccess(input)
		if result != input {
			t.Errorf("mapGenericAccess(0x%08x) = 0x%08x, want exact passthrough", input, result)
		}
	})
}

// ---------------------------------------------------------------------------
// mapGoErrorToNTStatus tests
// ---------------------------------------------------------------------------

func TestMapGoErrorToNTStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want NTStatus
	}{
		{"nil", nil, STATUS_SUCCESS},
		{"fs.ErrNotExist", fs.ErrNotExist, STATUS_OBJECT_NAME_NOT_FOUND},
		{"fs.ErrExist", fs.ErrExist, STATUS_OBJECT_NAME_COLLISION},
		{"fs.ErrPermission", fs.ErrPermission, STATUS_ACCESS_DENIED},
		{"fs.ErrInvalid", fs.ErrInvalid, STATUS_INVALID_PARAMETER},
		{"fs.ErrClosed", fs.ErrClosed, STATUS_FILE_CLOSED},
		{"io.EOF", io.EOF, STATUS_END_OF_FILE},
		{"ErrIsDirectory", ErrIsDirectory, STATUS_FILE_IS_A_DIRECTORY},
		{"ErrNotDirectory", ErrNotDirectory, STATUS_NOT_A_DIRECTORY},
		{"unknown error", errors.New("something unexpected"), STATUS_INVALID_DEVICE_REQUEST},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapGoErrorToNTStatus(tt.err)
			if got != tt.want {
				t.Errorf("mapGoErrorToNTStatus(%v) = %s, want %s", tt.err, got, tt.want)
			}
		})
	}

	// Verify wrapped errors also match (errors.Is semantics)
	t.Run("wrapped fs.ErrNotExist", func(t *testing.T) {
		wrapped := &fs.PathError{Op: "open", Path: "/foo", Err: fs.ErrNotExist}
		got := mapGoErrorToNTStatus(wrapped)
		if got != STATUS_OBJECT_NAME_NOT_FOUND {
			t.Errorf("mapGoErrorToNTStatus(wrapped ErrNotExist) = %s, want STATUS_OBJECT_NAME_NOT_FOUND", got)
		}
	})

	t.Run("wrapped fs.ErrPermission", func(t *testing.T) {
		wrapped := &fs.PathError{Op: "open", Path: "/bar", Err: fs.ErrPermission}
		got := mapGoErrorToNTStatus(wrapped)
		if got != STATUS_ACCESS_DENIED {
			t.Errorf("mapGoErrorToNTStatus(wrapped ErrPermission) = %s, want STATUS_ACCESS_DENIED", got)
		}
	})
}
