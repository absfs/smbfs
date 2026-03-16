package smbfs

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/absfs/memfs"
)

// ===========================================================================
// 1. handleCreate: FILE_OVERWRITE disposition
// ===========================================================================

func TestCreate_Overwrite(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open existing file with FILE_OVERWRITE disposition
	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ|GENERIC_WRITE, FILE_OVERWRITE, 0)
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

	// Verify create action is FILE_OVERWRITTEN
	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_OVERWRITTEN {
		t.Errorf("CreateAction = %d, want FILE_OVERWRITTEN (%d)", createAction, FILE_OVERWRITTEN)
	}
}

func TestCreate_Overwrite_NonExistent(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OVERWRITE on non-existent file should fail
	msg := buildCreateMsg(sessionID, treeID, "nosuchfile.txt", GENERIC_WRITE, FILE_OVERWRITE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_OBJECT_NAME_NOT_FOUND {
		t.Errorf("status = %s, want STATUS_OBJECT_NAME_NOT_FOUND", resp.Header.Status)
	}
}

func TestCreate_Overwrite_Directory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OVERWRITE on a directory should fail
	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_WRITE, FILE_OVERWRITE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_FILE_IS_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_FILE_IS_A_DIRECTORY", resp.Header.Status)
	}
}

// ===========================================================================
// 1b. handleCreate: FILE_OVERWRITE_IF disposition
// ===========================================================================

func TestCreate_OverwriteIf_Existing(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OVERWRITE_IF on existing file
	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ|GENERIC_WRITE, FILE_OVERWRITE_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_OVERWRITTEN {
		t.Errorf("CreateAction = %d, want FILE_OVERWRITTEN (%d)", createAction, FILE_OVERWRITTEN)
	}
}

func TestCreate_OverwriteIf_NonExistent(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OVERWRITE_IF on non-existent file should create it
	msg := buildCreateMsg(sessionID, treeID, "overwriteif_new.txt", GENERIC_READ|GENERIC_WRITE, FILE_OVERWRITE_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}
}

func TestCreate_OverwriteIf_Directory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OVERWRITE_IF on an existing directory should fail
	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_WRITE, FILE_OVERWRITE_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_FILE_IS_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_FILE_IS_A_DIRECTORY", resp.Header.Status)
	}
}

// ===========================================================================
// 1c. handleCreate: FILE_SUPERSEDE disposition
// ===========================================================================

func TestCreate_Supersede_Existing(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_SUPERSEDE on existing file
	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ|GENERIC_WRITE, FILE_SUPERSEDE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_SUPERSEDED {
		t.Errorf("CreateAction = %d, want FILE_SUPERSEDED (%d)", createAction, FILE_SUPERSEDED)
	}
}

func TestCreate_Supersede_NonExistent(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_SUPERSEDE on non-existent file should create
	msg := buildCreateMsg(sessionID, treeID, "supersede_new.txt", GENERIC_READ|GENERIC_WRITE, FILE_SUPERSEDE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}
}

func TestCreate_Supersede_Directory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_SUPERSEDE on an existing directory should fail
	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_WRITE, FILE_SUPERSEDE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_FILE_IS_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_FILE_IS_A_DIRECTORY", resp.Header.Status)
	}
}

// ===========================================================================
// 1d. handleCreate: Read-only share denies write dispositions
// ===========================================================================

func setupHandlerEnvWithReadOnlyShare(t *testing.T) (*handlerEnv, uint64, uint32) {
	t.Helper()
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})

	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("memfs.NewFS() failed: %v", err)
	}

	f, err := fs.Create("/existing.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	_, _ = f.Write([]byte("content"))
	f.Close()

	if err := env.server.AddShare(fs, ShareOptions{
		ShareName:  "readonly",
		SharePath:  "/",
		AllowGuest: true,
		ReadOnly:   true,
	}); err != nil {
		t.Fatalf("AddShare() failed: %v", err)
	}

	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)
	treeID := connectTree(t, env, sessionID, "readonly")
	return env, sessionID, treeID
}

func TestCreate_ReadOnlyShare_Create(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// FILE_CREATE on read-only share should fail with ACCESS_DENIED
	msg := buildCreateMsg(sessionID, treeID, "newfile.txt", GENERIC_WRITE, FILE_CREATE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", resp.Header.Status)
	}
}

func TestCreate_ReadOnlyShare_Overwrite(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// FILE_OVERWRITE on read-only share should fail with ACCESS_DENIED
	msg := buildCreateMsg(sessionID, treeID, "existing.txt", GENERIC_WRITE, FILE_OVERWRITE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", resp.Header.Status)
	}
}

func TestCreate_ReadOnlyShare_OverwriteIf(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// FILE_OVERWRITE_IF on read-only share should fail with ACCESS_DENIED
	msg := buildCreateMsg(sessionID, treeID, "existing.txt", GENERIC_WRITE, FILE_OVERWRITE_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", resp.Header.Status)
	}
}

func TestCreate_ReadOnlyShare_Supersede(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// FILE_SUPERSEDE on read-only share should fail with ACCESS_DENIED
	msg := buildCreateMsg(sessionID, treeID, "existing.txt", GENERIC_WRITE, FILE_SUPERSEDE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", resp.Header.Status)
	}
}

func TestCreate_ReadOnlyShare_OpenIfCreate(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// FILE_OPEN_IF on non-existent file in read-only share should fail
	msg := buildCreateMsg(sessionID, treeID, "nosuchfile.txt", GENERIC_WRITE, FILE_OPEN_IF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("status = %s, want STATUS_ACCESS_DENIED", resp.Header.Status)
	}
}

// ===========================================================================
// 1e. handleCreate: Invalid disposition
// ===========================================================================

func TestCreate_InvalidDisposition(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, 0xFF, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// ===========================================================================
// 1f. handleCreate: Share access violation
// ===========================================================================

func buildCreateMsgWithShareAccess(sessionID uint64, treeID uint32, filename string, access, shareAccess, disposition, options uint32) *SMB2Message {
	nameUTF16 := EncodeStringToUTF16LE(filename)
	nameOffset := uint16(SMB2HeaderSize + 56)

	w := NewByteWriter(128)
	w.WriteUint16(57)                    // StructureSize
	w.WriteOneByte(0)                    // SecurityFlags
	w.WriteOneByte(0)                    // RequestedOplockLevel
	w.WriteUint32(0x00000002)            // ImpersonationLevel
	w.WriteUint64(0)                     // SmbCreateFlags
	w.WriteUint64(0)                     // Reserved
	w.WriteUint32(access)                // DesiredAccess
	w.WriteUint32(FILE_ATTRIBUTE_NORMAL) // FileAttributes
	w.WriteUint32(shareAccess)           // ShareAccess
	w.WriteUint32(disposition)           // CreateDisposition
	w.WriteUint32(options)               // CreateOptions
	w.WriteUint16(nameOffset)            // NameOffset
	w.WriteUint16(uint16(len(nameUTF16))) // NameLength
	w.WriteUint32(0)                     // CreateContextsOffset
	w.WriteUint32(0)                     // CreateContextsLength
	w.WriteBytes(nameUTF16)

	return &SMB2Message{
		Header:  makeHeader(SMB2_CREATE, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func TestCreate_ShareAccessViolation(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open file with FILE_READ_DATA and exclusive access (no sharing)
	msg1 := buildCreateMsgWithShareAccess(sessionID, treeID, "test.txt", FILE_READ_DATA, 0, FILE_OPEN, 0)
	resp1, err := env.handler.HandleMessage(env.state, msg1)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp1.Header.Status != STATUS_SUCCESS {
		t.Fatalf("first open status = %s, want STATUS_SUCCESS", resp1.Header.Status)
	}

	// Try to open the same file again with read access - should get sharing violation
	// because first open doesn't share read
	msg2 := buildCreateMsgWithShareAccess(sessionID, treeID, "test.txt", FILE_READ_DATA, 0, FILE_OPEN, 0)
	resp2, err := env.handler.HandleMessage(env.state, msg2)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp2.Header.Status != STATUS_SHARING_VIOLATION {
		t.Errorf("second open status = %s, want STATUS_SHARING_VIOLATION", resp2.Header.Status)
	}
}

// ===========================================================================
// 1g. handleCreate: Type mismatch errors (FILE_OPEN)
// ===========================================================================

func TestCreate_OpenFileAsDirectory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Try to open a file with FILE_DIRECTORY_FILE option
	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_NOT_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_NOT_A_DIRECTORY", resp.Header.Status)
	}
}

func TestCreate_OpenDirectoryAsFile(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Try to open a directory with FILE_NON_DIRECTORY_FILE option
	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_FILE_IS_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_FILE_IS_A_DIRECTORY", resp.Header.Status)
	}
}

// ===========================================================================
// 1h. handleCreate: FILE_OPEN_IF type mismatch errors
// ===========================================================================

func TestCreate_OpenIf_FileAsDirectory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OPEN_IF on existing file with FILE_DIRECTORY_FILE - should fail
	msg := buildCreateMsg(sessionID, treeID, "test.txt", GENERIC_READ, FILE_OPEN_IF, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_NOT_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_NOT_A_DIRECTORY", resp.Header.Status)
	}
}

func TestCreate_OpenIf_DirectoryAsFile(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OPEN_IF on existing directory with FILE_NON_DIRECTORY_FILE - should fail
	msg := buildCreateMsg(sessionID, treeID, "subdir", GENERIC_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_FILE_IS_A_DIRECTORY {
		t.Errorf("status = %s, want STATUS_FILE_IS_A_DIRECTORY", resp.Header.Status)
	}
}

// ===========================================================================
// 1i. handleCreate: Create directory via FILE_OPEN_IF and FILE_CREATE
// ===========================================================================

func TestCreate_OpenIf_NewDirectory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_OPEN_IF on non-existent path with FILE_DIRECTORY_FILE should create dir
	msg := buildCreateMsg(sessionID, treeID, "newdir", GENERIC_READ, FILE_OPEN_IF, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}
}

func TestCreate_CreateDirectory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// FILE_CREATE with FILE_DIRECTORY_FILE should create a new directory
	msg := buildCreateMsg(sessionID, treeID, "brandnewdir", GENERIC_READ, FILE_CREATE, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	createAction := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if createAction != FILE_CREATED {
		t.Errorf("CreateAction = %d, want FILE_CREATED (%d)", createAction, FILE_CREATED)
	}

	// Verify attributes include DIRECTORY
	attrs := binary.LittleEndian.Uint32(resp.Payload[56:60])
	if attrs&FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.Errorf("attributes = 0x%08x, expected FILE_ATTRIBUTE_DIRECTORY bit set", attrs)
	}
}

// ===========================================================================
// 1j. handleCreate: Hidden file (dot prefix)
// ===========================================================================

func TestCreate_HiddenFile(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a file with dot prefix (hidden)
	msg := buildCreateMsg(sessionID, treeID, ".hidden", GENERIC_WRITE, FILE_CREATE, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// Verify attributes include HIDDEN
	attrs := binary.LittleEndian.Uint32(resp.Payload[56:60])
	if attrs&FILE_ATTRIBUTE_HIDDEN == 0 {
		t.Errorf("attributes = 0x%08x, expected FILE_ATTRIBUTE_HIDDEN bit set", attrs)
	}
}

// ===========================================================================
// 2. extractClientSigningAlgorithms and parseClientNegotiateContexts
// ===========================================================================

func TestExtractClientSigningAlgorithms(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	// Build raw bytes simulating SMB2 header + negotiate payload with contexts
	// We need the offset to point to where contexts start in rawBytes
	header := make([]byte, SMB2HeaderSize)
	copy(header[0:4], SMB2ProtocolID)

	// Build negotiate contexts at a known offset
	// Context: type=0x0008 (SIGNING), datalen=6 (2 for count + 2*2 for algs)
	contextOffset := uint32(SMB2HeaderSize + 36 + 4) // after header + negotiate body + dialects
	// Build some padding payload to fill space
	padding := make([]byte, int(contextOffset)-SMB2HeaderSize)

	// Build the signing capabilities context
	ctx := make([]byte, 8+6) // 8-byte header + 6-byte data
	binary.LittleEndian.PutUint16(ctx[0:2], 0x0008) // ContextType = SIGNING_CAPABILITIES
	binary.LittleEndian.PutUint16(ctx[2:4], 6)       // DataLength = 6
	// Reserved 4 bytes at ctx[4:8] = 0
	binary.LittleEndian.PutUint16(ctx[8:10], 2)      // AlgorithmCount = 2
	binary.LittleEndian.PutUint16(ctx[10:12], 0x0001) // AES-CMAC
	binary.LittleEndian.PutUint16(ctx[12:14], 0x0002) // AES-GMAC

	rawBytes := make([]byte, 0, len(header)+len(padding)+len(ctx))
	rawBytes = append(rawBytes, header...)
	rawBytes = append(rawBytes, padding...)
	rawBytes = append(rawBytes, ctx...)

	algs := env.handler.extractClientSigningAlgorithms(rawBytes, contextOffset, 1)
	if len(algs) != 2 {
		t.Fatalf("expected 2 algorithms, got %d", len(algs))
	}
	if algs[0] != 0x0001 {
		t.Errorf("alg[0] = 0x%04x, want 0x0001 (AES-CMAC)", algs[0])
	}
	if algs[1] != 0x0002 {
		t.Errorf("alg[1] = 0x%04x, want 0x0002 (AES-GMAC)", algs[1])
	}
}

func TestExtractClientSigningAlgorithms_NoSigningContext(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	// Build raw bytes with a preauth context but NO signing context
	header := make([]byte, SMB2HeaderSize)
	copy(header[0:4], SMB2ProtocolID)

	contextOffset := uint32(SMB2HeaderSize)

	// Build preauth context (type=0x0001)
	ctx := make([]byte, 8+4) // 8 header + 4 data
	binary.LittleEndian.PutUint16(ctx[0:2], 0x0001) // PREAUTH_INTEGRITY
	binary.LittleEndian.PutUint16(ctx[2:4], 4)       // DataLength
	// Data: just some bytes
	binary.LittleEndian.PutUint16(ctx[8:10], 1)      // HashAlgorithmCount
	binary.LittleEndian.PutUint16(ctx[10:12], 0x0001) // SHA-512

	rawBytes := append(header, ctx...)

	algs := env.handler.extractClientSigningAlgorithms(rawBytes, contextOffset, 1)
	if algs != nil {
		t.Errorf("expected nil algorithms when no signing context, got %v", algs)
	}
}

func TestExtractClientSigningAlgorithms_OffsetBeyondMessage(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	rawBytes := make([]byte, 64)

	algs := env.handler.extractClientSigningAlgorithms(rawBytes, 999, 1)
	if algs != nil {
		t.Errorf("expected nil for offset beyond message, got %v", algs)
	}
}

func TestParseClientNegotiateContexts(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	header := make([]byte, SMB2HeaderSize)
	copy(header[0:4], SMB2ProtocolID)

	contextOffset := uint32(SMB2HeaderSize)

	// Build multiple negotiate contexts
	var contexts []byte

	// Context 1: PREAUTH_INTEGRITY (0x0001) - 4 bytes data
	ctx1 := make([]byte, 8+4)
	binary.LittleEndian.PutUint16(ctx1[0:2], 0x0001) // PREAUTH_INTEGRITY
	binary.LittleEndian.PutUint16(ctx1[2:4], 4)
	binary.LittleEndian.PutUint16(ctx1[8:10], 1)      // HashAlgorithmCount
	binary.LittleEndian.PutUint16(ctx1[10:12], 0x0001) // SHA-512
	contexts = append(contexts, ctx1...)
	// Pad to 8-byte boundary: 12 bytes -> need 4 bytes padding
	contexts = append(contexts, 0, 0, 0, 0)

	// Context 2: ENCRYPTION (0x0002) - 4 bytes data
	ctx2 := make([]byte, 8+4)
	binary.LittleEndian.PutUint16(ctx2[0:2], 0x0002) // ENCRYPTION
	binary.LittleEndian.PutUint16(ctx2[2:4], 4)
	binary.LittleEndian.PutUint16(ctx2[8:10], 1)      // CipherCount
	binary.LittleEndian.PutUint16(ctx2[10:12], 0x0002) // AES-128-GCM
	contexts = append(contexts, ctx2...)
	// Pad to 8-byte boundary: 12 bytes -> need 4 bytes padding
	contexts = append(contexts, 0, 0, 0, 0)

	// Context 3: SIGNING (0x0008) - 4 bytes data
	ctx3 := make([]byte, 8+4)
	binary.LittleEndian.PutUint16(ctx3[0:2], 0x0008) // SIGNING
	binary.LittleEndian.PutUint16(ctx3[2:4], 4)
	binary.LittleEndian.PutUint16(ctx3[8:10], 1)      // AlgorithmCount
	binary.LittleEndian.PutUint16(ctx3[10:12], 0x0001) // AES-CMAC
	contexts = append(contexts, ctx3...)

	rawBytes := append(header, contexts...)

	// Should not panic and should parse all 3 contexts
	env.handler.parseClientNegotiateContexts(rawBytes, contextOffset, 3)
}

func TestParseClientNegotiateContexts_OffsetBeyondMessage(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	rawBytes := make([]byte, 64)
	// Should not panic with offset beyond message
	env.handler.parseClientNegotiateContexts(rawBytes, 999, 1)
}

func TestParseClientNegotiateContexts_AllContextTypes(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	header := make([]byte, SMB2HeaderSize)
	copy(header[0:4], SMB2ProtocolID)
	contextOffset := uint32(SMB2HeaderSize)

	// Test all known context type names: COMPRESSION(0x0003), NETNAME(0x0005),
	// TRANSPORT(0x0006), RDMA(0x0007)
	contextTypes := []uint16{0x0003, 0x0005, 0x0006, 0x0007}
	var contexts []byte
	for _, ct := range contextTypes {
		ctx := make([]byte, 8+8) // 8 header + 8 data (pad to 8 boundary)
		binary.LittleEndian.PutUint16(ctx[0:2], ct)
		binary.LittleEndian.PutUint16(ctx[2:4], 8) // DataLength=8
		contexts = append(contexts, ctx...)
	}

	rawBytes := append(header, contexts...)
	env.handler.parseClientNegotiateContexts(rawBytes, contextOffset, uint16(len(contextTypes)))
}

// ===========================================================================
// 2b. Negotiate with SMB 3.1.1 and contexts in the raw message
// ===========================================================================

func TestNegotiate_SMB311WithSigningContexts(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	// Build a negotiate message for SMB 3.1.1 with negotiate contexts
	w := NewByteWriter(256)
	w.WriteUint16(36)                             // StructureSize
	w.WriteUint16(1)                              // DialectCount=1
	w.WriteUint16(SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	w.WriteUint16(0)                              // Reserved
	w.WriteUint32(0)                              // Capabilities
	w.WriteGUID([16]byte{})                       // ClientGUID

	// Calculate context offset: SMB2HeaderSize + 36 (fixed) + 2 (dialect) = header+38
	// Contexts must be 8-byte aligned: 36+2=38, pad to 40
	negContextOffset := uint32(SMB2HeaderSize + 40)
	w.WriteUint32(negContextOffset) // NegotiateContextOffset
	w.WriteUint16(1)                // NegotiateContextCount = 1
	w.WriteUint16(0)                // Reserved2
	w.WriteUint16(uint16(SMB3_1_1)) // Dialect

	// Pad to 8-byte alignment (current payload size is 38, need 2 bytes)
	w.WriteUint16(0)

	// Write signing context at the offset
	// Context type 0x0008 (SIGNING_CAPABILITIES)
	w.WriteUint16(0x0008) // ContextType
	w.WriteUint16(4)       // DataLength (2 for count + 2 for one algorithm)
	w.WriteUint32(0)       // Reserved
	w.WriteUint16(1)       // AlgorithmCount
	w.WriteUint16(0x0001)  // AES-CMAC

	payload := w.Bytes()
	header := makeHeader(SMB2_NEGOTIATE, 0, 0)

	msg := &SMB2Message{
		Header:   header,
		Payload:  payload,
		RawBytes: makeRawBytes(header, payload),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// Verify that the client signing algorithms were extracted
	if len(env.state.clientSigningAlgorithms) == 0 {
		t.Error("clientSigningAlgorithms should be populated after SMB 3.1.1 negotiate with signing context")
	}
}

// ===========================================================================
// 3. sessionCleanupLoop
// ===========================================================================

func TestSessionCleanup_ExpiredInLoop(t *testing.T) {
	srv, err := NewServer(ServerOptions{
		Logger:      &NullLogger{},
		AllowGuest:  true,
		IdleTimeout: 50 * time.Millisecond, // Very short for testing
	})
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	// Add a share so cleanup has something to iterate
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("memfs.NewFS() failed: %v", err)
	}
	if err := srv.AddShare(fs, ShareOptions{
		ShareName:  "testshare",
		SharePath:  "/",
		AllowGuest: true,
	}); err != nil {
		t.Fatalf("AddShare() failed: %v", err)
	}

	// Create a session with expired timestamp
	session := srv.sessions.CreateSession(SMB2_1, [16]byte{}, "127.0.0.1:54321")
	session.SetValid("testuser", "", false, nil)
	sessionID := session.ID

	// Set session's last activity far in the past
	session.LastActivity = time.Now().Add(-10 * time.Minute)

	// Directly call CleanupExpired and verify it works
	expired := srv.sessions.CleanupExpired()
	if len(expired) == 0 {
		t.Error("expected at least one expired session")
	}

	// Verify our session was in the expired list
	found := false
	for _, s := range expired {
		if s.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected our session to be in the expired list")
	}

	// Simulate the cleanup loop body: clean up file handles for expired sessions
	for _, session := range expired {
		for _, share := range srv.shares {
			share.fileHandles.ReleaseBySession(session.ID)
		}
	}

	// Session should be gone from the manager
	if srv.sessions.GetSession(sessionID) != nil {
		t.Error("session still exists after cleanup")
	}
}

// ===========================================================================
// 4. Attribute Set methods — "clear" path (set=false)
// ===========================================================================

func TestAttributes_SetClear(t *testing.T) {
	// Start with all bits set
	wa := NewWindowsAttributes(FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE)

	// Clear each one
	wa.SetSystem(false)
	if wa.IsSystem() {
		t.Error("SetSystem(false) failed - system bit still set")
	}
	if wa.Attributes()&FILE_ATTRIBUTE_SYSTEM != 0 {
		t.Error("SetSystem(false) failed - raw bit still set")
	}

	wa.SetReadOnly(false)
	if wa.IsReadOnly() {
		t.Error("SetReadOnly(false) failed - readonly bit still set")
	}
	if wa.Attributes()&FILE_ATTRIBUTE_READONLY != 0 {
		t.Error("SetReadOnly(false) failed - raw bit still set")
	}

	wa.SetArchive(false)
	if wa.IsArchive() {
		t.Error("SetArchive(false) failed - archive bit still set")
	}
	if wa.Attributes()&FILE_ATTRIBUTE_ARCHIVE != 0 {
		t.Error("SetArchive(false) failed - raw bit still set")
	}

	// Verify all cleared
	if wa.Attributes() != 0 {
		t.Errorf("Expected attrs=0 after clearing all, got 0x%08x", wa.Attributes())
	}
}

// ===========================================================================
// 5. GetWindowsAttributes (via FileInfoEx interface)
// ===========================================================================

// testFileInfoEx implements FileInfoEx for testing
type testFileInfoEx struct {
	testFileInfo
	winAttrs *WindowsAttributes
}

func (f *testFileInfoEx) WindowsAttributes() *WindowsAttributes {
	return f.winAttrs
}

func TestGetWindowsAttributes_FromFileInfoEx(t *testing.T) {
	wa := NewWindowsAttributes(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
	info := &testFileInfoEx{
		testFileInfo: testFileInfo{name: "test.txt", size: 100},
		winAttrs:     wa,
	}

	result := GetWindowsAttributes(info)
	if result == nil {
		t.Fatal("GetWindowsAttributes returned nil for FileInfoEx")
	}
	if !result.IsHidden() {
		t.Error("expected Hidden attribute to be set")
	}
	if !result.IsSystem() {
		t.Error("expected System attribute to be set")
	}
}

func TestGetWindowsAttributes_NilFromFileInfoEx(t *testing.T) {
	info := &testFileInfoEx{
		testFileInfo: testFileInfo{name: "test.txt"},
		winAttrs:     nil,
	}

	result := GetWindowsAttributes(info)
	if result != nil {
		t.Error("expected nil when FileInfoEx.WindowsAttributes() returns nil")
	}
}

func TestGetWindowsAttributes_FromRegularFileInfo(t *testing.T) {
	info := &testFileInfo{name: "test.txt", size: 100}

	result := GetWindowsAttributes(info)
	if result != nil {
		t.Error("expected nil for regular FileInfo that doesn't implement FileInfoEx")
	}
}

// ===========================================================================
// 6. newMetadataCache: zero-value defaults
// ===========================================================================

func TestNewMetadataCache_ZeroValues(t *testing.T) {
	// All zero values should get defaults applied
	config := CacheConfig{
		EnableCache:     true,
		DirCacheTTL:     0,
		StatCacheTTL:    0,
		MaxCacheEntries: 0,
	}
	cache := newMetadataCache(config)

	// Defaults should be applied
	if cache.config.MaxCacheEntries != 1000 {
		t.Errorf("MaxCacheEntries = %d, want 1000", cache.config.MaxCacheEntries)
	}
	if cache.config.DirCacheTTL != 5*time.Second {
		t.Errorf("DirCacheTTL = %v, want 5s", cache.config.DirCacheTTL)
	}
	if cache.config.StatCacheTTL != 5*time.Second {
		t.Errorf("StatCacheTTL = %v, want 5s", cache.config.StatCacheTTL)
	}
	if !cache.enabled {
		t.Error("cache should be enabled")
	}
}

func TestNewMetadataCache_DisabledNoOps(t *testing.T) {
	cache := newMetadataCache(CacheConfig{EnableCache: false})

	// All operations should be no-ops
	cache.putDirEntries("/dir", nil)
	_, ok := cache.getDirEntries("/dir")
	if ok {
		t.Error("getDirEntries should return false when disabled")
	}

	cache.putStatInfo("/file.txt", nil)
	_, ok = cache.getStatInfo("/file.txt")
	if ok {
		t.Error("getStatInfo should return false when disabled")
	}

	// invalidate and invalidateAll should not panic
	cache.invalidate("/file.txt")
	cache.invalidateAll()
}

// ===========================================================================
// 7. handleLogoff with open tree connections and file handles
// ===========================================================================

func TestLogoff_WithTreeAndFiles(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open a file
	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		GENERIC_READ|GENERIC_WRITE, FILE_OPEN, 0)
	if fileID.IsZero() {
		t.Fatal("failed to open file")
	}

	// Now logoff - this should clean up tree connections and file handles
	msg := buildLogoffMsg(sessionID)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(LOGOFF) error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Errorf("LOGOFF status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// Session should be destroyed
	if env.server.sessions.GetSession(sessionID) != nil {
		t.Error("session still exists after logoff")
	}
	if env.state.session != nil {
		t.Error("connState.session should be nil after logoff")
	}
}

func TestLogoff_TooShortPayload(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_LOGOFF,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: []byte{0x04}, // Only 1 byte, need >= 4
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleLogoffImpl(env.state, msg)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}

func TestLogoff_InvalidStructSize(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	w := NewByteWriter(4)
	w.WriteUint16(99) // Wrong StructureSize (should be 4)
	w.WriteUint16(0)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_LOGOFF,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: w.Bytes(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleLogoffImpl(env.state, msg)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}

// ===========================================================================
// 8. String method for attributes: cover more attribute combinations
// ===========================================================================

func TestAttributes_String_AllCombinations(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		want  string
	}{
		{
			name:  "sparse",
			attrs: FILE_ATTRIBUTE_SPARSE_FILE,
			want:  "Sparse",
		},
		{
			name:  "offline",
			attrs: FILE_ATTRIBUTE_OFFLINE,
			want:  "Offline",
		},
		{
			name:  "encrypted",
			attrs: FILE_ATTRIBUTE_ENCRYPTED,
			want:  "Encrypted",
		},
		{
			name:  "compressed",
			attrs: FILE_ATTRIBUTE_COMPRESSED,
			want:  "Compressed",
		},
		{
			name:  "reparse_point",
			attrs: FILE_ATTRIBUTE_REPARSE_POINT,
			want:  "ReparsePoint",
		},
		{
			name:  "temporary",
			attrs: FILE_ATTRIBUTE_TEMPORARY,
			want:  "Temporary",
		},
		{
			name:  "archive",
			attrs: FILE_ATTRIBUTE_ARCHIVE,
			want:  "Archive",
		},
		{
			name:  "all_special",
			attrs: FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_ENCRYPTED,
			want:  "Sparse, Offline, Encrypted",
		},
		{
			name:  "zero_attrs",
			attrs: 0,
			want:  "Normal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wa := NewWindowsAttributes(tt.attrs)
			got := wa.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ===========================================================================
// 9. handleWrite on read-only tree
// ===========================================================================

func TestWrite_ReadOnlyTree(t *testing.T) {
	env, sessionID, treeID := setupHandlerEnvWithReadOnlyShare(t)

	// Open existing file for reading
	msg := buildCreateMsg(sessionID, treeID, "existing.txt", GENERIC_READ, FILE_OPEN, 0)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
	fileID := parseCreateResponse(t, resp.Payload)

	// Try to write - should fail with ACCESS_DENIED
	writeMsg := buildWriteMsg(sessionID, treeID, fileID, 0, []byte("data"))
	writeResp, err := env.handler.HandleMessage(env.state, writeMsg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if writeResp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("WRITE status = %s, want STATUS_ACCESS_DENIED", writeResp.Header.Status)
	}
}

// ===========================================================================
// 10. attributesToMode: read-only directory branch
// ===========================================================================

func TestAttributesToMode_ReadOnlyDirectory(t *testing.T) {
	mode := attributesToMode(FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_DIRECTORY, true)
	if !mode.IsDir() {
		t.Error("expected directory mode")
	}
	// Read-only dir should have 0555 perm bits
	if mode.Perm() != 0555 {
		t.Errorf("Perm() = %o, want 0555", mode.Perm())
	}
}

// ===========================================================================
// 11. handleCreate: empty path opens root directory
// ===========================================================================

func TestCreate_EmptyPathOpensRoot(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Empty path should open root directory
	msg := buildCreateMsg(sessionID, treeID, "", GENERIC_READ, FILE_OPEN, FILE_DIRECTORY_FILE)
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// Verify it's a directory
	attrs := binary.LittleEndian.Uint32(resp.Payload[56:60])
	if attrs&FILE_ATTRIBUTE_DIRECTORY == 0 {
		t.Errorf("attributes = 0x%08x, expected FILE_ATTRIBUTE_DIRECTORY", attrs)
	}
}

// ===========================================================================
// 12. handleCreate: small payload errors
// ===========================================================================

func TestCreate_TooShortPayload(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CREATE, sessionID, treeID),
		Payload: []byte{0x39, 0x00, 0x01, 0x02}, // Only 4 bytes
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestCreate_InvalidStructSize(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Build a valid-length payload but with wrong structure size
	nameUTF16 := EncodeStringToUTF16LE("test.txt")
	nameOffset := uint16(SMB2HeaderSize + 56)

	w := NewByteWriter(128)
	w.WriteUint16(99) // Wrong StructureSize (should be 57)
	w.WriteOneByte(0)
	w.WriteOneByte(0)
	w.WriteUint32(0x00000002)
	w.WriteUint64(0)
	w.WriteUint64(0)
	w.WriteUint32(GENERIC_READ)
	w.WriteUint32(FILE_ATTRIBUTE_NORMAL)
	w.WriteUint32(FILE_SHARE_READ)
	w.WriteUint32(FILE_OPEN)
	w.WriteUint32(0)
	w.WriteUint16(nameOffset)
	w.WriteUint16(uint16(len(nameUTF16)))
	w.WriteUint32(0)
	w.WriteUint32(0)
	w.WriteBytes(nameUTF16)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CREATE, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// ===========================================================================
// 13. handleRead/handleWrite/handleFlush/handleClose: too-short payloads
// ===========================================================================

func TestRead_TooShortPayload(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_READ, sessionID, treeID),
		Payload: []byte{0x31, 0x00, 0x01}, // Only 3 bytes
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestRead_InvalidStructSize(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	w := NewByteWriter(52)
	w.WriteUint16(99) // Wrong StructureSize (should be 49)
	w.WriteOneByte(0) // Padding
	w.WriteOneByte(0) // Flags
	w.WriteUint32(4096)
	w.WriteUint64(0)
	w.WriteFileID(FileID{})
	w.WriteUint32(0)
	w.WriteUint32(0)
	w.WriteUint32(0)
	w.WriteUint16(0)
	w.WriteUint16(0)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_READ, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestWrite_TooShortPayload(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_WRITE, sessionID, treeID),
		Payload: []byte{0x31, 0x00, 0x01}, // Only 3 bytes
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestWrite_InvalidStructSize(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	w := NewByteWriter(64)
	w.WriteUint16(99) // Wrong StructureSize (should be 49)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteUint64(0)
	w.WriteFileID(FileID{})
	w.WriteUint32(0)
	w.WriteUint32(0)
	w.WriteUint16(0)
	w.WriteUint16(0)
	w.WriteUint32(0)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_WRITE, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestFlush_TooShortPayload(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_FLUSH, sessionID, treeID),
		Payload: []byte{0x18, 0x00, 0x01}, // Only 3 bytes
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestFlush_InvalidStructSize(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	w := NewByteWriter(24)
	w.WriteUint16(99) // Wrong StructureSize (should be 24)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteFileID(FileID{})

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_FLUSH, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestClose_TooShortPayload(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CLOSE, sessionID, treeID),
		Payload: []byte{0x18, 0x00, 0x01}, // Only 3 bytes
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

func TestClose_InvalidStructSize(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	w := NewByteWriter(24)
	w.WriteUint16(99) // Wrong StructureSize (should be 24)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteFileID(FileID{})

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CLOSE, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// ===========================================================================
// 14. handleWrite with no write access (GENERIC_READ only)
// ===========================================================================

func TestWrite_NoWriteAccess(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Open file with read-only access
	fileID := openFileViaCreate(t, env, sessionID, treeID, "test.txt",
		FILE_READ_DATA, FILE_OPEN, 0)

	// Try to write - should fail
	writeMsg := buildWriteMsg(sessionID, treeID, fileID, 0, []byte("data"))
	writeResp, err := env.handler.HandleMessage(env.state, writeMsg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if writeResp.Header.Status != STATUS_ACCESS_DENIED {
		t.Errorf("WRITE status = %s, want STATUS_ACCESS_DENIED", writeResp.Header.Status)
	}
}

// ===========================================================================
// 15. handleWrite with invalid file handle
// ===========================================================================

func TestWrite_InvalidHandle(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	bogusID := FileID{Persistent: 0xDEAD, Volatile: 0xBEEF}
	writeMsg := buildWriteMsg(sessionID, treeID, bogusID, 0, []byte("data"))
	writeResp, err := env.handler.HandleMessage(env.state, writeMsg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if writeResp.Header.Status != STATUS_FILE_CLOSED {
		t.Errorf("WRITE status = %s, want STATUS_FILE_CLOSED", writeResp.Header.Status)
	}
}

// ===========================================================================
// 16. handleClose with delete-on-close for directory
// ===========================================================================

func TestClose_DeleteOnClose_Directory(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	// Create a directory with DELETE_ON_CLOSE
	createMsg := buildCreateMsg(sessionID, treeID, "ephemeral_dir",
		GENERIC_READ|DELETE, FILE_CREATE, FILE_DIRECTORY_FILE|FILE_DELETE_ON_CLOSE)
	createResp, err := env.handler.HandleMessage(env.state, createMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CREATE) error: %v", err)
	}
	if createResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CREATE status = %s, want STATUS_SUCCESS", createResp.Header.Status)
	}
	fileID := parseCreateResponse(t, createResp.Payload)

	// Close - should trigger deletion
	closeMsg := buildCloseMsg(sessionID, treeID, fileID)
	closeResp, err := env.handler.HandleMessage(env.state, closeMsg)
	if err != nil {
		t.Fatalf("HandleMessage(CLOSE) error: %v", err)
	}
	if closeResp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("CLOSE status = %s, want STATUS_SUCCESS", closeResp.Header.Status)
	}

	// Verify directory is gone
	openMsg := buildCreateMsg(sessionID, treeID, "ephemeral_dir", GENERIC_READ, FILE_OPEN, FILE_DIRECTORY_FILE)
	openResp, err := env.handler.HandleMessage(env.state, openMsg)
	if err != nil {
		t.Fatalf("HandleMessage(re-open) error: %v", err)
	}
	if openResp.Header.Status != STATUS_OBJECT_NAME_NOT_FOUND {
		t.Errorf("re-open status = %s, want STATUS_OBJECT_NAME_NOT_FOUND", openResp.Header.Status)
	}
}

// ===========================================================================
// 17. Negotiate: below minimum dialect
// ===========================================================================

func TestNegotiate_BelowMinDialect(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
		MinDialect: SMB3_0,   // Server requires SMB 3.0+
		MaxDialect: SMB3_1_1,
	})

	// Client only offers SMB 2.1 which is below the server min
	msg := buildNegotiateMsg([]SMBDialect{SMB2_1})
	resp := negotiateWithMsg(t, env, msg)

	if resp.Header.Status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", resp.Header.Status)
	}
}

// ===========================================================================
// 18. handleNegotiateImpl: empty payload (SMB1 upgrade)
// ===========================================================================

func TestNegotiate_EmptyPayload(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_NEGOTIATE, 0, 0),
		Payload: nil, // Empty payload = SMB1 upgrade path
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Errorf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
}

// ===========================================================================
// 19. Negotiate: not enough bytes for dialect array
// ===========================================================================

func TestNegotiate_NotEnoughDialectBytes(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	w := NewByteWriter(64)
	w.WriteUint16(36)                             // StructureSize
	w.WriteUint16(100)                            // DialectCount = 100 (way more than data)
	w.WriteUint16(SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	w.WriteUint16(0)                              // Reserved
	w.WriteUint32(0)                              // Capabilities
	w.WriteGUID([16]byte{})                       // ClientGUID
	w.WriteUint32(0)                              // NegotiateContextOffset
	w.WriteUint16(0)                              // NegotiateContextCount
	w.WriteUint16(0)                              // Reserved2
	// Only 2 bytes of dialect data (for 1 dialect, but claimed 100)
	w.WriteUint16(uint16(SMB2_1))

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_NEGOTIATE, 0, 0),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// ===========================================================================
// 20. SessionSetup: reconnect to previous session
// ===========================================================================

func TestSessionSetup_PreviousSessionReconnect(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Create initial session
	sessionID := authenticateGuest(t, env)

	// Try to reconnect using previousSessionId
	secBufOffset := uint16(SMB2HeaderSize + 24)
	secBlob := []byte("not-ntlm")

	w := NewByteWriter(64)
	w.WriteUint16(25)                                        // StructureSize
	w.WriteOneByte(0)                                        // Flags
	w.WriteOneByte(byte(SMB2_NEGOTIATE_SIGNING_ENABLED))     // SecurityMode
	w.WriteUint32(0)                                         // Capabilities
	w.WriteUint32(0)                                         // Channel
	w.WriteUint16(secBufOffset)                              // SecurityBufferOffset
	w.WriteUint16(uint16(len(secBlob)))                      // SecurityBufferLength
	w.WriteUint64(sessionID)                                 // PreviousSessionId
	w.WriteBytes(secBlob)

	header := makeHeader(SMB2_SESSION_SETUP, 0, 0) // New session ID = 0
	msg := &SMB2Message{
		Header:   header,
		Payload:  w.Bytes(),
		RawBytes: makeRawBytes(header, w.Bytes()),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
}

// ===========================================================================
// 21. Various SMBDialect.String() edge case
// ===========================================================================

func TestSMBDialect_String_Unknown(t *testing.T) {
	d := SMBDialect(0x9999)
	s := d.String()
	if s == "" {
		t.Error("String() should not return empty for unknown dialect")
	}
}

// ===========================================================================
// 22. modeToAttributes: regular file gets ARCHIVE
// ===========================================================================

func TestModeToAttributes_RegularFile(t *testing.T) {
	attrs := modeToAttributes(0644) // Regular file mode
	if attrs&FILE_ATTRIBUTE_ARCHIVE == 0 {
		t.Errorf("expected FILE_ATTRIBUTE_ARCHIVE for regular file, got 0x%08x", attrs)
	}
}

// ===========================================================================
// 23. Server getters
// ===========================================================================

func TestServer_Getters(t *testing.T) {
	srv, err := NewServer(ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}

	opts := srv.Options()
	if !opts.AllowGuest {
		t.Error("Options().AllowGuest should be true")
	}

	sessions := srv.Sessions()
	if sessions == nil {
		t.Error("Sessions() should not be nil")
	}

	logger := srv.Logger()
	if logger == nil {
		t.Error("Logger() should not be nil")
	}

	count := srv.ConnectionCount()
	if count != 0 {
		t.Errorf("ConnectionCount() = %d, want 0", count)
	}

	sCount := srv.SessionCount()
	if sCount != 0 {
		t.Errorf("SessionCount() = %d, want 0", sCount)
	}

	// Addr should be nil before listening
	if srv.Addr() != nil {
		t.Error("Addr() should be nil before Listen()")
	}
}

// ===========================================================================
// 24. Negotiate: signing required flag
// ===========================================================================

func TestNegotiate_SigningRequired(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:          &NullLogger{},
		AllowGuest:      true,
		SigningRequired:  true,
	})

	// Client requests signing
	w := NewByteWriter(64)
	w.WriteUint16(36)
	w.WriteUint16(1)                                                            // DialectCount
	w.WriteUint16(SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED) // Both signing flags
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteGUID([16]byte{})
	w.WriteUint32(0)
	w.WriteUint16(0)
	w.WriteUint16(0)
	w.WriteUint16(uint16(SMB2_1))

	payload := w.Bytes()
	header := makeHeader(SMB2_NEGOTIATE, 0, 0)
	msg := &SMB2Message{
		Header:   header,
		Payload:  payload,
		RawBytes: makeRawBytes(header, payload),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// Verify signing required was negotiated
	if !env.state.signingRequired {
		t.Error("signingRequired should be true when client requests it")
	}
}

// ===========================================================================
// 25. handleCreate: name offset/length out of bounds
// ===========================================================================

func TestCreate_InvalidNameOffset(t *testing.T) {
	env, sessionID, treeID := fullTestSetup(t)

	w := NewByteWriter(128)
	w.WriteUint16(57)
	w.WriteOneByte(0)
	w.WriteOneByte(0)
	w.WriteUint32(0x00000002)
	w.WriteUint64(0)
	w.WriteUint64(0)
	w.WriteUint32(GENERIC_READ)
	w.WriteUint32(FILE_ATTRIBUTE_NORMAL)
	w.WriteUint32(FILE_SHARE_READ)
	w.WriteUint32(FILE_OPEN)
	w.WriteUint32(0)
	w.WriteUint16(0xFFFF) // Invalid name offset (way too large)
	w.WriteUint16(10)     // NameLength
	w.WriteUint32(0)
	w.WriteUint32(0)

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CREATE, sessionID, treeID),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}
