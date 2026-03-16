package smbfs

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/absfs/memfs"
)

// handlerEnv holds the setup state for handler-level tests.
type handlerEnv struct {
	server  *Server
	handler *SMBHandler
	state   *connState
}

// setupHandlerEnv creates a minimal Server, SMBHandler, and connState for unit
// tests that exercise handler implementations directly (no real TCP connection).
func setupHandlerEnv(t *testing.T, opts *ServerOptions) *handlerEnv {
	t.Helper()

	var sopts ServerOptions
	if opts != nil {
		sopts = *opts
	}
	if sopts.Logger == nil {
		sopts.Logger = &NullLogger{}
	}

	srv, err := NewServer(sopts)
	if err != nil {
		t.Fatalf("setupHandlerEnv: NewServer failed: %v", err)
	}

	state := &connState{
		remoteAddr: "127.0.0.1:12345",
		dialect:    SMB2_1,
	}

	return &handlerEnv{
		server:  srv,
		handler: srv.handler,
		state:   state,
	}
}

// setupHandlerEnvWithShare creates a handlerEnv with AllowGuest=true and a
// memfs-backed "testshare" share pre-populated with:
//   - /test.txt ("hello world")
//   - /subdir/ (directory)
//   - /subdir/file.txt ("nested content")
func setupHandlerEnvWithShare(t *testing.T) *handlerEnv {
	t.Helper()
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})

	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("memfs.NewFS() failed: %v", err)
	}

	f, err := fs.Create("/test.txt")
	if err != nil {
		t.Fatalf("Create /test.txt failed: %v", err)
	}
	_, _ = f.Write([]byte("hello world"))
	f.Close()

	if err := fs.Mkdir("/subdir", 0755); err != nil {
		t.Fatalf("Mkdir /subdir failed: %v", err)
	}

	f, err = fs.Create("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Create /subdir/file.txt failed: %v", err)
	}
	_, _ = f.Write([]byte("nested content"))
	f.Close()

	if err := env.server.AddShare(fs, ShareOptions{
		ShareName:  "testshare",
		SharePath:  "/",
		AllowGuest: true,
	}); err != nil {
		t.Fatalf("AddShare() failed: %v", err)
	}

	return env
}

// fullTestSetup does negotiate + guest auth + tree connect to "testshare".
// Returns the env, session ID, and tree ID needed for file operation tests.
func fullTestSetup(t *testing.T) (*handlerEnv, uint64, uint32) {
	t.Helper()

	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)
	treeID := connectTree(t, env, sessionID, "testshare")
	return env, sessionID, treeID
}

// addTestShare adds a memfs-backed share to the server and returns the share.
func (e *handlerEnv) addTestShare(t *testing.T, name string, opts ShareOptions) *Share {
	t.Helper()
	fs, err := memfs.NewFS()
	if err != nil {
		t.Fatalf("addTestShare: memfs.NewFS failed: %v", err)
	}
	opts.ShareName = name
	if err := e.server.AddShare(fs, opts); err != nil {
		t.Fatalf("addTestShare: AddShare(%s) failed: %v", name, err)
	}
	return e.server.GetShare(name)
}

// ---------------------------------------------------------------------------
// SMB2Message builders — construct full *SMB2Message with header + payload
// ---------------------------------------------------------------------------

// makeHeader creates an SMB2 request header.
func makeHeader(command uint16, sessionID uint64, treeID uint32) *SMB2Header {
	h := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		Command:       command,
		CreditRequest: 10,
		SessionID:     sessionID,
		TreeID:        treeID,
	}
	copy(h.ProtocolID[:], SMB2ProtocolID)
	return h
}

// makeRawBytes builds raw message bytes from header + payload (for preauth hash).
func makeRawBytes(header *SMB2Header, payload []byte) []byte {
	hdr := header.Marshal()
	raw := make([]byte, len(hdr)+len(payload))
	copy(raw, hdr)
	copy(raw[len(hdr):], payload)
	return raw
}

func buildNegotiateMsg(dialects []SMBDialect) *SMB2Message {
	w := NewByteWriter(64)
	w.WriteUint16(36)                             // StructureSize
	w.WriteUint16(uint16(len(dialects)))          // DialectCount
	w.WriteUint16(SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	w.WriteUint16(0)                              // Reserved
	w.WriteUint32(0)                              // Capabilities
	w.WriteGUID([16]byte{})                       // ClientGUID
	w.WriteUint32(0)                              // NegotiateContextOffset
	w.WriteUint16(0)                              // NegotiateContextCount
	w.WriteUint16(0)                              // Reserved2
	for _, d := range dialects {
		w.WriteUint16(uint16(d))
	}

	payload := w.Bytes()
	header := makeHeader(SMB2_NEGOTIATE, 0, 0)

	return &SMB2Message{
		Header:   header,
		Payload:  payload,
		RawBytes: makeRawBytes(header, payload),
	}
}

func buildSessionSetupMsg(sessionID uint64, secBlob []byte) *SMB2Message {
	secBufOffset := uint16(SMB2HeaderSize + 24)

	w := NewByteWriter(64)
	w.WriteUint16(25)                               // StructureSize
	w.WriteOneByte(0)                               // Flags
	w.WriteOneByte(byte(SMB2_NEGOTIATE_SIGNING_ENABLED)) // SecurityMode
	w.WriteUint32(0)                                // Capabilities
	w.WriteUint32(0)                                // Channel
	w.WriteUint16(secBufOffset)                     // SecurityBufferOffset
	w.WriteUint16(uint16(len(secBlob)))             // SecurityBufferLength
	w.WriteUint64(0)                                // PreviousSessionId
	w.WriteBytes(secBlob)

	payload := w.Bytes()
	header := makeHeader(SMB2_SESSION_SETUP, sessionID, 0)

	return &SMB2Message{
		Header:   header,
		Payload:  payload,
		RawBytes: makeRawBytes(header, payload),
	}
}

func buildTreeConnectMsg(sessionID uint64, sharePath string) *SMB2Message {
	pathUTF16 := EncodeStringToUTF16LE(sharePath)
	pathOffset := uint16(SMB2HeaderSize + 8)

	w := NewByteWriter(64)
	w.WriteUint16(9)
	w.WriteUint16(0)
	w.WriteUint16(pathOffset)
	w.WriteUint16(uint16(len(pathUTF16)))
	w.WriteBytes(pathUTF16)

	return &SMB2Message{
		Header:  makeHeader(SMB2_TREE_CONNECT, sessionID, 0),
		Payload: w.Bytes(),
	}
}

func buildTreeDisconnectMsg(sessionID uint64, treeID uint32) *SMB2Message {
	w := NewByteWriter(4)
	w.WriteUint16(4)
	w.WriteUint16(0)

	return &SMB2Message{
		Header:  makeHeader(SMB2_TREE_DISCONNECT, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildCreateMsg(sessionID uint64, treeID uint32, filename string, access, disposition, options uint32) *SMB2Message {
	nameUTF16 := EncodeStringToUTF16LE(filename)
	nameOffset := uint16(SMB2HeaderSize + 56)

	w := NewByteWriter(128)
	w.WriteUint16(57)                                 // StructureSize
	w.WriteOneByte(0)                                 // SecurityFlags
	w.WriteOneByte(0)                                 // RequestedOplockLevel
	w.WriteUint32(0x00000002)                         // ImpersonationLevel
	w.WriteUint64(0)                                  // SmbCreateFlags
	w.WriteUint64(0)                                  // Reserved
	w.WriteUint32(access)                             // DesiredAccess
	w.WriteUint32(FILE_ATTRIBUTE_NORMAL)              // FileAttributes
	w.WriteUint32(FILE_SHARE_READ | FILE_SHARE_WRITE) // ShareAccess
	w.WriteUint32(disposition)                        // CreateDisposition
	w.WriteUint32(options)                            // CreateOptions
	w.WriteUint16(nameOffset)                         // NameOffset
	w.WriteUint16(uint16(len(nameUTF16)))             // NameLength
	w.WriteUint32(0)                                  // CreateContextsOffset
	w.WriteUint32(0)                                  // CreateContextsLength
	w.WriteBytes(nameUTF16)

	return &SMB2Message{
		Header:  makeHeader(SMB2_CREATE, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildCloseMsg(sessionID uint64, treeID uint32, fileID FileID) *SMB2Message {
	w := NewByteWriter(24)
	w.WriteUint16(24)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteFileID(fileID)

	return &SMB2Message{
		Header:  makeHeader(SMB2_CLOSE, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildReadMsg(sessionID uint64, treeID uint32, fileID FileID, offset uint64, length uint32) *SMB2Message {
	w := NewByteWriter(52)
	w.WriteUint16(49)
	w.WriteOneByte(0) // Padding
	w.WriteOneByte(0) // Flags
	w.WriteUint32(length)
	w.WriteUint64(offset)
	w.WriteFileID(fileID)
	w.WriteUint32(0) // MinimumCount
	w.WriteUint32(0) // Channel
	w.WriteUint32(0) // RemainingBytes
	w.WriteUint16(0) // ReadChannelInfoOffset
	w.WriteUint16(0) // ReadChannelInfoLength

	return &SMB2Message{
		Header:  makeHeader(SMB2_READ, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildWriteMsg(sessionID uint64, treeID uint32, fileID FileID, offset uint64, data []byte) *SMB2Message {
	dataOffset := uint16(SMB2HeaderSize + 48)

	w := NewByteWriter(64 + len(data))
	w.WriteUint16(49)
	w.WriteUint16(dataOffset)
	w.WriteUint32(uint32(len(data)))
	w.WriteUint64(offset)
	w.WriteFileID(fileID)
	w.WriteUint32(0) // Channel
	w.WriteUint32(0) // RemainingBytes
	w.WriteUint16(0) // WriteChannelInfoOffset
	w.WriteUint16(0) // WriteChannelInfoLength
	w.WriteUint32(0) // Flags
	w.WriteBytes(data)

	return &SMB2Message{
		Header:  makeHeader(SMB2_WRITE, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildFlushMsg(sessionID uint64, treeID uint32, fileID FileID) *SMB2Message {
	w := NewByteWriter(24)
	w.WriteUint16(24)
	w.WriteUint16(0)
	w.WriteUint32(0)
	w.WriteFileID(fileID)

	return &SMB2Message{
		Header:  makeHeader(SMB2_FLUSH, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildEchoMsg() *SMB2Message {
	w := NewByteWriter(4)
	w.WriteUint16(4)
	w.WriteUint16(0)

	return &SMB2Message{
		Header:  makeHeader(SMB2_ECHO, 0, 0),
		Payload: w.Bytes(),
	}
}

func buildLogoffMsg(sessionID uint64) *SMB2Message {
	w := NewByteWriter(4)
	w.WriteUint16(4)
	w.WriteUint16(0)

	return &SMB2Message{
		Header:  makeHeader(SMB2_LOGOFF, sessionID, 0),
		Payload: w.Bytes(),
	}
}

func buildQueryDirMsg(sessionID uint64, treeID uint32, fileID FileID, pattern string, infoClass uint8, flags uint8) *SMB2Message {
	patternUTF16 := EncodeStringToUTF16LE(pattern)
	fileNameOffset := uint16(SMB2HeaderSize + 32)

	w := NewByteWriter(64)
	w.WriteUint16(33)
	w.WriteOneByte(infoClass)
	w.WriteOneByte(flags)
	w.WriteUint32(0) // FileIndex
	w.WriteFileID(fileID)
	w.WriteUint16(fileNameOffset)
	w.WriteUint16(uint16(len(patternUTF16)))
	w.WriteUint32(65536) // OutputBufferLength
	w.WriteBytes(patternUTF16)

	return &SMB2Message{
		Header:  makeHeader(SMB2_QUERY_DIRECTORY, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildQueryInfoMsg(sessionID uint64, treeID uint32, fileID FileID, infoType, infoClass uint8) *SMB2Message {
	w := NewByteWriter(44)
	w.WriteUint16(41)
	w.WriteOneByte(infoType)
	w.WriteOneByte(infoClass)
	w.WriteUint32(65536) // OutputBufferLength
	w.WriteUint16(0)     // InputBufferOffset
	w.WriteUint16(0)     // Reserved
	w.WriteUint32(0)     // InputBufferLength
	w.WriteUint32(0)     // AdditionalInformation
	w.WriteUint32(0)     // Flags
	w.WriteFileID(fileID)

	return &SMB2Message{
		Header:  makeHeader(SMB2_QUERY_INFO, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildSetInfoMsg(sessionID uint64, treeID uint32, fileID FileID, infoType, infoClass uint8, buffer []byte) *SMB2Message {
	bufferOffset := uint16(SMB2HeaderSize + 32)

	w := NewByteWriter(64 + len(buffer))
	w.WriteUint16(33)
	w.WriteOneByte(infoType)
	w.WriteOneByte(infoClass)
	w.WriteUint32(uint32(len(buffer)))
	w.WriteUint16(bufferOffset)
	w.WriteUint16(0) // Reserved
	w.WriteUint32(0) // AdditionalInformation
	w.WriteFileID(fileID)
	w.WriteBytes(buffer)

	return &SMB2Message{
		Header:  makeHeader(SMB2_SET_INFO, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

func buildIOCTLMsg(sessionID uint64, treeID uint32, ctlCode uint32, fileID FileID, input []byte) *SMB2Message {
	inputOffset := uint32(0)
	if len(input) > 0 {
		inputOffset = uint32(SMB2HeaderSize + 56)
	}

	w := NewByteWriter(64 + len(input))
	w.WriteUint16(57)
	w.WriteUint16(0)
	w.WriteUint32(ctlCode)
	w.WriteUint64(fileID.Persistent)
	w.WriteUint64(fileID.Volatile)
	w.WriteUint32(inputOffset)
	w.WriteUint32(uint32(len(input)))
	w.WriteUint32(65536) // MaxInputResponse
	w.WriteUint32(0)     // OutputOffset
	w.WriteUint32(0)     // OutputCount
	w.WriteUint32(65536) // MaxOutputResponse
	w.WriteUint32(0x00000001) // Flags (FSCTL)
	w.WriteUint32(0)
	w.WriteBytes(input)

	return &SMB2Message{
		Header:  makeHeader(SMB2_IOCTL, sessionID, treeID),
		Payload: w.Bytes(),
	}
}

// ---------------------------------------------------------------------------
// Backward-compatible payload-only builders
// ---------------------------------------------------------------------------

func buildSessionSetupRequest(securityBlob []byte) []byte {
	return buildSessionSetupMsg(0, securityBlob).Payload
}

func buildTreeConnectRequest(uncPath string) []byte {
	return buildTreeConnectMsg(0, uncPath).Payload
}

func buildIOCTLRequest(ctlCode uint32, inputBuffer []byte) []byte {
	return buildIOCTLMsg(0, 0, ctlCode, FileID{
		Persistent: 0xFFFFFFFFFFFFFFFF,
		Volatile:   0xFFFFFFFFFFFFFFFF,
	}, inputBuffer).Payload
}

func buildLogoffRequest() []byte {
	return buildLogoffMsg(0).Payload
}

func buildTreeDisconnectRequest() []byte {
	return buildTreeDisconnectMsg(0, 0).Payload
}

// ---------------------------------------------------------------------------
// Negotiate helpers
// ---------------------------------------------------------------------------

// negotiateWith sends a NEGOTIATE via HandleMessage and returns the response status.
func negotiateWith(t *testing.T, env *handlerEnv, dialects []SMBDialect) NTStatus {
	t.Helper()
	msg := buildNegotiateMsg(dialects)

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("negotiateWith: HandleMessage returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("negotiateWith: HandleMessage returned nil response")
	}
	return resp.Header.Status
}

// negotiateDefault performs a negotiate with SMB 2.1 dialect.
func negotiateDefault(t *testing.T, env *handlerEnv) {
	t.Helper()
	status := negotiateWith(t, env, []SMBDialect{SMB2_1})
	if status != STATUS_SUCCESS {
		t.Fatalf("negotiateDefault: expected STATUS_SUCCESS, got %s", status)
	}
}

// negotiateWithMsg sends a NEGOTIATE *SMB2Message and returns the full response.
func negotiateWithMsg(t *testing.T, env *handlerEnv, msg *SMB2Message) *SMB2Message {
	t.Helper()
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("negotiateWithMsg: HandleMessage returned error: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Session setup helpers
// ---------------------------------------------------------------------------

// authenticateGuest performs a SESSION_SETUP that authenticates as guest.
// The server must have AllowGuest=true. Returns the session ID.
func authenticateGuest(t *testing.T, env *handlerEnv) uint64 {
	t.Helper()
	msg := buildSessionSetupMsg(0, []byte("not-ntlm"))

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("authenticateGuest: HandleMessage returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("authenticateGuest: HandleMessage returned nil response")
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("authenticateGuest: expected STATUS_SUCCESS, got %s", resp.Header.Status)
	}
	if resp.Header.SessionID == 0 {
		t.Fatal("authenticateGuest: session ID is 0")
	}

	session := env.server.sessions.GetSession(resp.Header.SessionID)
	if session == nil {
		t.Fatal("authenticateGuest: session not found in manager")
	}
	env.state.session = session
	return resp.Header.SessionID
}

// ---------------------------------------------------------------------------
// Tree connect helpers
// ---------------------------------------------------------------------------

// connectTree performs a TREE_CONNECT and returns the tree ID.
func connectTree(t *testing.T, env *handlerEnv, sessionID uint64, shareName string) uint32 {
	t.Helper()
	msg := buildTreeConnectMsg(sessionID, `\\server\`+shareName)

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("connectTree(%s): HandleMessage returned error: %v", shareName, err)
	}
	if resp == nil {
		t.Fatalf("connectTree(%s): HandleMessage returned nil response", shareName)
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("connectTree(%s): expected STATUS_SUCCESS, got %s", shareName, resp.Header.Status)
	}
	if resp.Header.TreeID == 0 {
		t.Fatalf("connectTree(%s): tree ID is 0", shareName)
	}
	return resp.Header.TreeID
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

// parseNegotiateResponse extracts the selected dialect from a NEGOTIATE response.
func parseNegotiateResponse(t *testing.T, payload []byte) SMBDialect {
	t.Helper()
	if len(payload) < 8 {
		t.Fatalf("NEGOTIATE response too short: %d bytes", len(payload))
	}
	r := NewByteReader(payload)
	structSize := r.ReadUint16()
	if structSize != 65 {
		t.Fatalf("NEGOTIATE response StructureSize = %d, want 65", structSize)
	}
	_ = r.ReadUint16() // SecurityMode
	return SMBDialect(r.ReadUint16())
}

// parseCreateResponse extracts the FileID from a CREATE response.
func parseCreateResponse(t *testing.T, payload []byte) FileID {
	t.Helper()
	if len(payload) < 80 {
		t.Fatalf("CREATE response too short: %d bytes", len(payload))
	}
	persistent := binary.LittleEndian.Uint64(payload[64:72])
	volatile := binary.LittleEndian.Uint64(payload[72:80])
	return FileID{Persistent: persistent, Volatile: volatile}
}

// ---------------------------------------------------------------------------
// Time helper for deterministic tests
// ---------------------------------------------------------------------------

func withFixedTime(t *testing.T) {
	t.Helper()
	orig := now
	now = func() time.Time {
		return time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	}
	t.Cleanup(func() { now = orig })
}
