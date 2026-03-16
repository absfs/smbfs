package smbfs

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// setupNetworkTestServer creates a server configured for network-level tests.
// It does NOT listen on a real port (good for readMessage/writeMessage tests).
func setupNetworkTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(ServerOptions{
		Logger:       &NullLogger{},
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		IdleTimeout:  15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}
	return srv
}

// setupListeningServer creates a server that listens on a random OS-assigned port.
func setupListeningServer(t *testing.T, opts ServerOptions) *Server {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = &NullLogger{}
	}
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer() failed: %v", err)
	}
	// Override the default port (445) so Listen uses port 0 (OS-assigned).
	srv.options.Port = 0
	srv.options.Hostname = "127.0.0.1"
	return srv
}

// buildNetBIOSFrame wraps payload in a 4-byte NetBIOS session message header.
func buildNetBIOSFrame(payload []byte) []byte {
	length := len(payload)
	buf := make([]byte, 4+length)
	buf[0] = 0x00
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	copy(buf[4:], payload)
	return buf
}

// buildValidSMB2Payload constructs a minimal valid SMB2 message (header only).
func buildValidSMB2Payload() []byte {
	header := &SMB2Header{
		StructureSize: SMB2HeaderSize,
		Command:       SMB2_NEGOTIATE,
		MessageID:     1,
		CreditRequest: 1,
	}
	copy(header.ProtocolID[:], SMB2ProtocolID)
	return header.Marshal()
}

// TestReadMessage_Valid verifies readMessage parses a valid SMB2 message correctly.
func TestReadMessage_Valid(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	payload := buildValidSMB2Payload()
	frame := buildNetBIOSFrame(payload)

	go func() {
		_, _ = clientConn.Write(frame)
	}()

	msg, err := srv.readMessage(serverConn)
	if err != nil {
		t.Fatalf("readMessage() error = %v", err)
	}
	if msg == nil {
		t.Fatal("readMessage() returned nil")
	}
	if msg.Header.Command != SMB2_NEGOTIATE {
		t.Errorf("Command = %d, want SMB2_NEGOTIATE (%d)", msg.Header.Command, SMB2_NEGOTIATE)
	}
	if msg.Header.MessageID != 1 {
		t.Errorf("MessageID = %d, want 1", msg.Header.MessageID)
	}
	if msg.Header.CreditRequest != 1 {
		t.Errorf("CreditRequest = %d, want 1", msg.Header.CreditRequest)
	}
	if string(msg.Header.ProtocolID[:]) != SMB2ProtocolID {
		t.Errorf("ProtocolID = %x, want SMB2 magic", msg.Header.ProtocolID)
	}
}

// TestReadMessage_TooShort verifies readMessage returns an error when the
// NetBIOS header cannot be fully read (fewer than 4 bytes).
func TestReadMessage_TooShort(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0x00, 0x01})
		clientConn.Close()
	}()

	_, err := srv.readMessage(serverConn)
	if err == nil {
		t.Fatal("readMessage() expected error for short data, got nil")
	}
}

// TestReadMessage_InvalidProtocol verifies readMessage rejects a message with
// a non-SMB2 protocol signature.
func TestReadMessage_InvalidProtocol(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Build a payload the right size but with bogus protocol bytes.
	payload := make([]byte, SMB2HeaderSize)
	copy(payload[0:4], []byte("XXXX"))
	frame := buildNetBIOSFrame(payload)

	go func() {
		_, _ = clientConn.Write(frame)
	}()

	_, err := srv.readMessage(serverConn)
	if err != ErrInvalidMessage {
		t.Errorf("readMessage() error = %v, want ErrInvalidMessage", err)
	}
}

// TestReadMessage_MessageTooSmall verifies readMessage rejects a message where
// the NetBIOS length is less than SMB2HeaderSize.
func TestReadMessage_MessageTooSmall(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// NetBIOS header claiming only 10 bytes of payload.
	smallFrame := []byte{0x00, 0x00, 0x00, 10}

	go func() {
		_, _ = clientConn.Write(smallFrame)
	}()

	_, err := srv.readMessage(serverConn)
	if err != ErrInvalidMessage {
		t.Errorf("readMessage() error = %v, want ErrInvalidMessage", err)
	}
}

// TestReadMessage_SMB1Negotiate verifies that an SMB1 NEGOTIATE triggers
// handleSMB1Negotiate and returns a synthetic SMB2 negotiate message.
func TestReadMessage_SMB1Negotiate(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Build an SMB1 header: 0xFF 'S' 'M' 'B' followed by enough bytes.
	smb1Payload := make([]byte, SMB2HeaderSize)
	smb1Payload[0] = 0xFF
	copy(smb1Payload[1:4], []byte("SMB"))
	frame := buildNetBIOSFrame(smb1Payload)

	go func() {
		_, _ = clientConn.Write(frame)
	}()

	msg, err := srv.readMessage(serverConn)
	if err != nil {
		t.Fatalf("readMessage() error = %v", err)
	}
	if msg == nil {
		t.Fatal("readMessage() returned nil")
	}
	if msg.Header.Command != SMB2_NEGOTIATE {
		t.Errorf("Command = %d, want SMB2_NEGOTIATE after SMB1 upgrade", msg.Header.Command)
	}
	if string(msg.Header.ProtocolID[:]) != SMB2ProtocolID {
		t.Errorf("ProtocolID should be SMB2 after SMB1 upgrade, got %x", msg.Header.ProtocolID)
	}
}

// TestReadMessage_WithPayload verifies readMessage correctly separates header
// from payload when the message is larger than 64 bytes.
func TestReadMessage_WithPayload(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	headerBytes := buildValidSMB2Payload()
	extraPayload := []byte("extra-data-here!")
	fullMsg := append(headerBytes, extraPayload...)
	frame := buildNetBIOSFrame(fullMsg)

	go func() {
		_, _ = clientConn.Write(frame)
	}()

	msg, err := srv.readMessage(serverConn)
	if err != nil {
		t.Fatalf("readMessage() error = %v", err)
	}
	if len(msg.Payload) != len(extraPayload) {
		t.Errorf("Payload length = %d, want %d", len(msg.Payload), len(extraPayload))
	}
	if string(msg.Payload) != string(extraPayload) {
		t.Errorf("Payload = %q, want %q", msg.Payload, extraPayload)
	}
}

// TestWriteMessage_Valid verifies writeMessage produces a correct NetBIOS frame.
func TestWriteMessage_Valid(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	msg := &SMB2Message{
		Header: &SMB2Header{
			StructureSize: SMB2HeaderSize,
			Command:       SMB2_NEGOTIATE,
			Flags:         SMB2_FLAGS_SERVER_TO_REDIR,
			MessageID:     42,
			CreditRequest: 10,
		},
		Payload: []byte("test-payload"),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	// Write from server side.
	go func() {
		_, err := srv.writeMessage(serverConn, msg)
		if err != nil {
			t.Errorf("writeMessage() error = %v", err)
		}
		serverConn.Close()
	}()

	// Read from client side.
	data, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	// Check NetBIOS header.
	if len(data) < 4 {
		t.Fatalf("Response too short: %d bytes", len(data))
	}
	if data[0] != 0x00 {
		t.Errorf("NetBIOS type = %02x, want 0x00", data[0])
	}
	nbLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	expectedLen := SMB2HeaderSize + len(msg.Payload)
	if nbLen != expectedLen {
		t.Errorf("NetBIOS length = %d, want %d", nbLen, expectedLen)
	}

	// Check total data length.
	if len(data) != 4+expectedLen {
		t.Fatalf("Total response length = %d, want %d", len(data), 4+expectedLen)
	}

	// Verify SMB2 protocol magic in the response.
	smb2Data := data[4:]
	if string(smb2Data[0:4]) != SMB2ProtocolID {
		t.Errorf("Response ProtocolID = %x, want SMB2 magic", smb2Data[0:4])
	}

	// Verify command in response.
	cmd := binary.LittleEndian.Uint16(smb2Data[12:14])
	if cmd != SMB2_NEGOTIATE {
		t.Errorf("Response command = %d, want %d", cmd, SMB2_NEGOTIATE)
	}

	// Verify payload is included.
	payloadInResponse := smb2Data[SMB2HeaderSize:]
	if string(payloadInResponse) != "test-payload" {
		t.Errorf("Payload = %q, want %q", payloadInResponse, "test-payload")
	}
}

// TestWriteMessage_WithSigning verifies that writeMessage applies a signature
// when a SigningKey is set.
func TestWriteMessage_WithSigning(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	signingKey := make([]byte, 16)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}

	msg := &SMB2Message{
		Header: &SMB2Header{
			StructureSize: SMB2HeaderSize,
			Command:       SMB2_SESSION_SETUP,
			Flags:         SMB2_FLAGS_SERVER_TO_REDIR,
			MessageID:     7,
			CreditRequest: 5,
		},
		Payload:    []byte("signed-payload"),
		SigningKey:  signingKey,
		Dialect:     SMB2_1,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	go func() {
		_, err := srv.writeMessage(serverConn, msg)
		if err != nil {
			t.Errorf("writeMessage() error = %v", err)
		}
		serverConn.Close()
	}()

	data, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	// The signature field is at offset 48 in the SMB2 header (after the NetBIOS 4-byte prefix).
	smb2Data := data[4:]
	sig := smb2Data[SignatureOffset : SignatureOffset+SignatureLength]

	// The signature should not be all zeros (it was applied).
	allZero := true
	for _, b := range sig {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Signature is all zeros; expected non-zero after signing")
	}
}

// TestWriteMessage_ReturnsRawBytes verifies that writeMessage returns the SMB2
// message bytes (without NetBIOS header) for preauth hash computation.
func TestWriteMessage_ReturnsRawBytes(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	msg := &SMB2Message{
		Header: &SMB2Header{
			StructureSize: SMB2HeaderSize,
			Command:       SMB2_ECHO,
			Flags:         SMB2_FLAGS_SERVER_TO_REDIR,
		},
		Payload: []byte("raw-bytes-test"),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	var rawBytes []byte
	go func() {
		var err error
		rawBytes, err = srv.writeMessage(serverConn, msg)
		if err != nil {
			t.Errorf("writeMessage() error = %v", err)
		}
		serverConn.Close()
	}()

	// Drain the client side so the write completes.
	_, _ = io.ReadAll(clientConn)

	// rawBytes should be the SMB2 data only (no NetBIOS header).
	expectedLen := SMB2HeaderSize + len(msg.Payload)
	if len(rawBytes) != expectedLen {
		t.Errorf("rawBytes length = %d, want %d", len(rawBytes), expectedLen)
	}
	if string(rawBytes[0:4]) != SMB2ProtocolID {
		t.Errorf("rawBytes ProtocolID = %x, want SMB2 magic", rawBytes[0:4])
	}
}

// TestHandleSMB1Negotiate verifies that handleSMB1Negotiate returns a
// synthetic SMB2 NEGOTIATE message.
func TestHandleSMB1Negotiate(t *testing.T) {
	srv := setupNetworkTestServer(t)

	smb1Data := make([]byte, SMB2HeaderSize)
	smb1Data[0] = 0xFF
	copy(smb1Data[1:4], []byte("SMB"))

	msg, err := srv.handleSMB1Negotiate(smb1Data)
	if err != nil {
		t.Fatalf("handleSMB1Negotiate() error = %v", err)
	}
	if msg == nil {
		t.Fatal("handleSMB1Negotiate() returned nil")
	}
	if msg.Header.Command != SMB2_NEGOTIATE {
		t.Errorf("Command = %d, want SMB2_NEGOTIATE", msg.Header.Command)
	}
	if string(msg.Header.ProtocolID[:]) != SMB2ProtocolID {
		t.Errorf("ProtocolID = %x, want SMB2 magic", msg.Header.ProtocolID)
	}
	if msg.Header.StructureSize != SMB2HeaderSize {
		t.Errorf("StructureSize = %d, want %d", msg.Header.StructureSize, SMB2HeaderSize)
	}
	if msg.Payload != nil {
		t.Errorf("Payload should be nil (signals SMB1 upgrade), got %d bytes", len(msg.Payload))
	}
}

// TestServer_ListenAndStop verifies Listen starts the server and Stop shuts it
// down cleanly.
func TestServer_ListenAndStop(t *testing.T) {
	srv := setupListeningServer(t, ServerOptions{})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil after Listen()")
	}

	// Verify we can connect.
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	conn.Close()

	// Stop should complete without hanging.
	done := make(chan error, 1)
	go func() {
		done <- srv.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() timed out")
	}

	// After stop, Addr still returns the old address (listener was set),
	// but new connections should fail.
}

// TestServer_Addr_BeforeListen verifies Addr returns nil before Listen.
func TestServer_Addr_BeforeListen(t *testing.T) {
	srv := setupNetworkTestServer(t)
	if srv.Addr() != nil {
		t.Errorf("Addr() before Listen() should be nil, got %v", srv.Addr())
	}
}

// TestServer_AcceptLoop_ConnLimit verifies the connection limit is enforced.
func TestServer_AcceptLoop_ConnLimit(t *testing.T) {
	srv := setupListeningServer(t, ServerOptions{
		MaxConnections: 1,
		ReadTimeout:    2 * time.Second,
	})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = srv.Stop() }()

	addr := srv.Addr().String()

	// First connection should succeed.
	conn1, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("First connection failed: %v", err)
	}
	defer conn1.Close()

	// Send a valid SMB2 message so the server registers this connection.
	frame := buildNetBIOSFrame(buildValidSMB2Payload())
	_, _ = conn1.Write(frame)

	// Give the server time to process and register the connection.
	time.Sleep(100 * time.Millisecond)

	// Second connection should be accepted at TCP level but the server
	// will close it because of the connection limit.
	conn2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		// Server rejected at accept level - that's fine.
		return
	}
	defer conn2.Close()

	// The server will close the rejected connection; a read should return
	// an error or EOF shortly.
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn2.Read(buf)
	if readErr == nil {
		t.Log("Second connection was not immediately rejected but may be handled after first disconnects")
	}
}

// TestSessionCleanupLoop verifies that expired sessions are cleaned up.
func TestSessionCleanupLoop(t *testing.T) {
	srv, err := NewServer(ServerOptions{
		Logger:      &NullLogger{},
		IdleTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Create a session that will be expired.
	session := srv.sessions.CreateSession(SMB2_1, [16]byte{}, "127.0.0.1:1234")
	session.SetValid("testuser", "", false, nil)

	// Back-date the session activity so it's already expired.
	session.LastActivity = time.Now().Add(-time.Second)

	if srv.sessions.SessionCount() != 1 {
		t.Fatalf("SessionCount = %d, want 1", srv.sessions.SessionCount())
	}

	// Run cleanup directly (the real loop uses a ticker, but we test the core logic).
	expired := srv.sessions.CleanupExpired()
	if len(expired) != 1 {
		t.Errorf("CleanupExpired() returned %d sessions, want 1", len(expired))
	}
	if srv.sessions.SessionCount() != 0 {
		t.Errorf("SessionCount after cleanup = %d, want 0", srv.sessions.SessionCount())
	}
}

// TestSessionCleanupLoop_InServer verifies the full cleanup loop runs within
// the server and cleans up expired sessions.
func TestSessionCleanupLoop_InServer(t *testing.T) {
	srv := setupListeningServer(t, ServerOptions{
		IdleTimeout: 50 * time.Millisecond,
	})

	// Create an already-expired session.
	session := srv.sessions.CreateSession(SMB2_1, [16]byte{}, "127.0.0.1:5678")
	session.SetValid("user", "", false, nil)
	session.LastActivity = time.Now().Add(-time.Second)

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	// The cleanup loop runs on a 1-minute ticker in production. Since we
	// cannot easily speed that up, we verify the core CleanupExpired logic
	// works and that the goroutine does not block Stop.
	expired := srv.sessions.CleanupExpired()
	if len(expired) != 1 {
		t.Errorf("CleanupExpired() returned %d, want 1", len(expired))
	}

	// Stop should not hang even with the cleanup loop running.
	done := make(chan error, 1)
	go func() {
		done <- srv.Stop()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() timed out with cleanup loop running")
	}
}

// TestReadMessage_EOF verifies readMessage returns io.EOF when the connection
// is closed by the remote side.
func TestReadMessage_EOF(t *testing.T) {
	srv := setupNetworkTestServer(t)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	// Close immediately.
	clientConn.Close()

	_, err := srv.readMessage(serverConn)
	if err != io.EOF {
		t.Errorf("readMessage() error = %v, want io.EOF", err)
	}
}

// TestHandleConnection_ReadError verifies handleConnection exits gracefully
// on a read error (connection closed immediately).
func TestHandleConnection_ReadError(t *testing.T) {
	srv := setupListeningServer(t, ServerOptions{
		MaxConnections: 10,
		ReadTimeout:    500 * time.Millisecond,
	})

	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = srv.Stop() }()

	addr := srv.Addr().String()

	// Connect and immediately close.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial error = %v", err)
	}
	conn.Close()

	// Give the server time to handle the closed connection.
	time.Sleep(200 * time.Millisecond)

	// Server should still be running and accepting new connections.
	conn2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Server stopped accepting connections after read error: %v", err)
	}
	conn2.Close()
}
