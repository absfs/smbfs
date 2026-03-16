package smbfs

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Tree Connect tests
// ---------------------------------------------------------------------------

func TestTreeConnect_ValidShare(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	env.addTestShare(t, "data", ShareOptions{AllowGuest: true})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	treeID := connectTree(t, env, sessionID, "data")
	if treeID == 0 {
		t.Fatal("tree ID should not be zero")
	}

	// Verify tree connection exists on the session
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found")
	}
	tree := session.GetTreeConnection(treeID)
	if tree == nil {
		t.Fatal("tree connection not found")
	}
	if tree.ShareName != "data" {
		t.Errorf("tree ShareName = %q, want %q", tree.ShareName, "data")
	}
}

func TestTreeConnect_NonExistentShare(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	uncPath := `\\server\nonexistent`
	payload := buildTreeConnectRequest(uncPath)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_CONNECT,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{
		Command:   SMB2_TREE_CONNECT,
		SessionID: sessionID,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR,
	}

	_, status := env.handler.handleTreeConnectImpl(env.state, msg, respHeader)
	if status != STATUS_BAD_NETWORK_NAME {
		t.Errorf("expected STATUS_BAD_NETWORK_NAME, got %s", status)
	}
}

func TestTreeConnect_NoSession(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	env.addTestShare(t, "data", ShareOptions{AllowGuest: true})
	negotiateDefault(t, env)
	// Do NOT authenticate — no valid session

	uncPath := `\\server\data`
	payload := buildTreeConnectRequest(uncPath)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_CONNECT,
			SessionID:     0xBAADF00D, // bogus session
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{
		Command:   SMB2_TREE_CONNECT,
		SessionID: 0xBAADF00D,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR,
	}

	_, status := env.handler.handleTreeConnectImpl(env.state, msg, respHeader)
	if status == STATUS_SUCCESS {
		t.Error("expected error status, got STATUS_SUCCESS")
	}
}

func TestTreeConnect_ReadOnlyShare(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	env.addTestShare(t, "readonly", ShareOptions{AllowGuest: true, ReadOnly: true})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	uncPath := `\\server\readonly`
	payload := buildTreeConnectRequest(uncPath)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_CONNECT,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{
		Command:   SMB2_TREE_CONNECT,
		SessionID: sessionID,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR,
	}

	respPayload, status := env.handler.handleTreeConnectImpl(env.state, msg, respHeader)
	if status != STATUS_SUCCESS {
		t.Fatalf("expected STATUS_SUCCESS, got %s", status)
	}

	// Parse MaximalAccess from the response (last 4 bytes of 16-byte response)
	if len(respPayload) < 16 {
		t.Fatalf("response payload too short: %d bytes", len(respPayload))
	}
	r := NewByteReader(respPayload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadOneByte() // ShareType
	_ = r.ReadOneByte() // Reserved
	_ = r.ReadUint32() // ShareFlags
	_ = r.ReadUint32() // Capabilities
	maxAccess := r.ReadUint32()

	// Read-only should NOT have FILE_WRITE_DATA
	if maxAccess&FILE_WRITE_DATA != 0 {
		t.Errorf("MaximalAccess 0x%08x should not include FILE_WRITE_DATA for read-only share", maxAccess)
	}
	// Should have FILE_READ_DATA
	if maxAccess&FILE_READ_DATA == 0 {
		t.Errorf("MaximalAccess 0x%08x should include FILE_READ_DATA", maxAccess)
	}
}

func TestTreeConnect_IPC(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	// IPC$ is auto-added by server
	uncPath := `\\server\IPC$`
	payload := buildTreeConnectRequest(uncPath)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_CONNECT,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{
		Command:   SMB2_TREE_CONNECT,
		SessionID: sessionID,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR,
	}

	respPayload, status := env.handler.handleTreeConnectImpl(env.state, msg, respHeader)
	if status != STATUS_SUCCESS {
		t.Fatalf("expected STATUS_SUCCESS, got %s", status)
	}

	// Verify ShareType is PIPE (0x02)
	if len(respPayload) < 3 {
		t.Fatalf("response payload too short: %d bytes", len(respPayload))
	}
	r := NewByteReader(respPayload)
	_ = r.ReadUint16()         // StructureSize
	shareType := r.ReadOneByte() // ShareType
	if shareType != uint8(SMBShareTypePipe) {
		t.Errorf("ShareType = 0x%02x, want 0x%02x (PIPE)", shareType, SMBShareTypePipe)
	}
}

// ---------------------------------------------------------------------------
// Tree Disconnect tests
// ---------------------------------------------------------------------------

func TestTreeDisconnect_Valid(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	env.addTestShare(t, "data", ShareOptions{AllowGuest: true})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)
	treeID := connectTree(t, env, sessionID, "data")

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_DISCONNECT,
			SessionID:     sessionID,
			TreeID:        treeID,
			CreditRequest: 1,
		},
		Payload: buildTreeDisconnectRequest(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleTreeDisconnectImpl(env.state, msg)
	if status != STATUS_SUCCESS {
		t.Errorf("expected STATUS_SUCCESS, got %s", status)
	}

	// Tree should be gone
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session unexpectedly destroyed")
	}
	tree := session.GetTreeConnection(treeID)
	if tree != nil {
		t.Error("tree connection still exists after disconnect")
	}
}

func TestTreeDisconnect_InvalidTree(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_DISCONNECT,
			SessionID:     sessionID,
			TreeID:        0xDEAD, // no tree connected
			CreditRequest: 1,
		},
		Payload: buildTreeDisconnectRequest(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleTreeDisconnectImpl(env.state, msg)
	if status == STATUS_SUCCESS {
		t.Error("expected error status for invalid tree ID, got STATUS_SUCCESS")
	}
}

func TestTreeDisconnect_NoSession(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_TREE_DISCONNECT,
			SessionID:     0xBAADF00D,
			TreeID:        1,
			CreditRequest: 1,
		},
		Payload: buildTreeDisconnectRequest(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleTreeDisconnectImpl(env.state, msg)
	if status == STATUS_SUCCESS {
		t.Error("expected error status for missing session, got STATUS_SUCCESS")
	}
}

// ---------------------------------------------------------------------------
// extractShareName tests
// ---------------------------------------------------------------------------

func TestExtractShareName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`\\server\share`, "share"},
		{`\\SERVER\Share$`, "Share$"},
		{`\\192.168.1.1\data`, "data"},
		{`\\server\share\subfolder`, "share"},
		{`//server/share`, "share"},
		{``, ""},
		{`\\server\`, ""},
		{`\\server`, "server"}, // no second separator: whole thing after removing leading slashes
		{`\\\\\server\\share`, ""},  // double backslash after server leaves empty segment
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractShareName(tt.input)
			if got != tt.want {
				t.Errorf("extractShareName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
