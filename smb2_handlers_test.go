package smbfs

import (
	"testing"
)

// TestHandleMessage_Echo sends an ECHO request and verifies STATUS_SUCCESS
// with a 4-byte response payload.
func TestHandleMessage_Echo(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := buildEchoMsg()
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(ECHO) error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage(ECHO) returned nil response")
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Errorf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
	if len(resp.Payload) != 4 {
		t.Errorf("payload length = %d, want 4", len(resp.Payload))
	}
	// Verify StructureSize field is 4
	if len(resp.Payload) >= 2 {
		r := NewByteReader(resp.Payload)
		structSize := r.ReadUint16()
		if structSize != 4 {
			t.Errorf("StructureSize = %d, want 4", structSize)
		}
	}
}

// TestHandleMessage_Cancel sends a CANCEL request and verifies nil response
// (CANCEL never gets a response per SMB2 spec).
func TestHandleMessage_Cancel(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_CANCEL, 0, 0),
		Payload: []byte{},
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(CANCEL) error: %v", err)
	}
	if resp != nil {
		t.Error("HandleMessage(CANCEL) should return nil response")
	}
}

// TestHandleMessage_UnknownCommand sends an unrecognized command code and
// verifies STATUS_NOT_SUPPORTED.
func TestHandleMessage_UnknownCommand(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := &SMB2Message{
		Header:  makeHeader(0xFFFF, 0, 0),
		Payload: []byte{},
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(0xFFFF) error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage(0xFFFF) returned nil response")
	}
	if resp.Header.Status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", resp.Header.Status)
	}
}

// TestHandleMessage_NegotiateDispatch verifies that a NEGOTIATE sent through
// HandleMessage is dispatched correctly, setting the dialect on connState.
func TestHandleMessage_NegotiateDispatch(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	// Clear dialect to verify it gets set
	env.state.dialect = 0

	msg := buildNegotiateMsg([]SMBDialect{SMB2_0_2, SMB2_1})
	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage(NEGOTIATE) error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage(NEGOTIATE) returned nil response")
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}
	if env.state.dialect == 0 {
		t.Error("state.dialect not set after NEGOTIATE dispatch")
	}
	// Should select the highest offered that the server supports
	if env.state.dialect != SMB2_1 {
		t.Errorf("state.dialect = %s, want SMB 2.1", env.state.dialect)
	}
}

// TestValidateSession_Valid creates a valid session and verifies
// validateSession succeeds.
func TestValidateSession_Valid(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	header := &SMB2Header{SessionID: sessionID}
	session, status := env.handler.validateSession(header)
	if status != STATUS_SUCCESS {
		t.Fatalf("validateSession() status = %s, want STATUS_SUCCESS", status)
	}
	if session == nil {
		t.Fatal("validateSession() returned nil session")
	}
	if session.ID != sessionID {
		t.Errorf("session ID = %d, want %d", session.ID, sessionID)
	}
}

// TestValidateSession_Invalid tests validateSession with a non-existent
// session ID.
func TestValidateSession_Invalid(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	header := &SMB2Header{SessionID: 0xDEADBEEF}
	session, status := env.handler.validateSession(header)
	if status == STATUS_SUCCESS {
		t.Error("validateSession() with invalid session should not return STATUS_SUCCESS")
	}
	if session != nil {
		t.Error("validateSession() with invalid session should return nil")
	}
}

// TestValidateTree_Valid creates a session + tree connection and verifies
// validateTree succeeds.
func TestValidateTree_Valid(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)
	treeID := connectTree(t, env, sessionID, "testshare")

	header := &SMB2Header{SessionID: sessionID, TreeID: treeID}
	session, tree, status := env.handler.validateTree(header)
	if status != STATUS_SUCCESS {
		t.Fatalf("validateTree() status = %s, want STATUS_SUCCESS", status)
	}
	if session == nil {
		t.Fatal("validateTree() returned nil session")
	}
	if tree == nil {
		t.Fatal("validateTree() returned nil tree")
	}
	if tree.ID != treeID {
		t.Errorf("tree ID = %d, want %d", tree.ID, treeID)
	}
	if tree.ShareName != "testshare" {
		t.Errorf("tree ShareName = %q, want %q", tree.ShareName, "testshare")
	}
}

// TestValidateTree_InvalidTree verifies that a valid session with a wrong
// tree ID fails validation.
func TestValidateTree_InvalidTree(t *testing.T) {
	env := setupHandlerEnvWithShare(t)
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	header := &SMB2Header{SessionID: sessionID, TreeID: 0xDEAD}
	session, tree, status := env.handler.validateTree(header)
	if status == STATUS_SUCCESS {
		t.Error("validateTree() with invalid tree should not return STATUS_SUCCESS")
	}
	if tree != nil {
		t.Error("validateTree() with invalid tree should return nil tree")
	}
	// Session should still be valid even though tree is invalid
	_ = session
}

// TestBuildErrorResponse verifies the error response is 9 bytes with
// StructureSize=9.
func TestBuildErrorResponse(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger: &NullLogger{},
	})

	errResp := env.handler.buildErrorResponse()
	if len(errResp) != 9 {
		t.Fatalf("buildErrorResponse() length = %d, want 9", len(errResp))
	}

	r := NewByteReader(errResp)
	structSize := r.ReadUint16()
	if structSize != 9 {
		t.Errorf("StructureSize = %d, want 9", structSize)
	}

	errorContextCount := r.ReadOneByte()
	if errorContextCount != 0 {
		t.Errorf("ErrorContextCount = %d, want 0", errorContextCount)
	}

	_ = r.ReadOneByte() // Reserved

	byteCount := r.ReadUint32()
	if byteCount != 0 {
		t.Errorf("ByteCount = %d, want 0", byteCount)
	}
}

// TestHandleMessage_Signing verifies that after negotiation and guest auth
// with a signing key, a signed request produces a signed response.
func TestHandleMessage_Signing(t *testing.T) {
	env := setupHandlerEnvWithShare(t)

	// Negotiate with SMB 2.1
	status := negotiateWith(t, env, []SMBDialect{SMB2_1})
	if status != STATUS_SUCCESS {
		t.Fatalf("NEGOTIATE status = %s, want STATUS_SUCCESS", status)
	}

	// Authenticate as guest (guest auth gives no signing key by default)
	sessionID := authenticateGuest(t, env)

	// Manually set a signing key on the session to test signing behavior
	signingKey := []byte("0123456789abcdef") // 16-byte test key
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found")
	}
	session.SigningKey = signingKey
	env.state.signingRequired = true

	// Connect to tree
	treeID := connectTree(t, env, sessionID, "testshare")

	// Send a signed ECHO request
	echoMsg := buildEchoMsg()
	echoMsg.Header.SessionID = sessionID
	echoMsg.Header.TreeID = treeID
	echoMsg.Header.Flags |= SMB2_FLAGS_SIGNED // Mark request as signed

	resp, err := env.handler.HandleMessage(env.state, echoMsg)
	if err != nil {
		t.Fatalf("HandleMessage(signed ECHO) error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage(signed ECHO) returned nil")
	}
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// The response should have the signed flag set
	if resp.Header.Flags&SMB2_FLAGS_SIGNED == 0 {
		t.Error("response does not have SMB2_FLAGS_SIGNED set")
	}

	// The response should have a signing key attached
	if len(resp.SigningKey) == 0 {
		t.Error("response SigningKey is empty, expected signing key to be set")
	}
}
