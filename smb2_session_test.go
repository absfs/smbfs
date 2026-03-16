package smbfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/md4" //nolint:staticcheck
)

// ---------------------------------------------------------------------------
// Session Setup tests
// ---------------------------------------------------------------------------

func TestSessionSetup_GuestAuth(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	sessionID := authenticateGuest(t, env)

	// Verify session was created and is guest
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found")
	}
	if !session.IsGuest {
		t.Error("expected session.IsGuest == true")
	}
	if session.State != SessionStateValid {
		t.Errorf("expected SessionStateValid, got %d", session.State)
	}
}

func TestSessionSetup_TooShortPayload(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Send a payload that's too short (< 24 bytes)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_SESSION_SETUP,
			CreditRequest: 1,
		},
		Payload: []byte{0x19, 0x00}, // Only 2 bytes
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{Command: SMB2_SESSION_SETUP, Flags: SMB2_FLAGS_SERVER_TO_REDIR}
	_, status := env.handler.handleSessionSetupImpl(env.state, msg, respHeader)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}

func TestSessionSetup_InvalidStructSize(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Build a 24-byte payload with wrong StructureSize (99 instead of 25)
	w := NewByteWriter(32)
	w.WriteUint16(99)  // Wrong StructureSize
	w.WriteOneByte(0)  // Flags
	w.WriteOneByte(0)  // SecurityMode
	w.WriteUint32(0)   // Capabilities
	w.WriteUint32(0)   // Channel
	w.WriteUint16(0)   // SecurityBufferOffset
	w.WriteUint16(0)   // SecurityBufferLength
	w.WriteUint64(0)   // PreviousSessionId

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_SESSION_SETUP,
			CreditRequest: 1,
		},
		Payload: w.Bytes(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{Command: SMB2_SESSION_SETUP, Flags: SMB2_FLAGS_SERVER_TO_REDIR}
	_, status := env.handler.handleSessionSetupImpl(env.state, msg, respHeader)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}

func TestSessionSetup_NTLMNegotiate(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Build an NTLM Type 1 (Negotiate) message
	ntlmType1 := buildNTLMType1()
	payload := buildSessionSetupRequest(ntlmType1)

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_SESSION_SETUP,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader := &SMB2Header{Command: SMB2_SESSION_SETUP, Flags: SMB2_FLAGS_SERVER_TO_REDIR}
	respPayload, status := env.handler.handleSessionSetupImpl(env.state, msg, respHeader)

	if status != STATUS_MORE_PROCESSING_REQUIRED {
		t.Fatalf("expected STATUS_MORE_PROCESSING_REQUIRED, got %s", status)
	}

	// The response should contain a security blob (SPNEGO-wrapped NTLM Type 2)
	if len(respPayload) < 8 {
		t.Fatalf("response payload too short: %d bytes", len(respPayload))
	}

	// Parse response: StructureSize(2) + SessionFlags(2) + SecBufOffset(2) + SecBufLen(2) + SecBuf(variable)
	r := NewByteReader(respPayload)
	structSize := r.ReadUint16()
	if structSize != 9 {
		t.Errorf("response StructureSize = %d, want 9", structSize)
	}
	_ = r.ReadUint16() // SessionFlags
	_ = r.ReadUint16() // SecurityBufferOffset
	secBufLen := r.ReadUint16()
	if secBufLen == 0 {
		t.Error("expected non-zero SecurityBufferLength (NTLM challenge)")
	}

	// Session ID should be set
	if respHeader.SessionID == 0 {
		t.Error("session ID should be non-zero after Type 1")
	}
}

func TestSessionSetup_NTLMFullFlow(t *testing.T) {
	withFixedTime(t)
	username := "testuser"
	password := "testpass"
	domain := ""

	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: false,
		Users:      map[string]string{username: password},
		ServerName: "TESTSERVER",
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Step 1: Send NTLM Type 1 (Negotiate)
	ntlmType1 := buildNTLMType1()
	payload1 := buildSessionSetupRequest(ntlmType1)

	msg1 := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_SESSION_SETUP,
			CreditRequest: 1,
		},
		Payload: payload1,
	}
	copy(msg1.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader1 := &SMB2Header{Command: SMB2_SESSION_SETUP, Flags: SMB2_FLAGS_SERVER_TO_REDIR}
	respPayload1, status1 := env.handler.handleSessionSetupImpl(env.state, msg1, respHeader1)
	if status1 != STATUS_MORE_PROCESSING_REQUIRED {
		t.Fatalf("Type 1: expected STATUS_MORE_PROCESSING_REQUIRED, got %s", status1)
	}

	sessionID := respHeader1.SessionID
	if sessionID == 0 {
		t.Fatal("session ID is 0 after Type 1")
	}

	// Extract NTLM challenge from SPNEGO response
	r := NewByteReader(respPayload1)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // SessionFlags
	_ = r.ReadUint16() // SecurityBufferOffset
	secBufLen := r.ReadUint16()
	secBuf := r.ReadBytes(int(secBufLen))

	serverChallenge := extractChallengeFromSPNEGO(t, secBuf)
	if len(serverChallenge) != 8 {
		t.Fatalf("server challenge length = %d, want 8", len(serverChallenge))
	}

	// Step 2: Build and send NTLM Type 3 (Authenticate)
	ntlmType3 := buildNTLMType3(username, password, domain, serverChallenge)
	payload3 := buildSessionSetupRequest(ntlmType3)

	msg3 := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_SESSION_SETUP,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload3,
	}
	copy(msg3.Header.ProtocolID[:], SMB2ProtocolID)

	respHeader3 := &SMB2Header{
		Command:   SMB2_SESSION_SETUP,
		SessionID: sessionID,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR,
	}
	_, status3 := env.handler.handleSessionSetupImpl(env.state, msg3, respHeader3)
	if status3 != STATUS_SUCCESS {
		t.Fatalf("Type 3: expected STATUS_SUCCESS, got %s", status3)
	}

	// Verify session state
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found after auth")
	}
	if session.State != SessionStateValid {
		t.Errorf("expected SessionStateValid, got %d", session.State)
	}
	if !strings.EqualFold(session.Username, username) {
		t.Errorf("username = %q, want %q", session.Username, username)
	}
	if session.IsGuest {
		t.Error("expected non-guest session")
	}
}

func TestLogoff_ValidSession(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	// Send logoff
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_LOGOFF,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: buildLogoffRequest(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleLogoffImpl(env.state, msg)
	if status != STATUS_SUCCESS {
		t.Errorf("expected STATUS_SUCCESS, got %s", status)
	}

	// Session should be destroyed
	session := env.server.sessions.GetSession(sessionID)
	if session != nil {
		t.Error("session still exists after logoff")
	}
	if env.state.session != nil {
		t.Error("connState.session should be nil after logoff")
	}
}

func TestLogoff_InvalidSession(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	// Send logoff with a bogus session ID (no session was created)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_LOGOFF,
			SessionID:     0xDEADBEEF,
			CreditRequest: 1,
		},
		Payload: buildLogoffRequest(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleLogoffImpl(env.state, msg)
	if status == STATUS_SUCCESS {
		t.Error("expected error status for invalid session, got STATUS_SUCCESS")
	}
}

// ---------------------------------------------------------------------------
// NTLM message builders for tests
// ---------------------------------------------------------------------------

// buildNTLMType1 creates a minimal NTLM Type 1 (Negotiate) message.
func buildNTLMType1() []byte {
	buf := make([]byte, 32)
	copy(buf[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(buf[8:12], ntlmNegotiateMessage)
	// Flags: UNICODE | NTLM | REQUEST_TARGET | EXTENDED_SESSION_SECURITY | KEY_EXCH | 128
	flags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM |
		ntlmFlagRequestTarget | ntlmFlagNegotiateExtendedSessionSec |
		ntlmFlagNegotiateKeyExch | ntlmFlagNegotiate128 |
		ntlmFlagNegotiateAlwaysSign | ntlmFlagNegotiateSign)
	binary.LittleEndian.PutUint32(buf[12:16], flags)
	// DomainNameFields (Len, MaxLen, Offset) = 0
	// WorkstationFields = 0
	// Version: 6.1.7601.15
	buf[24] = 6  // Major
	buf[25] = 1  // Minor
	binary.LittleEndian.PutUint16(buf[26:28], 7601)
	buf[31] = 15 // NTLM revision
	return buf
}

// extractChallengeFromSPNEGO extracts the 8-byte server challenge from an
// SPNEGO-wrapped NTLM Type 2 message.
func extractChallengeFromSPNEGO(t *testing.T, spnegoBlob []byte) []byte {
	t.Helper()
	// Scan for NTLMSSP signature in blob
	for i := 0; i+8 <= len(spnegoBlob); i++ {
		if bytes.Equal(spnegoBlob[i:i+8], ntlmSignature) {
			ntlmMsg := spnegoBlob[i:]
			if len(ntlmMsg) < 32 {
				t.Fatal("NTLM Type 2 message too short")
			}
			msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])
			if msgType != ntlmChallengeMessage {
				t.Fatalf("expected NTLM Type 2, got type %d", msgType)
			}
			return ntlmMsg[24:32] // Server challenge is at offset 24
		}
	}
	t.Fatal("NTLMSSP signature not found in SPNEGO blob")
	return nil
}

// buildNTLMType3 creates an NTLM Type 3 (Authenticate) message with a valid
// NTLMv2 response for the given credentials and server challenge.
func buildNTLMType3(username, password, domain string, serverChallenge []byte) []byte {
	// Compute NTLMv2 hash: HMAC_MD5(NT_Hash, UPPER(user) + UPPER(domain))
	utf16Pass := EncodeStringToUTF16LE(password)
	md4h := md4.New()
	md4h.Write(utf16Pass)
	ntHash := md4h.Sum(nil)

	userDomain := strings.ToUpper(username) + strings.ToUpper(domain)
	userDomainUTF16 := EncodeStringToUTF16LE(userDomain)
	mac := hmac.New(md5.New, ntHash)
	mac.Write(userDomainUTF16)
	responseKeyNT := mac.Sum(nil)

	// Build a minimal NTLMv2 client blob
	// RespType(1) + HiRespType(1) + Reserved1(2) + Reserved2(4) + TimeStamp(8) +
	// ChallengeFromClient(8) + Reserved3(4) + AvPairs(min 4 bytes for EOL)
	clientChallenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	blob := make([]byte, 28+4) // 28 bytes + 4 bytes for MsvAvEOL
	blob[0] = 1                // RespType
	blob[1] = 1                // HiRespType
	// Reserved1, Reserved2 = 0 already
	// TimeStamp = 0 (8 bytes at offset 8)
	copy(blob[16:24], clientChallenge)
	// Reserved3 = 0 (4 bytes at offset 24)
	// MsvAvEOL at offset 28: AvId=0, AvLen=0
	binary.LittleEndian.PutUint16(blob[28:30], 0) // AvId = MsvAvEOL
	binary.LittleEndian.PutUint16(blob[30:32], 0) // AvLen = 0

	// Compute NTProofStr = HMAC_MD5(responseKeyNT, serverChallenge + blob)
	mac2 := hmac.New(md5.New, responseKeyNT)
	mac2.Write(serverChallenge)
	mac2.Write(blob)
	ntProofStr := mac2.Sum(nil)

	// Full NTLMv2 response = NTProofStr(16) + ClientBlob
	ntResponse := append(ntProofStr, blob...)

	// Compute session base key = HMAC_MD5(responseKeyNT, ntProofStr)
	mac3 := hmac.New(md5.New, responseKeyNT)
	mac3.Write(ntProofStr)
	sessionBaseKey := mac3.Sum(nil)

	// Generate random exported session key and encrypt with RC4(sessionBaseKey)
	exportedSessionKey := make([]byte, 16)
	for i := range exportedSessionKey {
		exportedSessionKey[i] = byte(i + 0x10) // deterministic for testing
	}
	cipher, _ := rc4.NewCipher(sessionBaseKey)
	encryptedSessionKey := make([]byte, 16)
	cipher.XORKeyStream(encryptedSessionKey, exportedSessionKey)

	// Build NTLM Type 3 message
	usernameUTF16 := EncodeStringToUTF16LE(username)
	domainUTF16 := EncodeStringToUTF16LE(domain)
	lmResponse := make([]byte, 24) // Empty LM response

	// Calculate offsets (after 88-byte fixed header)
	fixedSize := 88
	lmOffset := fixedSize
	ntOffset := lmOffset + len(lmResponse)
	domainOffset := ntOffset + len(ntResponse)
	userOffset := domainOffset + len(domainUTF16)
	workstationOffset := userOffset + len(usernameUTF16)
	encKeyOffset := workstationOffset + 0 // empty workstation

	totalSize := encKeyOffset + len(encryptedSessionKey)
	msg := make([]byte, totalSize)

	// Signature + MessageType
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuthenticateMessage)

	// LmChallengeResponseFields (offset 12)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(lmOffset))

	// NtChallengeResponseFields (offset 20)
	binary.LittleEndian.PutUint16(msg[20:22], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(msg[24:28], uint32(ntOffset))

	// DomainNameFields (offset 28)
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domainOffset))

	// UserNameFields (offset 36)
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(usernameUTF16)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(usernameUTF16)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(userOffset))

	// WorkstationFields (offset 44)
	binary.LittleEndian.PutUint16(msg[44:46], 0)
	binary.LittleEndian.PutUint16(msg[46:48], 0)
	binary.LittleEndian.PutUint32(msg[48:52], uint32(workstationOffset))

	// EncryptedRandomSessionKeyFields (offset 52)
	binary.LittleEndian.PutUint16(msg[52:54], uint16(len(encryptedSessionKey)))
	binary.LittleEndian.PutUint16(msg[54:56], uint16(len(encryptedSessionKey)))
	binary.LittleEndian.PutUint32(msg[56:60], uint32(encKeyOffset))

	// NegotiateFlags (offset 60)
	flags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM |
		ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateKeyExch |
		ntlmFlagNegotiate128 | ntlmFlagNegotiateAlwaysSign | ntlmFlagNegotiateSign)
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// Version (offset 64-72)
	msg[64] = 6
	msg[65] = 1
	binary.LittleEndian.PutUint16(msg[66:68], 7601)
	msg[71] = 15

	// MIC (offset 72-88): zeros for now

	// Copy variable-length data
	copy(msg[lmOffset:], lmResponse)
	copy(msg[ntOffset:], ntResponse)
	copy(msg[domainOffset:], domainUTF16)
	copy(msg[userOffset:], usernameUTF16)
	copy(msg[encKeyOffset:], encryptedSessionKey)

	return msg
}
