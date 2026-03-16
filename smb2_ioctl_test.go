package smbfs

import (
	"testing"
)

// ---------------------------------------------------------------------------
// IOCTL tests
// ---------------------------------------------------------------------------

func TestIOCTL_ValidateNegotiateInfo(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	payload := buildIOCTLRequest(FSCTL_VALIDATE_NEGOTIATE_INFO, nil)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("expected STATUS_NOT_SUPPORTED, got %s", status)
	}
}

func TestIOCTL_PipeTransceive(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	payload := buildIOCTLRequest(FSCTL_PIPE_TRANSCEIVE, []byte("hello"))
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("expected STATUS_NOT_SUPPORTED, got %s", status)
	}
}

func TestIOCTL_DFSReferrals(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	payload := buildIOCTLRequest(FSCTL_DFS_GET_REFERRALS, nil)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("expected STATUS_NOT_SUPPORTED, got %s", status)
	}
}

func TestIOCTL_NetworkInterfaceInfo(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	payload := buildIOCTLRequest(FSCTL_QUERY_NETWORK_INTERFACE_INFO, nil)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("expected STATUS_NOT_SUPPORTED, got %s", status)
	}
}

func TestIOCTL_UnsupportedCode(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	payload := buildIOCTLRequest(0xDEADBEEF, nil) // unknown IOCTL code
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_NOT_SUPPORTED {
		t.Errorf("expected STATUS_NOT_SUPPORTED, got %s", status)
	}
}

func TestIOCTL_TooShortPayload(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	// Send a payload that's too short (< 56 bytes)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: []byte{0x39, 0x00, 0x00, 0x00}, // only 4 bytes, StructureSize=57 but truncated
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}

func TestIOCTL_NoSession(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	// Do NOT authenticate

	payload := buildIOCTLRequest(FSCTL_VALIDATE_NEGOTIATE_INFO, nil)
	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     0xBAADF00D, // bogus session
			CreditRequest: 1,
		},
		Payload: payload,
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status == STATUS_SUCCESS || status == STATUS_NOT_SUPPORTED {
		t.Errorf("expected session validation error, got %s", status)
	}
}

func TestIOCTL_InvalidStructureSize(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)
	sessionID := authenticateGuest(t, env)

	// Build a 56-byte payload with wrong StructureSize
	w := NewByteWriter(64)
	w.WriteUint16(99) // Wrong StructureSize (should be 57)
	w.WriteUint16(0)  // Reserved
	w.WriteUint32(FSCTL_VALIDATE_NEGOTIATE_INFO) // CtlCode
	w.WriteUint64(0) // FileId.Persistent
	w.WriteUint64(0) // FileId.Volatile
	w.WriteUint32(0) // InputOffset
	w.WriteUint32(0) // InputCount
	w.WriteUint32(0) // MaxInputResponse
	w.WriteUint32(0) // OutputOffset
	w.WriteUint32(0) // OutputCount
	w.WriteUint32(0) // MaxOutputResponse
	w.WriteUint32(0) // Flags
	w.WriteUint32(0) // Reserved2

	msg := &SMB2Message{
		Header: &SMB2Header{
			Command:       SMB2_IOCTL,
			SessionID:     sessionID,
			CreditRequest: 1,
		},
		Payload: w.Bytes(),
	}
	copy(msg.Header.ProtocolID[:], SMB2ProtocolID)

	_, status := env.handler.handleIOCTL(env.state, msg)
	if status != STATUS_INVALID_PARAMETER {
		t.Errorf("expected STATUS_INVALID_PARAMETER, got %s", status)
	}
}
