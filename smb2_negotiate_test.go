package smbfs

import (
	"testing"
)

// TestNegotiate_ValidRequest sends a NEGOTIATE with multiple dialects and
// verifies STATUS_SUCCESS and the selected dialect is stored on the connState.
func TestNegotiate_ValidRequest(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	dialects := []SMBDialect{SMB2_0_2, SMB2_1, SMB3_0, SMB3_1_1}
	msg := buildNegotiateMsg(dialects)

	resp := negotiateWithMsg(t, env, msg)
	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	// The server should have selected the highest common dialect (SMB 3.1.1)
	selected := parseNegotiateResponse(t, resp.Payload)
	if selected != SMB3_1_1 {
		t.Errorf("selected dialect = %s, want SMB 3.1.1", selected)
	}

	// connState must also reflect the negotiated dialect
	if env.state.dialect != SMB3_1_1 {
		t.Errorf("state.dialect = %s, want SMB 3.1.1", env.state.dialect)
	}
}

// TestNegotiate_SingleDialect verifies that only offering SMB 2.0.2 results
// in that dialect being selected.
func TestNegotiate_SingleDialect(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := buildNegotiateMsg([]SMBDialect{SMB2_0_2})
	resp := negotiateWithMsg(t, env, msg)

	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	selected := parseNegotiateResponse(t, resp.Payload)
	if selected != SMB2_0_2 {
		t.Errorf("selected dialect = %s, want SMB 2.0.2", selected)
	}
	if env.state.dialect != SMB2_0_2 {
		t.Errorf("state.dialect = %s, want SMB 2.0.2", env.state.dialect)
	}
}

// TestNegotiate_SMB311WithContexts verifies that negotiating SMB 3.1.1
// initializes the preauth state (dialect stored on connState).
func TestNegotiate_SMB311WithContexts(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := buildNegotiateMsg([]SMBDialect{SMB3_1_1})
	resp := negotiateWithMsg(t, env, msg)

	if resp.Header.Status != STATUS_SUCCESS {
		t.Fatalf("status = %s, want STATUS_SUCCESS", resp.Header.Status)
	}

	if env.state.dialect != SMB3_1_1 {
		t.Fatalf("state.dialect = %s, want SMB 3.1.1", env.state.dialect)
	}

	// The response payload should contain negotiate contexts (StructureSize 65
	// with NegotiateContextCount > 0 encoded at offset 6).
	if len(resp.Payload) < 8 {
		t.Fatalf("response payload too short: %d bytes", len(resp.Payload))
	}
	r := NewByteReader(resp.Payload)
	_ = r.ReadUint16() // StructureSize
	_ = r.ReadUint16() // SecurityMode
	_ = r.ReadUint16() // DialectRevision
	negCtxCount := r.ReadUint16()
	if negCtxCount == 0 {
		t.Error("NegotiateContextCount = 0, expected > 0 for SMB 3.1.1")
	}
}

// TestNegotiate_TooShortPayload verifies that an empty/short payload results
// in an error status.
func TestNegotiate_TooShortPayload(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_NEGOTIATE, 0, 0),
		Payload: []byte{0x01, 0x02}, // way too short
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage returned error: %v", err)
	}
	if resp.Header.Status == STATUS_SUCCESS {
		t.Error("expected error status for short payload, got STATUS_SUCCESS")
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// TestNegotiate_InvalidStructSize verifies that a wrong StructureSize field
// results in an error.
func TestNegotiate_InvalidStructSize(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	// Build a valid-length payload but with bad StructureSize
	w := NewByteWriter(64)
	w.WriteUint16(99) // Wrong StructureSize (should be 36)
	w.WriteUint16(1)  // DialectCount
	w.WriteUint16(SMB2_NEGOTIATE_SIGNING_ENABLED)
	w.WriteUint16(0)         // Reserved
	w.WriteUint32(0)         // Capabilities
	w.WriteGUID([16]byte{})  // ClientGUID
	w.WriteUint32(0)         // NegotiateContextOffset
	w.WriteUint16(0)         // NegotiateContextCount
	w.WriteUint16(0)         // Reserved2
	w.WriteUint16(uint16(SMB2_1)) // One dialect

	msg := &SMB2Message{
		Header:  makeHeader(SMB2_NEGOTIATE, 0, 0),
		Payload: w.Bytes(),
	}

	resp, err := env.handler.HandleMessage(env.state, msg)
	if err != nil {
		t.Fatalf("HandleMessage returned error: %v", err)
	}
	if resp.Header.Status != STATUS_INVALID_PARAMETER {
		t.Errorf("status = %s, want STATUS_INVALID_PARAMETER", resp.Header.Status)
	}
}

// TestNegotiate_NoCommonDialect verifies that when the client offers only
// unsupported dialects, the server returns an appropriate error.
func TestNegotiate_NoCommonDialect(t *testing.T) {
	env := setupHandlerEnv(t, &ServerOptions{
		Logger:     &NullLogger{},
		AllowGuest: true,
	})

	msg := buildNegotiateMsg([]SMBDialect{SMBDialect(0x9999)})
	resp := negotiateWithMsg(t, env, msg)

	if resp.Header.Status == STATUS_SUCCESS {
		t.Error("expected error status for unsupported dialect, got STATUS_SUCCESS")
	}
	if resp.Header.Status != STATUS_NOT_SUPPORTED {
		t.Errorf("status = %s, want STATUS_NOT_SUPPORTED", resp.Header.Status)
	}
}

// TestSelectDialect is a table-driven test for the dialect selection logic.
func TestSelectDialect(t *testing.T) {
	tests := []struct {
		name           string
		clientDialects []SMBDialect
		minDialect     SMBDialect
		maxDialect     SMBDialect
		want           SMBDialect
	}{
		{
			name:           "highest common from full set",
			clientDialects: []SMBDialect{SMB2_0_2, SMB2_1, SMB3_0, SMB3_0_2, SMB3_1_1},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_1_1,
			want:           SMB3_1_1,
		},
		{
			name:           "client only supports 2.0.2",
			clientDialects: []SMBDialect{SMB2_0_2},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_1_1,
			want:           SMB2_0_2,
		},
		{
			name:           "server max is 3.0",
			clientDialects: []SMBDialect{SMB2_0_2, SMB2_1, SMB3_0, SMB3_1_1},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_0,
			want:           SMB3_0,
		},
		{
			name:           "server min is 3.0",
			clientDialects: []SMBDialect{SMB2_0_2, SMB2_1, SMB3_0, SMB3_1_1},
			minDialect:     SMB3_0,
			maxDialect:     SMB3_1_1,
			want:           SMB3_1_1,
		},
		{
			name:           "no common dialect",
			clientDialects: []SMBDialect{SMBDialect(0x9999)},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_1_1,
			want:           0,
		},
		{
			name:           "client below server minimum",
			clientDialects: []SMBDialect{SMB2_0_2, SMB2_1},
			minDialect:     SMB3_0,
			maxDialect:     SMB3_1_1,
			want:           0,
		},
		{
			name:           "client above server maximum",
			clientDialects: []SMBDialect{SMB3_1_1},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_0,
			want:           0,
		},
		{
			name:           "unordered client dialects",
			clientDialects: []SMBDialect{SMB3_1_1, SMB2_0_2, SMB3_0},
			minDialect:     SMB2_0_2,
			maxDialect:     SMB3_1_1,
			want:           SMB3_1_1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupHandlerEnv(t, &ServerOptions{
				Logger:     &NullLogger{},
				MinDialect: tt.minDialect,
				MaxDialect: tt.maxDialect,
			})

			got := env.handler.selectDialect(tt.clientDialects)
			if got != tt.want {
				t.Errorf("selectDialect(%v) = %s, want %s", tt.clientDialects, got, tt.want)
			}
		})
	}
}

// TestFormatDialects verifies the formatDialects logging helper.
func TestFormatDialects(t *testing.T) {
	tests := []struct {
		name     string
		dialects []SMBDialect
		want     string
	}{
		{
			name:     "empty",
			dialects: nil,
			want:     "[]",
		},
		{
			name:     "single",
			dialects: []SMBDialect{SMB2_1},
			want:     "[SMB 2.1]",
		},
		{
			name:     "multiple",
			dialects: []SMBDialect{SMB2_0_2, SMB3_1_1},
			want:     "[SMB 2.0.2, SMB 3.1.1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDialects(tt.dialects)
			if got != tt.want {
				t.Errorf("formatDialects() = %q, want %q", got, tt.want)
			}
		})
	}
}
