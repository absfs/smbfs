package smbfs

import (
	"bytes"
	"testing"
)

// --- Helper: build a SPNEGO NegTokenInit blob manually ---

// buildTestNegTokenInit constructs a SPNEGO NegTokenInit with the given
// mechanism OIDs and optional mechToken. OIDs should include their 0x06 tag
// and length prefix.
func buildTestNegTokenInit(mechOIDs [][]byte, mechToken []byte) []byte {
	// Build the inner SEQUENCE of OIDs.
	var oidSeqContent []byte
	for _, oid := range mechOIDs {
		oidSeqContent = append(oidSeqContent, oid...)
	}
	oidSeq := spnegoWrap(0x30, oidSeqContent)

	// Context [0] wraps the mechTypes SEQUENCE.
	mechTypesField := spnegoWrap(0xa0, oidSeq)

	// Build NegTokenInit SEQUENCE content.
	var seqContent []byte
	seqContent = append(seqContent, mechTypesField...)

	// Context [2] wraps the mechToken in an OCTET STRING.
	if mechToken != nil {
		tokenField := spnegoWrap(0xa2, spnegoWrap(0x04, mechToken))
		seqContent = append(seqContent, tokenField...)
	}

	innerSeq := spnegoWrap(0x30, seqContent)

	// Context [0] (NegotiationToken CHOICE).
	choiceWrapped := spnegoWrap(0xa0, innerSeq)

	// APPLICATION [0] wraps SPNEGO OID + choice.
	var appContent []byte
	appContent = append(appContent, oidSPNEGO...)
	appContent = append(appContent, choiceWrapped...)
	return spnegoWrap(0x60, appContent)
}

// --- ParseSPNEGOInit tests ---

func TestParseSPNEGOInit_KerberosPreferred(t *testing.T) {
	token := []byte("fake-kerberos-ap-req")
	blob := buildTestNegTokenInit([][]byte{oidKerberos}, token)

	mech, extracted, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechKerberos {
		t.Errorf("got mech %d, want MechKerberos (%d)", mech, MechKerberos)
	}
	if !bytes.Equal(extracted, token) {
		t.Errorf("got token %x, want %x", extracted, token)
	}
}

func TestParseSPNEGOInit_NTLMOnly(t *testing.T) {
	token := []byte("NTLMSSP\x00fake-negotiate")
	blob := buildTestNegTokenInit([][]byte{oidNTLM}, token)

	mech, extracted, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechNTLM {
		t.Errorf("got mech %d, want MechNTLM (%d)", mech, MechNTLM)
	}
	if !bytes.Equal(extracted, token) {
		t.Errorf("got token %x, want %x", extracted, token)
	}
}

func TestParseSPNEGOInit_BothMechs(t *testing.T) {
	token := []byte("some-auth-token")
	blob := buildTestNegTokenInit([][]byte{oidKerberos, oidNTLM}, token)

	mech, extracted, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechKerberos {
		t.Errorf("got mech %d, want MechKerberos (%d) (first/preferred)", mech, MechKerberos)
	}
	if !bytes.Equal(extracted, token) {
		t.Errorf("got token %x, want %x", extracted, token)
	}
}

func TestParseSPNEGOInit_MSKerberos(t *testing.T) {
	token := []byte("ms-krb-ap-req")
	blob := buildTestNegTokenInit([][]byte{oidMSKerberos}, token)

	mech, extracted, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechMSKerberos {
		t.Errorf("got mech %d, want MechMSKerberos (%d)", mech, MechMSKerberos)
	}
	if !bytes.Equal(extracted, token) {
		t.Errorf("got token %x, want %x", extracted, token)
	}
}

func TestParseSPNEGOInit_InvalidBlob(t *testing.T) {
	blob := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	mech, _, err := ParseSPNEGOInit(blob)
	if err == nil {
		t.Fatal("expected error for invalid blob, got nil")
	}
	if mech != MechUnknown {
		t.Errorf("got mech %d, want MechUnknown", mech)
	}
}

func TestParseSPNEGOInit_EmptyBlob(t *testing.T) {
	_, _, err := ParseSPNEGOInit(nil)
	if err == nil {
		t.Fatal("expected error for nil blob")
	}

	_, _, err = ParseSPNEGOInit([]byte{})
	if err == nil {
		t.Fatal("expected error for empty blob")
	}
}

func TestParseSPNEGOInit_NoMechToken(t *testing.T) {
	// Build a valid NegTokenInit with mechTypes but no mechToken (context [2]).
	blob := buildTestNegTokenInit([][]byte{oidNTLM}, nil)

	mech, token, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechNTLM {
		t.Errorf("got mech %d, want MechNTLM", mech)
	}
	if token != nil {
		t.Errorf("expected nil mechToken, got %x", token)
	}
}

func TestParseSPNEGOInit_RealNTLMBlob(t *testing.T) {
	// Use the existing wrapInSPNEGO from NTLMAuthenticator to create a real
	// NTLM SPNEGO response blob, then verify we can round-trip parse it.
	// Note: wrapInSPNEGO produces a NegTokenResp (context [1]), not a
	// NegTokenInit (APPLICATION [0]). So instead we build a NegTokenInit
	// using the same OID and an NTLM negotiate message.

	ntlmNegotiate := []byte("NTLMSSP\x00")
	ntlmNegotiate = append(ntlmNegotiate, 0x01, 0x00, 0x00, 0x00) // type 1
	ntlmNegotiate = append(ntlmNegotiate, 0x00, 0x00, 0x00, 0x00) // flags
	ntlmNegotiate = append(ntlmNegotiate, make([]byte, 16)...)     // domain+workstation

	blob := buildTestNegTokenInit([][]byte{oidNTLM}, ntlmNegotiate)

	mech, extracted, err := ParseSPNEGOInit(blob)
	if err != nil {
		t.Fatalf("ParseSPNEGOInit failed: %v", err)
	}
	if mech != MechNTLM {
		t.Errorf("got mech %d, want MechNTLM", mech)
	}
	if !bytes.Equal(extracted, ntlmNegotiate) {
		t.Errorf("round-trip failed: got %x, want %x", extracted, ntlmNegotiate)
	}

	// Also verify the extracted blob starts with NTLMSSP signature.
	if !bytes.HasPrefix(extracted, []byte("NTLMSSP\x00")) {
		t.Error("extracted token does not start with NTLMSSP signature")
	}
}

// --- BuildSPNEGOResponse tests ---

func TestBuildSPNEGOResponse_Accept(t *testing.T) {
	resp := BuildSPNEGOResponse(NegStateAcceptCompleted, nil, nil)

	// Should start with context [1] (0xa1).
	if len(resp) == 0 || resp[0] != 0xa1 {
		t.Fatalf("expected outer tag 0xa1, got 0x%02x", resp[0])
	}

	// Parse it back to verify structure: should contain negState = 0x00.
	// The negState is encoded as ENUMERATED inside context [0]:
	// a0 03 0a 01 00
	if !bytes.Contains(resp, []byte{0x0a, 0x01, 0x00}) {
		t.Error("accept-completed response missing ENUMERATED value 0x00")
	}
}

func TestBuildSPNEGOResponse_Challenge(t *testing.T) {
	challengeToken := []byte("ntlm-challenge-message-here")
	resp := BuildSPNEGOResponse(NegStateAcceptIncomplete, oidNTLMRaw, challengeToken)

	if len(resp) == 0 || resp[0] != 0xa1 {
		t.Fatalf("expected outer tag 0xa1, got 0x%02x", resp[0])
	}

	// Should contain negState accept-incomplete (0x01).
	if !bytes.Contains(resp, []byte{0x0a, 0x01, 0x01}) {
		t.Error("challenge response missing ENUMERATED value 0x01")
	}

	// Should contain the NTLM OID bytes.
	if !bytes.Contains(resp, oidNTLMRaw) {
		t.Error("challenge response missing NTLM OID")
	}

	// Should contain the challenge token.
	if !bytes.Contains(resp, challengeToken) {
		t.Error("challenge response missing challenge token")
	}

	// Round-trip: parse it back.
	token, err := ParseSPNEGOResponse(resp)
	if err != nil {
		t.Fatalf("ParseSPNEGOResponse failed: %v", err)
	}
	if !bytes.Equal(token, challengeToken) {
		t.Errorf("round-trip: got %x, want %x", token, challengeToken)
	}
}

func TestBuildSPNEGOResponse_Reject(t *testing.T) {
	resp := BuildSPNEGOResponse(NegStateReject, nil, nil)

	if len(resp) == 0 || resp[0] != 0xa1 {
		t.Fatalf("expected outer tag 0xa1, got 0x%02x", resp[0])
	}

	// Should contain negState reject (0x02).
	if !bytes.Contains(resp, []byte{0x0a, 0x01, 0x02}) {
		t.Error("reject response missing ENUMERATED value 0x02")
	}
}

// --- ParseSPNEGOResponse tests ---

func TestParseSPNEGOResponse_RoundTrip(t *testing.T) {
	token := []byte("response-token-data")
	resp := BuildSPNEGOResponse(NegStateAcceptIncomplete, oidNTLMRaw, token)

	extracted, err := ParseSPNEGOResponse(resp)
	if err != nil {
		t.Fatalf("ParseSPNEGOResponse failed: %v", err)
	}
	if !bytes.Equal(extracted, token) {
		t.Errorf("got %x, want %x", extracted, token)
	}
}

func TestParseSPNEGOResponse_NoResponseToken(t *testing.T) {
	// Build a NegTokenResp with only negState, no responseToken.
	resp := BuildSPNEGOResponse(NegStateAcceptCompleted, nil, nil)

	_, err := ParseSPNEGOResponse(resp)
	if err == nil {
		t.Fatal("expected error for NegTokenResp without responseToken")
	}
}

func TestParseSPNEGOResponse_InvalidBlob(t *testing.T) {
	_, err := ParseSPNEGOResponse([]byte{0xde, 0xad})
	if err == nil {
		t.Fatal("expected error for invalid blob")
	}
}

func TestParseSPNEGOResponse_EmptyBlob(t *testing.T) {
	_, err := ParseSPNEGOResponse(nil)
	if err == nil {
		t.Fatal("expected error for nil blob")
	}

	_, err = ParseSPNEGOResponse([]byte{})
	if err == nil {
		t.Fatal("expected error for empty blob")
	}
}

// --- asn1ReadTagAndLength tests ---

func TestASN1ReadTagAndLength_ShortForm(t *testing.T) {
	// Tag 0x30, length 5.
	data := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	tag, length, hdrLen, err := asn1ReadTagAndLength(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag != 0x30 {
		t.Errorf("tag = 0x%02x, want 0x30", tag)
	}
	if length != 5 {
		t.Errorf("length = %d, want 5", length)
	}
	if hdrLen != 2 {
		t.Errorf("hdrLen = %d, want 2", hdrLen)
	}
}

func TestASN1ReadTagAndLength_OneByteLongForm(t *testing.T) {
	// Tag 0x04, length 200 (0x81, 0xc8).
	data := []byte{0x04, 0x81, 0xc8}
	tag, length, hdrLen, err := asn1ReadTagAndLength(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag != 0x04 {
		t.Errorf("tag = 0x%02x, want 0x04", tag)
	}
	if length != 200 {
		t.Errorf("length = %d, want 200", length)
	}
	if hdrLen != 3 {
		t.Errorf("hdrLen = %d, want 3", hdrLen)
	}
}

func TestASN1ReadTagAndLength_TwoByteLongForm(t *testing.T) {
	// Tag 0xa0, length 300 (0x82, 0x01, 0x2c).
	data := []byte{0xa0, 0x82, 0x01, 0x2c}
	tag, length, hdrLen, err := asn1ReadTagAndLength(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag != 0xa0 {
		t.Errorf("tag = 0x%02x, want 0xa0", tag)
	}
	if length != 300 {
		t.Errorf("length = %d, want 300", length)
	}
	if hdrLen != 4 {
		t.Errorf("hdrLen = %d, want 4", hdrLen)
	}
}

func TestASN1ReadTagAndLength_TooShort(t *testing.T) {
	// Single byte — not enough for tag+length.
	_, _, _, err := asn1ReadTagAndLength([]byte{0x30})
	if err == nil {
		t.Fatal("expected error for single-byte input")
	}

	// Empty.
	_, _, _, err = asn1ReadTagAndLength([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}

	// 0x81 form but missing the length byte.
	_, _, _, err = asn1ReadTagAndLength([]byte{0x30, 0x81})
	if err == nil {
		t.Fatal("expected error for truncated 0x81 length")
	}

	// 0x82 form but missing second length byte.
	_, _, _, err = asn1ReadTagAndLength([]byte{0x30, 0x82, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated 0x82 length")
	}
}

// --- Compatibility: verify wrapInSPNEGO output can be parsed ---

func TestBuildSPNEGOResponse_MatchesWrapInSPNEGO(t *testing.T) {
	// Build an NTLM challenge message and wrap it with both the old
	// NTLMAuthenticator.wrapInSPNEGO and the new BuildSPNEGOResponse.
	// They should produce identical output.
	ntlmChallenge := make([]byte, 56)
	copy(ntlmChallenge[0:8], []byte("NTLMSSP\x00"))
	ntlmChallenge[8] = 0x02 // Type 2

	auth := &NTLMAuthenticator{}
	oldResult := auth.wrapInSPNEGO(ntlmChallenge)

	newResult := BuildSPNEGOResponse(NegStateAcceptIncomplete, oidNTLMRaw, ntlmChallenge)

	if !bytes.Equal(oldResult, newResult) {
		t.Errorf("output mismatch\nold: %x\nnew: %x", oldResult, newResult)
	}
}

// --- MechOIDForType ---

func TestMechOIDForType(t *testing.T) {
	tests := []struct {
		mech MechType
		want []byte
	}{
		{MechKerberos, oidKerberos[2:]},
		{MechMSKerberos, oidMSKerberos[2:]},
		{MechNTLM, oidNTLMRaw},
		{MechUnknown, nil},
	}
	for _, tt := range tests {
		got := MechOIDForType(tt.mech)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("MechOIDForType(%d) = %x, want %x", tt.mech, got, tt.want)
		}
	}
}
