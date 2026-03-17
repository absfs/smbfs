package smbfs

import (
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// testKeytab creates a keytab with a single entry for testing.
// Uses gokrb5's AddEntry which derives a key from the password.
func testKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	// Encryption type 17 = AES128-CTS-HMAC-SHA1-96
	err := kt.AddEntry("cifs/server.example.com", "EXAMPLE.COM", "testpassword", time.Now(), 1, 17)
	if err != nil {
		t.Fatalf("failed to create test keytab entry: %v", err)
	}
	return kt
}

// ---------------------------------------------------------------------------
// NewKerberosAuthenticator tests
// ---------------------------------------------------------------------------

func TestNewKerberosAuthenticator_Valid(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}
	if auth.spn != "cifs/server.example.com" {
		t.Errorf("expected spn %q, got %q", "cifs/server.example.com", auth.spn)
	}
	if auth.keytab == nil {
		t.Error("expected non-nil keytab")
	}
	if auth.settings == nil {
		t.Error("expected non-nil settings")
	}
	if auth.logger == nil {
		t.Error("expected non-nil logger (should default to NullLogger)")
	}
}

func TestNewKerberosAuthenticator_NilKeytab(t *testing.T) {
	auth, err := NewKerberosAuthenticator(nil, "cifs/server.example.com", nil)
	if err == nil {
		t.Fatal("expected error for nil keytab")
	}
	if auth != nil {
		t.Fatal("expected nil authenticator on error")
	}
}

func TestNewKerberosAuthenticator_EmptySPN(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "", nil)
	if err == nil {
		t.Fatal("expected error for empty SPN")
	}
	if auth != nil {
		t.Fatal("expected nil authenticator on error")
	}
}

func TestNewKerberosAuthenticator_WithLogger(t *testing.T) {
	kt := testKeytab(t)
	logger := &NullLogger{}
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if auth.logger != logger {
		t.Error("expected provided logger to be used")
	}
}

// ---------------------------------------------------------------------------
// Authenticate error paths
// ---------------------------------------------------------------------------

func TestKerberosAuth_EmptyBlob(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// nil blob
	result, err := auth.Authenticate(nil)
	if err == nil {
		t.Error("expected error for nil blob")
	}
	if result != nil {
		t.Error("expected nil result for nil blob")
	}

	// empty blob
	result, err = auth.Authenticate([]byte{})
	if err == nil {
		t.Error("expected error for empty blob")
	}
	if result != nil {
		t.Error("expected nil result for empty blob")
	}
}

func TestKerberosAuth_NonSPNEGOBlob(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Random bytes that aren't SPNEGO, NTLM, or Kerberos
	randomBlob := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}
	result, err := auth.Authenticate(randomBlob)
	if err == nil {
		t.Error("expected error for random blob")
	}
	if result != nil && result.Success {
		t.Error("expected authentication to fail for random blob")
	}
}

func TestKerberosAuth_NTLMBlob(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Raw NTLM Type 1 message
	ntlmType1 := []byte("NTLMSSP\x00")                        // Signature
	ntlmType1 = append(ntlmType1, 0x01, 0x00, 0x00, 0x00)     // Type 1
	ntlmType1 = append(ntlmType1, 0x00, 0x00, 0x00, 0x00)     // Flags
	ntlmType1 = append(ntlmType1, make([]byte, 16)...)         // Padding

	result, err := auth.Authenticate(ntlmType1)
	if err == nil {
		t.Error("expected error for NTLM blob")
	}
	if result != nil && result.Success {
		t.Error("expected authentication to fail for NTLM blob")
	}

	// NTLM inside SPNEGO wrapper
	spnegoNTLM := buildTestSPNEGONTLM(ntlmType1)
	result, err = auth.Authenticate(spnegoNTLM)
	if err == nil {
		t.Error("expected error for SPNEGO-wrapped NTLM blob")
	}
	if result != nil && result.Success {
		t.Error("expected authentication to fail for SPNEGO-wrapped NTLM blob")
	}
}

func TestKerberosAuth_ShortBlob(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	result, err := auth.Authenticate([]byte{0x60})
	if err == nil {
		t.Error("expected error for 1-byte blob")
	}
	if result != nil && result.Success {
		t.Error("expected authentication to fail for short blob")
	}
}

func TestKerberosAuth_InvalidAPReq(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Blob that starts with AP-REQ tag (0x6e) but has garbage content
	fakeAPReq := []byte{0x6e, 0x10}
	fakeAPReq = append(fakeAPReq, make([]byte, 16)...)

	result, err := auth.Authenticate(fakeAPReq)
	if err == nil {
		t.Error("expected error for garbage AP-REQ")
	}
	if result != nil && result.Success {
		t.Error("expected authentication to fail for invalid AP-REQ")
	}
}

// ---------------------------------------------------------------------------
// isKerberosBlob tests
// ---------------------------------------------------------------------------

func TestIsKerberosBlob(t *testing.T) {
	tests := []struct {
		name     string
		blob     []byte
		expected bool
	}{
		{
			name:     "nil blob",
			blob:     nil,
			expected: false,
		},
		{
			name:     "empty blob",
			blob:     []byte{},
			expected: false,
		},
		{
			name:     "short blob",
			blob:     []byte{0x01, 0x02},
			expected: false,
		},
		{
			name: "blob with standard Kerberos OID",
			blob: append([]byte{0x60, 0x30, 0x06, 0x06}, append(
				oidKerberosRaw,
				make([]byte, 30)...,
			)...),
			expected: true,
		},
		{
			name: "blob with MS Kerberos OID",
			blob: append([]byte{0x60, 0x30, 0x06, 0x06}, append(
				oidMSKerberosRaw,
				make([]byte, 30)...,
			)...),
			expected: true,
		},
		{
			name: "blob with Kerberos OID and NTLM signature",
			blob: func() []byte {
				b := append([]byte{0x60, 0x30, 0x06, 0x06}, oidKerberosRaw...)
				b = append(b, []byte("NTLMSSP\x00")...)
				b = append(b, make([]byte, 30)...)
				return b
			}(),
			expected: false, // NTLM signature present, not treated as Kerberos
		},
		{
			name: "NTLM blob without Kerberos OID",
			blob: func() []byte {
				b := []byte{0x60, 0x30}
				b = append(b, []byte("NTLMSSP\x00")...)
				b = append(b, make([]byte, 30)...)
				return b
			}(),
			expected: false,
		},
		{
			name:     "raw AP-REQ (tag 0x6e)",
			blob:     append([]byte{0x6e, 0x20}, make([]byte, 30)...),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isKerberosBlob(tt.blob)
			if got != tt.expected {
				t.Errorf("isKerberosBlob() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsNTLMSignature tests
// ---------------------------------------------------------------------------

func TestContainsNTLMSignature(t *testing.T) {
	tests := []struct {
		name     string
		blob     []byte
		expected bool
	}{
		{"empty", nil, false},
		{"no signature", []byte{0x01, 0x02, 0x03}, false},
		{"raw NTLMSSP", []byte("NTLMSSP\x00"), true},
		{"embedded NTLMSSP", append([]byte{0x60, 0x30}, []byte("NTLMSSP\x00")...), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNTLMSignature(tt.blob)
			if got != tt.expected {
				t.Errorf("containsNTLMSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isAPReq tests
// ---------------------------------------------------------------------------

func TestIsAPReq(t *testing.T) {
	tests := []struct {
		name     string
		blob     []byte
		expected bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"single byte", []byte{0x6e}, false},
		{"AP-REQ tag", []byte{0x6e, 0x10}, true},
		{"not AP-REQ", []byte{0x60, 0x10}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAPReq(tt.blob)
			if got != tt.expected {
				t.Errorf("isAPReq() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// readASN1Length tests
// ---------------------------------------------------------------------------

func TestReadASN1Length(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantLength   int
		wantConsumed int
	}{
		{"empty", []byte{}, 0, 0},
		{"short form 0", []byte{0x00}, 0, 1},
		{"short form 10", []byte{0x0a}, 10, 1},
		{"short form 127", []byte{0x7f}, 127, 1},
		{"long form 1 byte", []byte{0x81, 0x80}, 128, 2},
		{"long form 1 byte 255", []byte{0x81, 0xff}, 255, 2},
		{"long form 2 bytes", []byte{0x82, 0x01, 0x00}, 256, 3},
		{"long form 2 bytes big", []byte{0x82, 0x04, 0x00}, 1024, 3},
		{"truncated long form", []byte{0x82, 0x01}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, gotConsumed := readASN1Length(tt.data)
			if gotLen != tt.wantLength {
				t.Errorf("length = %d, want %d", gotLen, tt.wantLength)
			}
			if gotConsumed != tt.wantConsumed {
				t.Errorf("consumed = %d, want %d", gotConsumed, tt.wantConsumed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractMechTokenFromSPNEGO tests
// ---------------------------------------------------------------------------

func TestExtractMechTokenFromSPNEGO(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Build a minimal SPNEGO NegTokenInit with Kerberos OID and a fake mechToken.
	fakeAPReq := []byte{0x6e, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x42}
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// Build ASN.1 structure from innermost to outermost
	mechTokenOctet := testASN1Wrap(0x04, fakeAPReq)
	mechTokenCtx := testASN1Wrap(0xa2, mechTokenOctet)
	krbOIDFull := append([]byte{0x06, byte(len(oidKerberosRaw))}, oidKerberosRaw...)
	mechTypesSeq := testASN1Wrap(0x30, krbOIDFull)
	mechTypesCtx := testASN1Wrap(0xa0, mechTypesSeq)
	negTokenInit := testASN1Wrap(0x30, append(mechTypesCtx, mechTokenCtx...))
	negTokenInitCtx := testASN1Wrap(0xa0, negTokenInit)
	spnegoOIDTagged := append([]byte{0x06, byte(len(spnegoOID))}, spnegoOID...)
	gssPayload := append(spnegoOIDTagged, negTokenInitCtx...)
	gssWrapper := testASN1Wrap(0x60, gssPayload)

	result := auth.extractMechTokenFromSPNEGO(gssWrapper)
	if result == nil {
		t.Fatal("expected non-nil mechToken extraction")
	}
	if len(result) != len(fakeAPReq) {
		t.Fatalf("extracted mechToken length = %d, want %d", len(result), len(fakeAPReq))
	}
	for i, b := range result {
		if b != fakeAPReq[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, b, fakeAPReq[i])
		}
	}
}

func TestExtractMechTokenFromSPNEGO_NoKerberosOID(t *testing.T) {
	kt := testKeytab(t)
	auth, err := NewKerberosAuthenticator(kt, "cifs/server.example.com", nil)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Blob without Kerberos OID should return nil
	blob := []byte{0x60, 0x10, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x06, 0x30, 0x04, 0xa0, 0x02, 0x30, 0x00}
	result := auth.extractMechTokenFromSPNEGO(blob)
	if result != nil {
		t.Error("expected nil for blob without Kerberos OID")
	}
}

// ---------------------------------------------------------------------------
// NewKerberosAuthenticatorFromFile tests
// ---------------------------------------------------------------------------

func TestNewKerberosAuthenticatorFromFile_InvalidPath(t *testing.T) {
	auth, err := NewKerberosAuthenticatorFromFile("/nonexistent/path/test.keytab", "cifs/server.example.com", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent keytab file")
	}
	if auth != nil {
		t.Fatal("expected nil authenticator on error")
	}
}

func TestNewKerberosAuthenticatorFromFile_EmptyPath(t *testing.T) {
	auth, err := NewKerberosAuthenticatorFromFile("", "cifs/server.example.com", nil)
	if err == nil {
		t.Fatal("expected error for empty keytab path")
	}
	if auth != nil {
		t.Fatal("expected nil authenticator on error")
	}
}

// ---------------------------------------------------------------------------
// ServerOptions Kerberos fields
// ---------------------------------------------------------------------------

func TestServerOptions_KerberosFields(t *testing.T) {
	opts := ServerOptions{
		KeytabPath:       "/etc/krb5.keytab",
		ServicePrincipal: "cifs/server.example.com@EXAMPLE.COM",
	}
	if opts.KeytabPath != "/etc/krb5.keytab" {
		t.Errorf("KeytabPath = %q, want %q", opts.KeytabPath, "/etc/krb5.keytab")
	}
	if opts.ServicePrincipal != "cifs/server.example.com@EXAMPLE.COM" {
		t.Errorf("ServicePrincipal = %q, want %q", opts.ServicePrincipal, "cifs/server.example.com@EXAMPLE.COM")
	}
}

// ---------------------------------------------------------------------------
// NewServer with invalid keytab
// ---------------------------------------------------------------------------

func TestNewServer_WithInvalidKeytab(t *testing.T) {
	opts := ServerOptions{
		KeytabPath:       "/nonexistent/path/krb5.keytab",
		ServicePrincipal: "cifs/server.example.com@EXAMPLE.COM",
		Logger:           &NullLogger{},
	}
	_, err := NewServer(opts)
	if err == nil {
		t.Fatal("expected error for non-existent keytab path, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// ---------------------------------------------------------------------------
// Session setup authenticator selection (Kerberos vs NTLM)
// ---------------------------------------------------------------------------

func TestSessionSetup_SelectsNTLMWhenNoKerberos(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest: true,
		Logger:     &NullLogger{},
	})
	negotiateDefault(t, env)

	if env.server.kerberosAuth != nil {
		t.Fatal("kerberosAuth should be nil when no keytab is configured")
	}

	sessionID := authenticateGuest(t, env)
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found")
	}
	if !session.IsGuest {
		t.Error("expected guest session")
	}
}

func TestSessionSetup_NTLMStillWorksWithKerberosFields(t *testing.T) {
	withFixedTime(t)
	env := setupHandlerEnv(t, &ServerOptions{
		AllowGuest:       true,
		Logger:           &NullLogger{},
		KeytabPath:       "",
		ServicePrincipal: "",
	})
	negotiateDefault(t, env)

	sessionID := authenticateGuest(t, env)
	session := env.server.sessions.GetSession(sessionID)
	if session == nil {
		t.Fatal("session not found")
	}
	if !session.IsGuest {
		t.Error("expected guest session")
	}
}

// TODO: Integration tests with a real KDC would go here.
// Full end-to-end Kerberos authentication testing requires a running KDC
// to issue valid service tickets. The unit tests above cover error paths,
// input validation, and SPNEGO parsing. A future integration test suite
// could use a containerized MIT KDC for full AP-REQ verification testing.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildTestSPNEGONTLM wraps an NTLM token in a minimal SPNEGO NegTokenInit.
func buildTestSPNEGONTLM(ntlmToken []byte) []byte {
	ntlmOIDRaw := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	spnegoOID := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	mechTokenOctet := testASN1Wrap(0x04, ntlmToken)
	mechTokenCtx := testASN1Wrap(0xa2, mechTokenOctet)
	ntlmOIDFull := append([]byte{0x06, byte(len(ntlmOIDRaw))}, ntlmOIDRaw...)
	mechTypesSeq := testASN1Wrap(0x30, ntlmOIDFull)
	mechTypesCtx := testASN1Wrap(0xa0, mechTypesSeq)
	negTokenInit := testASN1Wrap(0x30, append(mechTypesCtx, mechTokenCtx...))
	negTokenInitCtx := testASN1Wrap(0xa0, negTokenInit)
	spnegoOIDTagged := append([]byte{0x06, byte(len(spnegoOID))}, spnegoOID...)
	gssPayload := append(spnegoOIDTagged, negTokenInitCtx...)
	return testASN1Wrap(0x60, gssPayload)
}

// testASN1Wrap wraps data in an ASN.1 TLV with the given tag.
func testASN1Wrap(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		result := make([]byte, 2+length)
		result[0] = tag
		result[1] = byte(length)
		copy(result[2:], data)
		return result
	}
	if length < 256 {
		result := make([]byte, 3+length)
		result[0] = tag
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
		return result
	}
	result := make([]byte, 4+length)
	result[0] = tag
	result[1] = 0x82
	result[2] = byte(length >> 8)
	result[3] = byte(length)
	copy(result[4:], data)
	return result
}
