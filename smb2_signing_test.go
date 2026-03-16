package smbfs

import (
	"bytes"
	"crypto/aes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// makeMinimalSMB2Message creates a valid SMB2-sized message (>= 64 bytes)
// with the SMB2 protocol signature. Additional payload bytes can be appended.
func makeMinimalSMB2Message(payloadSize int) []byte {
	hdr := &SMB2Header{
		StructureSize: 64,
		CreditCharge:  1,
		Command:       0x0000, // NEGOTIATE
		CreditRequest: 1,
		MessageID:     1,
		SessionID:     0x0001000000000001,
	}
	msg := hdr.Marshal()
	if payloadSize > 0 {
		msg = append(msg, make([]byte, payloadSize)...)
	}
	return msg
}

// hexDecode is a test helper that decodes hex strings, panicking on error.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}

// ========================================================================
// Tests for computeHMACSHA256
// ========================================================================

func TestComputeHMACSHA256(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		message []byte
	}{
		{
			name:    "known key and message",
			key:     bytes.Repeat([]byte{0x0b}, 16),
			message: []byte("Hi There"),
		},
		{
			name:    "zero key",
			key:     make([]byte, 16),
			message: []byte("test message"),
		},
		{
			name:    "empty message",
			key:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			message: []byte{},
		},
		{
			name:    "long key is truncated to 16 bytes",
			key:     bytes.Repeat([]byte{0xaa}, 32),
			message: []byte("data"),
		},
		{
			name:    "short key is padded to 16 bytes",
			key:     []byte{0x01, 0x02, 0x03},
			message: []byte("data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeHMACSHA256(tt.message, tt.key)

			// Must always return exactly 16 bytes
			if len(result) != 16 {
				t.Fatalf("expected 16 bytes, got %d", len(result))
			}

			// Must be deterministic
			result2 := computeHMACSHA256(tt.message, tt.key)
			if !bytes.Equal(result, result2) {
				t.Errorf("non-deterministic: %x != %x", result, result2)
			}
		})
	}
}

func TestComputeHMACSHA256_ShortKeyEquivPaddedKey(t *testing.T) {
	// A 3-byte key should produce the same result as that key zero-padded to 16 bytes,
	// because computeHMACSHA256 copies into a 16-byte buffer.
	shortKey := []byte{0x01, 0x02, 0x03}
	paddedKey := make([]byte, 16)
	copy(paddedKey, shortKey)
	msg := []byte("hello signing")

	r1 := computeHMACSHA256(msg, shortKey)
	r2 := computeHMACSHA256(msg, paddedKey)
	if !bytes.Equal(r1, r2) {
		t.Errorf("short key %x != padded key %x", r1, r2)
	}
}

// ========================================================================
// Tests for computeAESCMAC — RFC 4493 test vectors
// ========================================================================

func TestComputeAESCMAC_RFC4493(t *testing.T) {
	// RFC 4493 Section 4 test vectors
	key := hexDecode(t, "2b7e151628aed2a6abf7158809cf4f3c")

	tests := []struct {
		name     string
		message  string // hex-encoded
		expected string // hex-encoded expected MAC
	}{
		{
			name:     "empty message (0 bytes)",
			message:  "",
			expected: "bb1d6929e95937287fa37d129b756746",
		},
		{
			name:     "16-byte message",
			message:  "6bc1bee22e409f96e93d7e117393172a",
			expected: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			name:     "40-byte message",
			message:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			expected: "dfa66747de9ae63030ca32611497c827",
		},
		{
			name:     "64-byte message",
			message:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			expected: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := hexDecode(t, tt.message)
			expected := hexDecode(t, tt.expected)

			result := computeAESCMAC(msg, key)
			if !bytes.Equal(result, expected) {
				t.Errorf("AES-CMAC mismatch:\n  got:      %x\n  expected: %x", result, expected)
			}
		})
	}
}

// ========================================================================
// Tests for generateCMACSubkeys
// ========================================================================

func TestGenerateCMACSubkeys_RFC4493(t *testing.T) {
	// RFC 4493 Section 4 subkey test vectors
	key := hexDecode(t, "2b7e151628aed2a6abf7158809cf4f3c")
	expectedK1 := hexDecode(t, "fbeed618357133667c85e08f7236a8de")
	expectedK2 := hexDecode(t, "f7ddac306ae266ccf90bc11ee46d513b")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	k1, k2 := generateCMACSubkeys(block)

	if !bytes.Equal(k1, expectedK1) {
		t.Errorf("K1 mismatch:\n  got:      %x\n  expected: %x", k1, expectedK1)
	}
	if !bytes.Equal(k2, expectedK2) {
		t.Errorf("K2 mismatch:\n  got:      %x\n  expected: %x", k2, expectedK2)
	}
}

// ========================================================================
// Tests for shiftLeft
// ========================================================================

func TestShiftLeft(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "all zeros",
			input:    make([]byte, 16),
			expected: make([]byte, 16),
		},
		{
			name:     "single byte no carry",
			input:    []byte{0x01},
			expected: []byte{0x02},
		},
		{
			name:     "single byte MSB set (carry lost)",
			input:    []byte{0x80},
			expected: []byte{0x00},
		},
		{
			name:     "MSB carry propagation",
			input:    []byte{0x00, 0x80},
			expected: []byte{0x01, 0x00},
		},
		{
			name:     "all ones",
			input:    []byte{0xff, 0xff, 0xff, 0xff},
			expected: []byte{0xff, 0xff, 0xff, 0xfe},
		},
		{
			name:     "alternating bits",
			input:    []byte{0xaa, 0x55},
			expected: []byte{0x54, 0xaa},
		},
		{
			name: "16 bytes with MSB carry",
			input: func() []byte {
				b := make([]byte, 16)
				b[0] = 0x80
				b[15] = 0x01
				return b
			}(),
			expected: func() []byte {
				b := make([]byte, 16)
				// 0x80 << 1 = 0x00 (MSB carry dropped), 0x01 << 1 = 0x02
				b[0] = 0x00
				b[15] = 0x02
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, len(tt.input))
			shiftLeft(dst, tt.input)
			if !bytes.Equal(dst, tt.expected) {
				t.Errorf("shiftLeft mismatch:\n  input:    %x\n  got:      %x\n  expected: %x",
					tt.input, dst, tt.expected)
			}
		})
	}
}

// ========================================================================
// Tests for xorBytes
// ========================================================================

func TestXorBytes(t *testing.T) {
	tests := []struct {
		name     string
		dst      []byte
		src      []byte
		expected []byte
	}{
		{
			name:     "identity (XOR with zeros)",
			dst:      []byte{0xab, 0xcd, 0xef, 0x12},
			src:      []byte{0x00, 0x00, 0x00, 0x00},
			expected: []byte{0xab, 0xcd, 0xef, 0x12},
		},
		{
			name:     "complement (XOR with all ones)",
			dst:      []byte{0xab, 0xcd, 0xef, 0x12},
			src:      []byte{0xff, 0xff, 0xff, 0xff},
			expected: []byte{0x54, 0x32, 0x10, 0xed},
		},
		{
			name:     "same values produce zeros",
			dst:      []byte{0xab, 0xcd, 0xef, 0x12},
			src:      []byte{0xab, 0xcd, 0xef, 0x12},
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "dst shorter than src",
			dst:      []byte{0x01, 0x02},
			src:      []byte{0x03, 0x04, 0x05, 0x06},
			expected: []byte{0x02, 0x06},
		},
		{
			name:     "src shorter than dst",
			dst:      []byte{0x01, 0x02, 0x03, 0x04},
			src:      []byte{0xff, 0xff},
			expected: []byte{0xfe, 0xfd, 0x03, 0x04},
		},
		{
			name:     "empty src no-op",
			dst:      []byte{0xab, 0xcd},
			src:      []byte{},
			expected: []byte{0xab, 0xcd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Work on a copy to validate expected
			dst := make([]byte, len(tt.dst))
			copy(dst, tt.dst)
			xorBytes(dst, tt.src)
			if !bytes.Equal(dst, tt.expected) {
				t.Errorf("xorBytes mismatch:\n  got:      %x\n  expected: %x", dst, tt.expected)
			}
		})
	}
}

// ========================================================================
// Tests for SignMessage
// ========================================================================

func TestSignMessage(t *testing.T) {
	key16 := bytes.Repeat([]byte{0x42}, 16)

	t.Run("nil key returns nil", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		sig := SignMessage(msg, nil, SMB2_1)
		if sig != nil {
			t.Errorf("expected nil, got %x", sig)
		}
	})

	t.Run("empty key returns nil", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		sig := SignMessage(msg, []byte{}, SMB3_0)
		if sig != nil {
			t.Errorf("expected nil, got %x", sig)
		}
	})

	t.Run("message too short returns nil", func(t *testing.T) {
		shortMsg := make([]byte, SMB2HeaderSize-1)
		sig := SignMessage(shortMsg, key16, SMB2_1)
		if sig != nil {
			t.Errorf("expected nil for short message, got %x", sig)
		}
	})

	t.Run("SMB 2.x uses HMAC-SHA256 and returns 16 bytes", func(t *testing.T) {
		for _, dialect := range []SMBDialect{SMB2_0_2, SMB2_1} {
			msg := makeMinimalSMB2Message(32)
			sig := SignMessage(msg, key16, dialect)
			if sig == nil {
				t.Fatalf("SignMessage returned nil for %s", dialect)
			}
			if len(sig) != 16 {
				t.Errorf("expected 16-byte signature, got %d for %s", len(sig), dialect)
			}
		}
	})

	t.Run("SMB 3.x uses AES-CMAC and returns 16 bytes", func(t *testing.T) {
		for _, dialect := range []SMBDialect{SMB3_0, SMB3_0_2, SMB3_1_1} {
			msg := makeMinimalSMB2Message(32)
			sig := SignMessage(msg, key16, dialect)
			if sig == nil {
				t.Fatalf("SignMessage returned nil for %s", dialect)
			}
			if len(sig) != 16 {
				t.Errorf("expected 16-byte signature, got %d for %s", len(sig), dialect)
			}
		}
	})

	t.Run("SMB 2.x and 3.x produce different signatures for same input", func(t *testing.T) {
		msg := makeMinimalSMB2Message(32)
		sig2 := SignMessage(msg, key16, SMB2_1)
		sig3 := SignMessage(msg, key16, SMB3_0)
		if bytes.Equal(sig2, sig3) {
			t.Error("SMB 2.x and 3.x should use different algorithms and produce different signatures")
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		msg := makeMinimalSMB2Message(16)
		sig1 := SignMessage(msg, key16, SMB2_1)
		sig2 := SignMessage(msg, key16, SMB2_1)
		if !bytes.Equal(sig1, sig2) {
			t.Errorf("non-deterministic: %x != %x", sig1, sig2)
		}
	})

	t.Run("signature ignores existing signature field", func(t *testing.T) {
		// Two messages identical except for the signature field should produce the same signature
		msg1 := makeMinimalSMB2Message(16)
		msg2 := make([]byte, len(msg1))
		copy(msg2, msg1)
		// Set different signature bytes in msg2
		for i := SignatureOffset; i < SignatureOffset+SignatureLength; i++ {
			msg2[i] = 0xff
		}
		sig1 := SignMessage(msg1, key16, SMB2_1)
		sig2 := SignMessage(msg2, key16, SMB2_1)
		if !bytes.Equal(sig1, sig2) {
			t.Errorf("signature should ignore existing signature field: %x != %x", sig1, sig2)
		}
	})
}

// ========================================================================
// Tests for VerifySignature
// ========================================================================

func TestVerifySignature(t *testing.T) {
	key16 := bytes.Repeat([]byte{0x42}, 16)

	t.Run("nil key returns false", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		if VerifySignature(msg, nil, SMB2_1) {
			t.Error("expected false for nil key")
		}
	})

	t.Run("short message returns false", func(t *testing.T) {
		if VerifySignature(make([]byte, 10), key16, SMB2_1) {
			t.Error("expected false for short message")
		}
	})

	dialects := []struct {
		name    string
		dialect SMBDialect
	}{
		{"SMB2_0_2", SMB2_0_2},
		{"SMB2_1", SMB2_1},
		{"SMB3_0", SMB3_0},
		{"SMB3_0_2", SMB3_0_2},
		{"SMB3_1_1", SMB3_1_1},
	}

	for _, d := range dialects {
		t.Run("sign-then-verify roundtrip "+d.name, func(t *testing.T) {
			msg := makeMinimalSMB2Message(64)
			// Write some non-zero payload
			for i := SMB2HeaderSize; i < len(msg); i++ {
				msg[i] = byte(i)
			}

			sig := SignMessage(msg, key16, d.dialect)
			if sig == nil {
				t.Fatal("SignMessage returned nil")
			}
			ApplySignature(msg, sig)

			if !VerifySignature(msg, key16, d.dialect) {
				t.Error("VerifySignature failed on correctly signed message")
			}
		})
	}

	t.Run("tampered message fails verification", func(t *testing.T) {
		msg := makeMinimalSMB2Message(64)
		sig := SignMessage(msg, key16, SMB2_1)
		ApplySignature(msg, sig)

		// Tamper with payload byte
		msg[SMB2HeaderSize] ^= 0x01
		if VerifySignature(msg, key16, SMB2_1) {
			t.Error("VerifySignature should fail on tampered message")
		}
	})

	t.Run("wrong key fails verification", func(t *testing.T) {
		msg := makeMinimalSMB2Message(64)
		sig := SignMessage(msg, key16, SMB3_0)
		ApplySignature(msg, sig)

		wrongKey := bytes.Repeat([]byte{0x99}, 16)
		if VerifySignature(msg, wrongKey, SMB3_0) {
			t.Error("VerifySignature should fail with wrong key")
		}
	})

	t.Run("wrong dialect fails verification", func(t *testing.T) {
		msg := makeMinimalSMB2Message(64)
		sig := SignMessage(msg, key16, SMB2_1)
		ApplySignature(msg, sig)

		// Verify with SMB3 dialect (uses AES-CMAC instead of HMAC-SHA256)
		if VerifySignature(msg, key16, SMB3_0) {
			t.Error("VerifySignature should fail with mismatched dialect")
		}
	})
}

// ========================================================================
// Tests for DeriveSigningKey
// ========================================================================

func TestDeriveSigningKey(t *testing.T) {
	sessionKey := bytes.Repeat([]byte{0x11}, 16)
	preauthHash := bytes.Repeat([]byte{0xaa}, 64)

	t.Run("SMB 2.x returns raw session key", func(t *testing.T) {
		for _, dialect := range []SMBDialect{SMB2_0_2, SMB2_1} {
			result := DeriveSigningKey(sessionKey, dialect, nil)
			if !bytes.Equal(result, sessionKey) {
				t.Errorf("%s: expected raw session key, got %x", dialect, result)
			}
		}
	})

	t.Run("SMB 3.0 uses KDF with SMB2AESCMAC/SmbSign labels", func(t *testing.T) {
		result := DeriveSigningKey(sessionKey, SMB3_0, nil)

		// Should NOT be the raw session key (KDF should transform it)
		if bytes.Equal(result, sessionKey) {
			t.Error("SMB 3.0 should derive key via KDF, not return raw session key")
		}
		if len(result) != 16 {
			t.Errorf("expected 16 bytes, got %d", len(result))
		}

		// Should be deterministic
		result2 := DeriveSigningKey(sessionKey, SMB3_0, nil)
		if !bytes.Equal(result, result2) {
			t.Errorf("non-deterministic: %x != %x", result, result2)
		}
	})

	t.Run("SMB 3.0.2 uses same labels as SMB 3.0", func(t *testing.T) {
		r30 := DeriveSigningKey(sessionKey, SMB3_0, nil)
		r302 := DeriveSigningKey(sessionKey, SMB3_0_2, nil)
		if !bytes.Equal(r30, r302) {
			t.Errorf("SMB 3.0 and 3.0.2 should use same labels: %x != %x", r30, r302)
		}
	})

	t.Run("SMB 3.1.1 with preauthHash uses SMBSigningKey label", func(t *testing.T) {
		result := DeriveSigningKey(sessionKey, SMB3_1_1, preauthHash)
		if bytes.Equal(result, sessionKey) {
			t.Error("SMB 3.1.1 should derive key via KDF")
		}
		if len(result) != 16 {
			t.Errorf("expected 16 bytes, got %d", len(result))
		}

		// Must differ from SMB 3.0 derivation (different label and context)
		r30 := DeriveSigningKey(sessionKey, SMB3_0, nil)
		if bytes.Equal(result, r30) {
			t.Error("SMB 3.1.1 key should differ from SMB 3.0 key")
		}
	})

	t.Run("SMB 3.1.1 without preauthHash falls back to 3.0 labels", func(t *testing.T) {
		result := DeriveSigningKey(sessionKey, SMB3_1_1, nil)
		r30 := DeriveSigningKey(sessionKey, SMB3_0, nil)
		if !bytes.Equal(result, r30) {
			t.Errorf("SMB 3.1.1 without preauthHash should use SMB 3.0 labels: %x != %x", result, r30)
		}
	})

	t.Run("different session keys produce different signing keys", func(t *testing.T) {
		sk1 := bytes.Repeat([]byte{0x11}, 16)
		sk2 := bytes.Repeat([]byte{0x22}, 16)
		r1 := DeriveSigningKey(sk1, SMB3_0, nil)
		r2 := DeriveSigningKey(sk2, SMB3_0, nil)
		if bytes.Equal(r1, r2) {
			t.Error("different session keys should produce different signing keys")
		}
	})

	t.Run("different preauthHashes produce different signing keys", func(t *testing.T) {
		ph1 := bytes.Repeat([]byte{0xaa}, 64)
		ph2 := bytes.Repeat([]byte{0xbb}, 64)
		r1 := DeriveSigningKey(sessionKey, SMB3_1_1, ph1)
		r2 := DeriveSigningKey(sessionKey, SMB3_1_1, ph2)
		if bytes.Equal(r1, r2) {
			t.Error("different preauth hashes should produce different signing keys")
		}
	})
}

// ========================================================================
// Tests for kdfSP800108
// ========================================================================

func TestKdfSP800108(t *testing.T) {
	ki := bytes.Repeat([]byte{0x42}, 16)
	label := []byte("TestLabel\x00")
	context := []byte("TestContext\x00")

	t.Run("deterministic output", func(t *testing.T) {
		r1 := kdfSP800108(ki, label, context, 16)
		r2 := kdfSP800108(ki, label, context, 16)
		if !bytes.Equal(r1, r2) {
			t.Errorf("non-deterministic: %x != %x", r1, r2)
		}
	})

	t.Run("output length matches request", func(t *testing.T) {
		for _, length := range []int{8, 16, 32} {
			result := kdfSP800108(ki, label, context, length)
			if len(result) != length {
				t.Errorf("requested %d bytes, got %d", length, len(result))
			}
		}
	})

	t.Run("different keys produce different outputs", func(t *testing.T) {
		ki2 := bytes.Repeat([]byte{0x99}, 16)
		r1 := kdfSP800108(ki, label, context, 16)
		r2 := kdfSP800108(ki2, label, context, 16)
		if bytes.Equal(r1, r2) {
			t.Error("different keys should produce different outputs")
		}
	})

	t.Run("different labels produce different outputs", func(t *testing.T) {
		label2 := []byte("OtherLabel\x00")
		r1 := kdfSP800108(ki, label, context, 16)
		r2 := kdfSP800108(ki, label2, context, 16)
		if bytes.Equal(r1, r2) {
			t.Error("different labels should produce different outputs")
		}
	})

	t.Run("different contexts produce different outputs", func(t *testing.T) {
		context2 := []byte("OtherContext\x00")
		r1 := kdfSP800108(ki, label, context, 16)
		r2 := kdfSP800108(ki, label, context2, 16)
		if bytes.Equal(r1, r2) {
			t.Error("different contexts should produce different outputs")
		}
	})

	t.Run("SMB2AESCMAC/SmbSign known input regression", func(t *testing.T) {
		// Use the MS-SMB2 specified labels to ensure the function works
		// correctly with real-world parameters.
		smbLabel := []byte("SMB2AESCMAC\x00")
		smbContext := []byte("SmbSign\x00")
		sessionKey := make([]byte, 16)
		for i := range sessionKey {
			sessionKey[i] = byte(i)
		}
		result := kdfSP800108(sessionKey, smbLabel, smbContext, 16)
		if len(result) != 16 {
			t.Fatalf("expected 16 bytes, got %d", len(result))
		}
		// Verify deterministic
		result2 := kdfSP800108(sessionKey, smbLabel, smbContext, 16)
		if !bytes.Equal(result, result2) {
			t.Errorf("non-deterministic with SMB labels: %x != %x", result, result2)
		}
	})
}

// ========================================================================
// Tests for ApplySignature
// ========================================================================

func TestApplySignature(t *testing.T) {
	t.Run("applies 16-byte signature at offset 48-63", func(t *testing.T) {
		msg := makeMinimalSMB2Message(32) // 96 bytes total
		sig := bytes.Repeat([]byte{0xDE}, 16)

		ApplySignature(msg, sig)

		got := msg[SignatureOffset : SignatureOffset+SignatureLength]
		if !bytes.Equal(got, sig) {
			t.Errorf("signature not applied correctly:\n  got:      %x\n  expected: %x", got, sig)
		}
	})

	t.Run("does not modify bytes outside signature field", func(t *testing.T) {
		msg := makeMinimalSMB2Message(32)
		original := make([]byte, len(msg))
		copy(original, msg)

		sig := bytes.Repeat([]byte{0xDE}, 16)
		ApplySignature(msg, sig)

		// Check bytes before signature field
		if !bytes.Equal(msg[:SignatureOffset], original[:SignatureOffset]) {
			t.Error("bytes before signature field were modified")
		}
		// Check bytes after signature field
		if !bytes.Equal(msg[SignatureOffset+SignatureLength:], original[SignatureOffset+SignatureLength:]) {
			t.Error("bytes after signature field were modified")
		}
	})

	t.Run("message too short is no-op", func(t *testing.T) {
		shortMsg := make([]byte, 32)
		copy(shortMsg, []byte{1, 2, 3, 4})
		original := make([]byte, len(shortMsg))
		copy(original, shortMsg)

		ApplySignature(shortMsg, bytes.Repeat([]byte{0xDE}, 16))
		if !bytes.Equal(shortMsg, original) {
			t.Error("short message should not be modified")
		}
	})

	t.Run("signature too short is no-op", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		original := make([]byte, len(msg))
		copy(original, msg)

		ApplySignature(msg, []byte{0x01, 0x02})
		if !bytes.Equal(msg, original) {
			t.Error("message should not be modified with short signature")
		}
	})
}

// ========================================================================
// Tests for SetSignedFlag / IsMessageSigned
// ========================================================================

func TestSetSignedFlag_IsMessageSigned(t *testing.T) {
	t.Run("roundtrip: set flag then verify", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		if IsMessageSigned(msg) {
			t.Fatal("fresh message should not be signed")
		}

		SetSignedFlag(msg)
		if !IsMessageSigned(msg) {
			t.Error("message should be signed after SetSignedFlag")
		}
	})

	t.Run("setting flag is idempotent", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		SetSignedFlag(msg)
		flags1 := binary.LittleEndian.Uint32(msg[16:20])
		SetSignedFlag(msg)
		flags2 := binary.LittleEndian.Uint32(msg[16:20])
		if flags1 != flags2 {
			t.Errorf("SetSignedFlag not idempotent: 0x%08x != 0x%08x", flags1, flags2)
		}
	})

	t.Run("preserves other flags", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		// Set the response flag first
		flags := binary.LittleEndian.Uint32(msg[16:20])
		flags |= SMB2_FLAGS_SERVER_TO_REDIR
		binary.LittleEndian.PutUint32(msg[16:20], flags)

		SetSignedFlag(msg)

		resultFlags := binary.LittleEndian.Uint32(msg[16:20])
		if resultFlags&SMB2_FLAGS_SERVER_TO_REDIR == 0 {
			t.Error("SetSignedFlag should preserve existing flags")
		}
		if resultFlags&SMB2_FLAGS_SIGNED == 0 {
			t.Error("signed flag should be set")
		}
	})

	t.Run("clear flag then verify not signed", func(t *testing.T) {
		msg := makeMinimalSMB2Message(0)
		SetSignedFlag(msg)
		if !IsMessageSigned(msg) {
			t.Fatal("expected signed after SetSignedFlag")
		}

		// Manually clear the signed flag
		flags := binary.LittleEndian.Uint32(msg[16:20])
		flags &^= SMB2_FLAGS_SIGNED
		binary.LittleEndian.PutUint32(msg[16:20], flags)

		if IsMessageSigned(msg) {
			t.Error("message should not be signed after clearing flag")
		}
	})

	t.Run("short message: SetSignedFlag is no-op", func(t *testing.T) {
		msg := make([]byte, 10)
		SetSignedFlag(msg) // should not panic
	})

	t.Run("short message: IsMessageSigned returns false", func(t *testing.T) {
		msg := make([]byte, 10)
		if IsMessageSigned(msg) {
			t.Error("short message should not be considered signed")
		}
	})
}

// ========================================================================
// Tests for InitPreauthHash
// ========================================================================

func TestInitPreauthHash(t *testing.T) {
	hash := InitPreauthHash()
	if len(hash) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(hash))
	}
	for i, b := range hash {
		if b != 0 {
			t.Errorf("byte %d should be 0, got 0x%02x", i, b)
		}
	}
}

// ========================================================================
// Tests for UpdatePreauthHash
// ========================================================================

func TestUpdatePreauthHash(t *testing.T) {
	t.Run("deterministic SHA-512(currentHash || message)", func(t *testing.T) {
		currentHash := InitPreauthHash()
		message := []byte("NEGOTIATE request data")

		result := UpdatePreauthHash(currentHash, message)
		if len(result) != 64 {
			t.Fatalf("expected 64 bytes, got %d", len(result))
		}

		// Manually compute expected value
		h := sha512.New()
		h.Write(currentHash)
		h.Write(message)
		expected := h.Sum(nil)

		if !bytes.Equal(result, expected) {
			t.Errorf("hash mismatch:\n  got:      %x\n  expected: %x", result, expected)
		}
	})

	t.Run("nil currentHash initializes to zeros", func(t *testing.T) {
		message := []byte("test")
		result := UpdatePreauthHash(nil, message)

		// Should behave same as passing 64 zero bytes
		zeroHash := InitPreauthHash()
		expected := UpdatePreauthHash(zeroHash, message)
		if !bytes.Equal(result, expected) {
			t.Errorf("nil hash should init to zeros: %x != %x", result, expected)
		}
	})

	t.Run("empty currentHash initializes to zeros", func(t *testing.T) {
		message := []byte("test")
		result := UpdatePreauthHash([]byte{}, message)

		zeroHash := InitPreauthHash()
		expected := UpdatePreauthHash(zeroHash, message)
		if !bytes.Equal(result, expected) {
			t.Errorf("empty hash should init to zeros: %x != %x", result, expected)
		}
	})

	t.Run("chained updates are order-dependent", func(t *testing.T) {
		hash := InitPreauthHash()
		msg1 := []byte("NEGOTIATE request")
		msg2 := []byte("NEGOTIATE response")

		// Order 1: msg1 then msg2
		h1 := UpdatePreauthHash(hash, msg1)
		h12 := UpdatePreauthHash(h1, msg2)

		// Order 2: msg2 then msg1
		h2 := UpdatePreauthHash(hash, msg2)
		h21 := UpdatePreauthHash(h2, msg1)

		if bytes.Equal(h12, h21) {
			t.Error("chained updates in different order should produce different hashes")
		}
	})

	t.Run("different messages produce different hashes", func(t *testing.T) {
		hash := InitPreauthHash()
		r1 := UpdatePreauthHash(hash, []byte("message A"))
		r2 := UpdatePreauthHash(hash, []byte("message B"))
		if bytes.Equal(r1, r2) {
			t.Error("different messages should produce different hashes")
		}
	})

	t.Run("empty message still changes hash", func(t *testing.T) {
		hash := InitPreauthHash()
		result := UpdatePreauthHash(hash, []byte{})
		// SHA-512(64_zero_bytes || empty) != 64_zero_bytes
		if bytes.Equal(result, hash) {
			t.Error("even empty message should change hash (SHA-512 of zeros != zeros)")
		}
	})

	t.Run("known input regression", func(t *testing.T) {
		// Compute a specific known case for regression testing
		currentHash := make([]byte, 64)
		for i := range currentHash {
			currentHash[i] = byte(i)
		}
		message := []byte{0xFE, 0x53, 0x4D, 0x42} // SMB2 magic bytes

		result := UpdatePreauthHash(currentHash, message)

		// Manually compute expected
		h := sha512.New()
		h.Write(currentHash)
		h.Write(message)
		expected := h.Sum(nil)

		if !bytes.Equal(result, expected) {
			t.Errorf("regression:\n  got:      %x\n  expected: %x", result, expected)
		}
	})
}

// ========================================================================
// Integration: full sign-verify with derived keys
// ========================================================================

func TestSignVerify_WithDerivedKeys(t *testing.T) {
	sessionKey := make([]byte, 16)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}

	tests := []struct {
		name        string
		dialect     SMBDialect
		preauthHash []byte
	}{
		{"SMB 2.0.2", SMB2_0_2, nil},
		{"SMB 2.1", SMB2_1, nil},
		{"SMB 3.0", SMB3_0, nil},
		{"SMB 3.0.2", SMB3_0_2, nil},
		{"SMB 3.1.1 with preauth hash", SMB3_1_1, bytes.Repeat([]byte{0xcc}, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingKey := DeriveSigningKey(sessionKey, tt.dialect, tt.preauthHash)
			if len(signingKey) == 0 {
				t.Fatal("DeriveSigningKey returned empty key")
			}

			msg := makeMinimalSMB2Message(128)
			// Fill payload with non-zero data
			for i := SMB2HeaderSize; i < len(msg); i++ {
				msg[i] = byte(i * 7)
			}

			// Set signed flag BEFORE computing signature, since the flag
			// changes bytes in the header that are included in the hash.
			SetSignedFlag(msg)

			sig := SignMessage(msg, signingKey, tt.dialect)
			if sig == nil {
				t.Fatal("SignMessage returned nil")
			}
			ApplySignature(msg, sig)

			if !IsMessageSigned(msg) {
				t.Error("message should be marked as signed")
			}
			if !VerifySignature(msg, signingKey, tt.dialect) {
				t.Error("VerifySignature failed on correctly signed message")
			}
		})
	}
}
