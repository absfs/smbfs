package smbfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// --- Pure Function Tests ---

// TestNtHash verifies NT hash computation (MD4 of UTF-16LE password).
// MS-NLMP test vector: ntHash("Password") should produce a4f49c406510bdcab6824ee7c30fd852.
func TestNtHash(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.ntHash("Password")
	want, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	if !bytes.Equal(got, want) {
		t.Errorf("ntHash(\"Password\") = %x, want %x", got, want)
	}
}

func TestNtHash_Empty(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.ntHash("")
	// MD4 of empty input (zero-length UTF-16LE) should be the MD4 of empty string
	if len(got) != 16 {
		t.Errorf("ntHash(\"\") returned %d bytes, want 16", len(got))
	}
}

// TestNtv2Hash verifies NTOWFv2 = HMAC_MD5(ntHash, uppercase(username) + uppercase(domain) in UTF-16LE).
// Using User="User", Password="Password", Domain="Domain".
// Note: this implementation uppercases both username and domain.
func TestNtv2Hash(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.ntv2Hash("User", "Password", "Domain")

	// Compute expected value manually:
	// ntHash = MD4(UTF-16LE("Password")) = a4f49c406510bdcab6824ee7c30fd852
	ntHashBytes, _ := hex.DecodeString("a4f49c406510bdcab6824ee7c30fd852")
	// userDomain = "USERDOMAIN" (both uppercased in this implementation)
	userDomain := EncodeStringToUTF16LE("USERDOMAIN")
	h := hmac.New(md5.New, ntHashBytes)
	h.Write(userDomain)
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("ntv2Hash(\"User\", \"Password\", \"Domain\") = %x, want %x", got, want)
	}
	if len(got) != 16 {
		t.Errorf("ntv2Hash returned %d bytes, want 16", len(got))
	}
}

func TestNtv2Hash_CaseInsensitive(t *testing.T) {
	a := &NTLMAuthenticator{}
	// Both should produce the same result since both username and domain are uppercased
	hash1 := a.ntv2Hash("user", "Password", "domain")
	hash2 := a.ntv2Hash("USER", "Password", "DOMAIN")
	if !bytes.Equal(hash1, hash2) {
		t.Errorf("ntv2Hash should be case-insensitive for username and domain: %x != %x", hash1, hash2)
	}
}

// TestRC4Decrypt verifies RC4 encrypt/decrypt roundtrip.
func TestRC4Decrypt(t *testing.T) {
	key := []byte("sixteen-byte-key")
	plaintext := []byte("hello world test data for rc4")

	// Encrypt with RC4
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		t.Fatalf("rc4.NewCipher() error: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	// Decrypt using the function under test
	decrypted := rc4Decrypt(key, ciphertext)
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("rc4Decrypt roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestRC4Decrypt_EmptyData(t *testing.T) {
	key := []byte("some-key-here!!!")
	got := rc4Decrypt(key, []byte{})
	if len(got) != 0 {
		t.Errorf("rc4Decrypt with empty data should return empty, got %d bytes", len(got))
	}
}

// TestASN1Wrap_Short verifies ASN.1 wrapping for data < 128 bytes.
func TestASN1Wrap_Short(t *testing.T) {
	a := &NTLMAuthenticator{}
	data := []byte("hello") // 5 bytes
	got := a.asn1Wrap(0x30, data)

	if got[0] != 0x30 {
		t.Errorf("tag = 0x%02x, want 0x30", got[0])
	}
	if got[1] != 5 {
		t.Errorf("length = %d, want 5", got[1])
	}
	if !bytes.Equal(got[2:], data) {
		t.Errorf("payload = %x, want %x", got[2:], data)
	}
	if len(got) != 2+5 {
		t.Errorf("total length = %d, want 7", len(got))
	}
}

// TestASN1Wrap_Medium verifies ASN.1 wrapping for data 128-255 bytes.
func TestASN1Wrap_Medium(t *testing.T) {
	a := &NTLMAuthenticator{}
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	got := a.asn1Wrap(0xa0, data)

	if got[0] != 0xa0 {
		t.Errorf("tag = 0x%02x, want 0xa0", got[0])
	}
	if got[1] != 0x81 {
		t.Errorf("length marker = 0x%02x, want 0x81", got[1])
	}
	if got[2] != 200 {
		t.Errorf("length = %d, want 200", got[2])
	}
	if !bytes.Equal(got[3:], data) {
		t.Errorf("payload mismatch")
	}
	if len(got) != 3+200 {
		t.Errorf("total length = %d, want 203", len(got))
	}
}

// TestASN1Wrap_Long verifies ASN.1 wrapping for data > 255 bytes.
func TestASN1Wrap_Long(t *testing.T) {
	a := &NTLMAuthenticator{}
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}
	got := a.asn1Wrap(0x04, data)

	if got[0] != 0x04 {
		t.Errorf("tag = 0x%02x, want 0x04", got[0])
	}
	if got[1] != 0x82 {
		t.Errorf("length marker = 0x%02x, want 0x82", got[1])
	}
	encodedLen := binary.BigEndian.Uint16(got[2:4])
	if encodedLen != 300 {
		t.Errorf("length = %d, want 300", encodedLen)
	}
	if !bytes.Equal(got[4:], data) {
		t.Errorf("payload mismatch")
	}
	if len(got) != 4+300 {
		t.Errorf("total length = %d, want 304", len(got))
	}
}

// TestASN1Wrap_Boundary128 verifies the exact boundary at 128 bytes uses long form.
func TestASN1Wrap_Boundary128(t *testing.T) {
	a := &NTLMAuthenticator{}
	data := make([]byte, 128)
	got := a.asn1Wrap(0x30, data)
	// 128 >= 128, so should use 0x81 form
	if got[1] != 0x81 {
		t.Errorf("128 bytes should use long form (0x81), got 0x%02x", got[1])
	}
	if got[2] != 128 {
		t.Errorf("length byte = %d, want 128", got[2])
	}
}

// TestWriteAVPair verifies AV_PAIR serialization (avID uint16LE + length uint16LE + value).
func TestWriteAVPair(t *testing.T) {
	a := &NTLMAuthenticator{}
	var buf bytes.Buffer
	value := []byte{0xAA, 0xBB, 0xCC}

	a.writeAVPair(&buf, 0x0002, value)
	got := buf.Bytes()

	// Check avID (uint16LE)
	avID := binary.LittleEndian.Uint16(got[0:2])
	if avID != 0x0002 {
		t.Errorf("avID = 0x%04x, want 0x0002", avID)
	}

	// Check length (uint16LE)
	avLen := binary.LittleEndian.Uint16(got[2:4])
	if avLen != 3 {
		t.Errorf("avLen = %d, want 3", avLen)
	}

	// Check value
	if !bytes.Equal(got[4:7], value) {
		t.Errorf("value = %x, want %x", got[4:7], value)
	}

	if len(got) != 7 {
		t.Errorf("total size = %d, want 7", len(got))
	}
}

func TestWriteAVPair_Empty(t *testing.T) {
	a := &NTLMAuthenticator{}
	var buf bytes.Buffer
	a.writeAVPair(&buf, avIDMsvAvEOL, nil)
	got := buf.Bytes()

	if len(got) != 4 {
		t.Fatalf("EOL pair should be 4 bytes, got %d", len(got))
	}
	avID := binary.LittleEndian.Uint16(got[0:2])
	avLen := binary.LittleEndian.Uint16(got[2:4])
	if avID != 0 {
		t.Errorf("avID = %d, want 0 (EOL)", avID)
	}
	if avLen != 0 {
		t.Errorf("avLen = %d, want 0", avLen)
	}
}

// TestBuildTargetInfo verifies the AV_PAIR list structure for target info.
func TestBuildTargetInfo(t *testing.T) {
	a := &NTLMAuthenticator{targetName: "TESTSERVER"}
	info := a.buildTargetInfo()

	// Parse all AV_PAIRs
	type avPair struct {
		id    uint16
		value []byte
	}
	var pairs []avPair
	offset := 0
	for offset+4 <= len(info) {
		id := binary.LittleEndian.Uint16(info[offset : offset+2])
		length := binary.LittleEndian.Uint16(info[offset+2 : offset+4])
		var val []byte
		if length > 0 {
			if offset+4+int(length) > len(info) {
				t.Fatalf("AV_PAIR at offset %d overflows: length=%d, remaining=%d", offset, length, len(info)-offset-4)
			}
			val = info[offset+4 : offset+4+int(length)]
		}
		pairs = append(pairs, avPair{id: id, value: val})
		offset += 4 + int(length)
		if id == avIDMsvAvEOL {
			break
		}
	}

	// Build a map for easy lookup
	pairMap := make(map[uint16][]byte)
	for _, p := range pairs {
		pairMap[p.id] = p.value
	}

	// Verify required AV_PAIRs
	testServerUTF16 := EncodeStringToUTF16LE("TESTSERVER")

	// MsvAvNbDomainName (avID=2)
	if val, ok := pairMap[avIDMsvAvNbDomainName]; !ok {
		t.Error("MsvAvNbDomainName (avID=2) not found")
	} else if !bytes.Equal(val, testServerUTF16) {
		t.Errorf("MsvAvNbDomainName = %x, want %x", val, testServerUTF16)
	}

	// MsvAvNbComputerName (avID=1)
	if val, ok := pairMap[avIDMsvAvNbComputerName]; !ok {
		t.Error("MsvAvNbComputerName (avID=1) not found")
	} else if !bytes.Equal(val, testServerUTF16) {
		t.Errorf("MsvAvNbComputerName = %x, want %x", val, testServerUTF16)
	}

	// MsvAvDnsDomainName (avID=4)
	if _, ok := pairMap[avIDMsvAvDnsDomainName]; !ok {
		t.Error("MsvAvDnsDomainName (avID=4) not found")
	}

	// MsvAvDnsComputerName (avID=3)
	if _, ok := pairMap[avIDMsvAvDnsComputerName]; !ok {
		t.Error("MsvAvDnsComputerName (avID=3) not found")
	}

	// MsvAvTimestamp (avID=7) - must be 8 bytes
	if val, ok := pairMap[avIDMsvAvTimestamp]; !ok {
		t.Error("MsvAvTimestamp (avID=7) not found")
	} else if len(val) != 8 {
		t.Errorf("MsvAvTimestamp length = %d, want 8", len(val))
	}

	// MsvAvEOL (avID=0) should be the last pair
	lastPair := pairs[len(pairs)-1]
	if lastPair.id != avIDMsvAvEOL {
		t.Errorf("last AV_PAIR id = %d, want 0 (EOL)", lastPair.id)
	}
}

// TestBuildTargetInfo_Order verifies the pairs appear in the expected order.
func TestBuildTargetInfo_Order(t *testing.T) {
	a := &NTLMAuthenticator{targetName: "SRV"}
	info := a.buildTargetInfo()

	expectedOrder := []uint16{
		avIDMsvAvNbDomainName,
		avIDMsvAvNbComputerName,
		avIDMsvAvDnsDomainName,
		avIDMsvAvDnsComputerName,
		avIDMsvAvTimestamp,
		avIDMsvAvEOL,
	}

	var gotOrder []uint16
	offset := 0
	for offset+4 <= len(info) {
		id := binary.LittleEndian.Uint16(info[offset : offset+2])
		length := binary.LittleEndian.Uint16(info[offset+2 : offset+4])
		gotOrder = append(gotOrder, id)
		offset += 4 + int(length)
		if id == avIDMsvAvEOL {
			break
		}
	}

	if len(gotOrder) != len(expectedOrder) {
		t.Fatalf("got %d pairs, want %d", len(gotOrder), len(expectedOrder))
	}
	for i := range expectedOrder {
		if gotOrder[i] != expectedOrder[i] {
			t.Errorf("pair[%d] id = %d, want %d", i, gotOrder[i], expectedOrder[i])
		}
	}
}

// TestBuildResponseFlags verifies flag negotiation logic with table-driven tests.
func TestBuildResponseFlags(t *testing.T) {
	tests := []struct {
		name        string
		clientFlags uint32
		wantSet     uint32 // flags that MUST be set
		wantClear   uint32 // flags that MUST NOT be set
	}{
		{
			name:        "no client flags, only NTLM base",
			clientFlags: 0,
			wantSet:     ntlmFlagNegotiateNTLM,
			wantClear:   ntlmFlagNegotiateUnicode | ntlmFlagNegotiateOEM,
		},
		{
			name:        "UNICODE requested",
			clientFlags: ntlmFlagNegotiateUnicode,
			wantSet:     ntlmFlagNegotiateNTLM | ntlmFlagNegotiateUnicode,
			wantClear:   ntlmFlagNegotiateOEM, // OEM must not be set when UNICODE is
		},
		{
			name:        "OEM only requested",
			clientFlags: ntlmFlagNegotiateOEM,
			wantSet:     ntlmFlagNegotiateNTLM | ntlmFlagNegotiateOEM,
			wantClear:   ntlmFlagNegotiateUnicode,
		},
		{
			name:        "UNICODE and OEM both requested, UNICODE wins",
			clientFlags: ntlmFlagNegotiateUnicode | ntlmFlagNegotiateOEM,
			wantSet:     ntlmFlagNegotiateUnicode,
			wantClear:   ntlmFlagNegotiateOEM,
		},
		{
			name:        "TARGET_INFO echoed",
			clientFlags: ntlmFlagNegotiateTargetInfo,
			wantSet:     ntlmFlagNegotiateTargetInfo,
		},
		{
			name:        "EXTENDED_SESSION_SEC echoed",
			clientFlags: ntlmFlagNegotiateExtendedSessionSec,
			wantSet:     ntlmFlagNegotiateExtendedSessionSec,
		},
		{
			name:        "128 and 56 bit encryption echoed",
			clientFlags: ntlmFlagNegotiate128 | ntlmFlagNegotiate56,
			wantSet:     ntlmFlagNegotiate128 | ntlmFlagNegotiate56,
		},
		{
			name:        "KEY_EXCH echoed",
			clientFlags: ntlmFlagNegotiateKeyExch,
			wantSet:     ntlmFlagNegotiateKeyExch,
		},
		{
			name:        "SIGN and SEAL echoed",
			clientFlags: ntlmFlagNegotiateSign | ntlmFlagNegotiateSeal,
			wantSet:     ntlmFlagNegotiateSign | ntlmFlagNegotiateSeal,
		},
		{
			name:        "LM_KEY with EXTENDED_SESSION_SEC cleared",
			clientFlags: ntlmFlagNegotiateLMKey | ntlmFlagNegotiateExtendedSessionSec,
			wantSet:     ntlmFlagNegotiateExtendedSessionSec,
			wantClear:   ntlmFlagNegotiateLMKey, // LM_KEY must not be set when ESS is
		},
		{
			name:        "LM_KEY without EXTENDED_SESSION_SEC set",
			clientFlags: ntlmFlagNegotiateLMKey,
			wantSet:     ntlmFlagNegotiateLMKey,
		},
		{
			name: "typical Windows client flags",
			clientFlags: ntlmFlagNegotiateUnicode | ntlmFlagRequestTarget |
				ntlmFlagNegotiateSign | ntlmFlagNegotiateSeal |
				ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateTargetInfo |
				ntlmFlagNegotiate128 | ntlmFlagNegotiateKeyExch |
				ntlmFlagNegotiate56 | ntlmFlagNegotiateVersion |
				ntlmFlagNegotiateAlwaysSign,
			wantSet: ntlmFlagNegotiateUnicode | ntlmFlagRequestTarget |
				ntlmFlagNegotiateSign | ntlmFlagNegotiateSeal |
				ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateTargetInfo |
				ntlmFlagNegotiate128 | ntlmFlagNegotiateKeyExch |
				ntlmFlagNegotiate56 | ntlmFlagNegotiateVersion |
				ntlmFlagNegotiateAlwaysSign | ntlmFlagNegotiateNTLM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &NTLMAuthenticator{clientFlags: tt.clientFlags}
			got := a.buildResponseFlags()

			if tt.wantSet != 0 && got&tt.wantSet != tt.wantSet {
				t.Errorf("buildResponseFlags() = 0x%08x, missing expected flags 0x%08x (missing: 0x%08x)",
					got, tt.wantSet, tt.wantSet&^got)
			}
			if tt.wantClear != 0 && got&tt.wantClear != 0 {
				t.Errorf("buildResponseFlags() = 0x%08x, has unwanted flags 0x%08x (present: 0x%08x)",
					got, tt.wantClear, got&tt.wantClear)
			}
		})
	}
}

// Helper to build a minimal NTLM Type 3 (Authenticate) message for testing extract functions.
// Layout per MS-NLMP AUTHENTICATE_MESSAGE:
//
//	Offset  0: Signature (8 bytes) "NTLMSSP\0"
//	Offset  8: MessageType (4 bytes) = 3
//	Offset 12: LmChallengeResponseFields (8 bytes: len, maxlen, offset)
//	Offset 20: NtChallengeResponseFields (8 bytes: len, maxlen, offset)
//	Offset 28: DomainNameFields (8 bytes: len, maxlen, offset)
//	Offset 36: UserNameFields (8 bytes: len, maxlen, offset)
//	Offset 44: WorkstationFields (8 bytes: len, maxlen, offset)
//	Offset 52: EncryptedRandomSessionKeyFields (8 bytes: len, maxlen, offset)
//	Offset 60: NegotiateFlags (4 bytes)
//	Offset 64: Payload...
func buildType3Message(domain, username string, ntResponse, encSessionKey []byte) []byte {
	domainUTF16 := EncodeStringToUTF16LE(domain)
	userUTF16 := EncodeStringToUTF16LE(username)
	workstation := EncodeStringToUTF16LE("WORKSTATION")
	lmResponse := make([]byte, 24) // 24-byte LM response (zeros for simplicity)

	headerSize := uint32(64)
	// Payload layout: LM response, NT response, domain, username, workstation, encSessionKey
	lmOffset := headerSize
	ntOffset := lmOffset + uint32(len(lmResponse))
	domainOffset := ntOffset + uint32(len(ntResponse))
	userOffset := domainOffset + uint32(len(domainUTF16))
	wsOffset := userOffset + uint32(len(userUTF16))
	encKeyOffset := wsOffset + uint32(len(workstation))

	totalLen := encKeyOffset + uint32(len(encSessionKey))
	msg := make([]byte, totalLen)

	// Signature
	copy(msg[0:8], ntlmSignature)
	// MessageType = 3
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuthenticateMessage)

	// LmChallengeResponseFields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint32(msg[16:20], lmOffset)

	// NtChallengeResponseFields
	binary.LittleEndian.PutUint16(msg[20:22], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(msg[24:28], ntOffset)

	// DomainNameFields
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint32(msg[32:36], domainOffset)

	// UserNameFields
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint32(msg[40:44], userOffset)

	// WorkstationFields
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(workstation)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(workstation)))
	binary.LittleEndian.PutUint32(msg[48:52], wsOffset)

	// EncryptedRandomSessionKeyFields
	binary.LittleEndian.PutUint16(msg[52:54], uint16(len(encSessionKey)))
	binary.LittleEndian.PutUint16(msg[54:56], uint16(len(encSessionKey)))
	binary.LittleEndian.PutUint32(msg[56:60], encKeyOffset)

	// NegotiateFlags
	flags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM | ntlmFlagNegotiateKeyExch)
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// Payload
	copy(msg[lmOffset:], lmResponse)
	copy(msg[ntOffset:], ntResponse)
	copy(msg[domainOffset:], domainUTF16)
	copy(msg[userOffset:], userUTF16)
	copy(msg[wsOffset:], workstation)
	copy(msg[encKeyOffset:], encSessionKey)

	return msg
}

// TestExtractUsername verifies username extraction from a Type 3 message.
func TestExtractUsername(t *testing.T) {
	a := &NTLMAuthenticator{}
	msg := buildType3Message("WORKGROUP", "TestUser", make([]byte, 32), make([]byte, 16))
	got := a.extractUsername(msg)
	if got != "TestUser" {
		t.Errorf("extractUsername() = %q, want %q", got, "TestUser")
	}
}

func TestExtractUsername_Empty(t *testing.T) {
	a := &NTLMAuthenticator{}
	msg := buildType3Message("WORKGROUP", "", make([]byte, 32), make([]byte, 16))
	got := a.extractUsername(msg)
	if got != "" {
		t.Errorf("extractUsername() = %q, want empty", got)
	}
}

func TestExtractUsername_TooShort(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractUsername(make([]byte, 10))
	if got != "" {
		t.Errorf("extractUsername() with short blob = %q, want empty", got)
	}
}

// TestExtractDomain verifies domain extraction from a Type 3 message.
func TestExtractDomain(t *testing.T) {
	a := &NTLMAuthenticator{}
	msg := buildType3Message("WORKGROUP", "TestUser", make([]byte, 32), make([]byte, 16))
	got := a.extractDomain(msg)
	if got != "WORKGROUP" {
		t.Errorf("extractDomain() = %q, want %q", got, "WORKGROUP")
	}
}

func TestExtractDomain_Empty(t *testing.T) {
	a := &NTLMAuthenticator{}
	msg := buildType3Message("", "TestUser", make([]byte, 32), make([]byte, 16))
	got := a.extractDomain(msg)
	if got != "" {
		t.Errorf("extractDomain() = %q, want empty", got)
	}
}

func TestExtractDomain_TooShort(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractDomain(make([]byte, 10))
	if got != "" {
		t.Errorf("extractDomain() with short blob = %q, want empty", got)
	}
}

// TestExtractNTResponse verifies NT response extraction from a Type 3 message.
func TestExtractNTResponse(t *testing.T) {
	a := &NTLMAuthenticator{}
	ntResp := make([]byte, 32)
	for i := range ntResp {
		ntResp[i] = byte(i + 0x10)
	}
	msg := buildType3Message("DOM", "user", ntResp, make([]byte, 16))
	got := a.extractNTResponse(msg)
	if !bytes.Equal(got, ntResp) {
		t.Errorf("extractNTResponse() = %x, want %x", got, ntResp)
	}
}

func TestExtractNTResponse_TooShort(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractNTResponse(make([]byte, 10))
	if got != nil {
		t.Errorf("extractNTResponse() with short blob = %x, want nil", got)
	}
}

// TestExtractEncryptedSessionKey verifies encrypted session key extraction.
func TestExtractEncryptedSessionKey(t *testing.T) {
	a := &NTLMAuthenticator{}
	encKey := make([]byte, 16)
	for i := range encKey {
		encKey[i] = byte(0xAA + i)
	}
	msg := buildType3Message("DOM", "user", make([]byte, 32), encKey)
	got := a.extractEncryptedSessionKey(msg)
	if !bytes.Equal(got, encKey) {
		t.Errorf("extractEncryptedSessionKey() = %x, want %x", got, encKey)
	}
}

func TestExtractEncryptedSessionKey_TooShort(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractEncryptedSessionKey(make([]byte, 10))
	if got != nil {
		t.Errorf("extractEncryptedSessionKey() with short blob = %x, want nil", got)
	}
}

func TestExtractEncryptedSessionKey_ZeroLength(t *testing.T) {
	a := &NTLMAuthenticator{}
	// Build a message with zero-length encrypted session key
	msg := buildType3Message("DOM", "user", make([]byte, 32), []byte{})
	got := a.extractEncryptedSessionKey(msg)
	if got != nil {
		t.Errorf("extractEncryptedSessionKey() with zero-len key = %x, want nil", got)
	}
}

// TestExtractNTLMFromSPNEGO verifies NTLM extraction from an SPNEGO wrapper.
func TestExtractNTLMFromSPNEGO(t *testing.T) {
	a := &NTLMAuthenticator{}
	// Build a simple NTLM Type 1 message
	ntlmMsg := make([]byte, 32)
	copy(ntlmMsg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(ntlmMsg[8:12], ntlmNegotiateMessage)
	binary.LittleEndian.PutUint32(ntlmMsg[12:16], ntlmFlagNegotiateUnicode|ntlmFlagNegotiateNTLM)

	// Wrap in SPNEGO
	wrapped := a.wrapInSPNEGO(ntlmMsg)

	// Extract
	got := a.extractNTLMFromSPNEGO(wrapped)
	if got == nil {
		t.Fatal("extractNTLMFromSPNEGO() returned nil")
	}
	if !bytes.HasPrefix(got, ntlmSignature) {
		t.Error("extracted blob does not start with NTLMSSP signature")
	}
	// The extracted blob should start at the NTLMSSP signature and continue to the end
	if !bytes.Equal(got[:len(ntlmMsg)], ntlmMsg) {
		t.Errorf("extracted NTLM message does not match original")
	}
}

func TestExtractNTLMFromSPNEGO_NoNTLM(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractNTLMFromSPNEGO([]byte{0x60, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a})
	if got != nil {
		t.Errorf("extractNTLMFromSPNEGO() with no NTLM = %x, want nil", got)
	}
}

func TestExtractNTLMFromSPNEGO_TooShort(t *testing.T) {
	a := &NTLMAuthenticator{}
	got := a.extractNTLMFromSPNEGO([]byte{0x01, 0x02})
	if got != nil {
		t.Errorf("extractNTLMFromSPNEGO() with short blob = %x, want nil", got)
	}
}

// TestWrapInSPNEGO verifies the SPNEGO wrapper contains the NTLM OID.
func TestWrapInSPNEGO(t *testing.T) {
	a := &NTLMAuthenticator{}
	ntlmMsg := []byte("test-ntlm-message")
	wrapped := a.wrapInSPNEGO(ntlmMsg)

	// NTLM OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	if !bytes.Contains(wrapped, ntlmOID) {
		t.Error("SPNEGO wrapper does not contain NTLM OID")
	}

	// Must contain the original message
	if !bytes.Contains(wrapped, ntlmMsg) {
		t.Error("SPNEGO wrapper does not contain the original NTLM message")
	}

	// Must start with context tag [1] = 0xa1
	if wrapped[0] != 0xa1 {
		t.Errorf("SPNEGO wrapper starts with 0x%02x, want 0xa1 (NegTokenResp)", wrapped[0])
	}
}

// TestWrapInSPNEGO_Roundtrip verifies wrap then extract returns the original message.
func TestWrapInSPNEGO_Roundtrip(t *testing.T) {
	a := &NTLMAuthenticator{}
	// Build an NTLM message with proper signature so extractNTLMFromSPNEGO can find it
	original := make([]byte, 20)
	copy(original[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(original[8:12], 2)
	original[12] = 0xFF

	wrapped := a.wrapInSPNEGO(original)
	extracted := a.extractNTLMFromSPNEGO(wrapped)
	if extracted == nil {
		t.Fatal("roundtrip: extractNTLMFromSPNEGO returned nil")
	}
	if !bytes.Equal(extracted[:len(original)], original) {
		t.Errorf("roundtrip failed: extracted[:%d] != original", len(original))
	}
}

// TestBuildChallengeMessage verifies the structure of an NTLM Type 2 challenge message.
func TestBuildChallengeMessage(t *testing.T) {
	a := &NTLMAuthenticator{
		targetName:      "TESTSVR",
		serverChallenge: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		clientFlags:     ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM | ntlmFlagRequestTarget,
	}

	msg := a.buildChallengeMessage()

	// Verify NTLMSSP signature
	if !bytes.Equal(msg[0:8], ntlmSignature) {
		t.Errorf("signature = %x, want %x", msg[0:8], ntlmSignature)
	}

	// Verify message type = 2
	msgType := binary.LittleEndian.Uint32(msg[8:12])
	if msgType != ntlmChallengeMessage {
		t.Errorf("message type = %d, want %d", msgType, ntlmChallengeMessage)
	}

	// Verify server challenge at offset 24
	challenge := msg[24:32]
	if !bytes.Equal(challenge, a.serverChallenge) {
		t.Errorf("server challenge = %x, want %x", challenge, a.serverChallenge)
	}

	// Verify target name is present in UTF-16LE
	targetNameUTF16 := EncodeStringToUTF16LE("TESTSVR")
	targetNameLen := binary.LittleEndian.Uint16(msg[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(msg[16:20])
	if int(targetNameLen) != len(targetNameUTF16) {
		t.Errorf("target name len = %d, want %d", targetNameLen, len(targetNameUTF16))
	}
	if !bytes.Equal(msg[targetNameOffset:targetNameOffset+uint32(targetNameLen)], targetNameUTF16) {
		t.Error("target name UTF-16LE content mismatch")
	}

	// Verify flags contain NTLM and TARGET_INFO (buildChallengeMessage always adds TARGET_INFO)
	flags := binary.LittleEndian.Uint32(msg[20:24])
	if flags&ntlmFlagNegotiateNTLM == 0 {
		t.Error("flags missing NEGOTIATE_NTLM")
	}
	if flags&ntlmFlagNegotiateTargetInfo == 0 {
		t.Error("flags missing NEGOTIATE_TARGET_INFO")
	}

	// Verify version fields at offset 48
	if msg[48] != 6 {
		t.Errorf("major version = %d, want 6", msg[48])
	}
	if msg[49] != 1 {
		t.Errorf("minor version = %d, want 1", msg[49])
	}
	buildNumber := binary.LittleEndian.Uint16(msg[50:52])
	if buildNumber != 7601 {
		t.Errorf("build number = %d, want 7601", buildNumber)
	}
	if msg[55] != 15 {
		t.Errorf("NTLM revision = %d, want 15", msg[55])
	}

	// Verify target info is present (offset in msg[44:48], length in msg[40:42])
	targetInfoLen := binary.LittleEndian.Uint16(msg[40:42])
	if targetInfoLen == 0 {
		t.Error("target info length is 0, expected non-zero")
	}
}

// --- Full Auth Flow Tests ---

// buildType1Message creates a minimal NTLM Type 1 (Negotiate) message.
func buildType1Message(flags uint32) []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmNegotiateMessage)
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	// DomainNameFields (offset 16, len 8) - zeros
	// WorkstationFields (offset 24, len 8) - zeros
	return msg
}

// computeNTLMv2Response computes a valid NTLMv2 response for testing.
// Returns (ntResponse, encryptedSessionKey).
func computeNTLMv2Response(username, password, domain string, serverChallenge []byte, clientFlags uint32) ([]byte, []byte) {
	a := &NTLMAuthenticator{}
	responseKeyNT := a.ntv2Hash(username, password, domain)

	// Build a minimal client blob (NTLMv2_CLIENT_CHALLENGE)
	// Blob structure:
	//   RespType (1 byte) = 0x01
	//   HiRespType (1 byte) = 0x01
	//   Reserved1 (2 bytes) = 0
	//   Reserved2 (4 bytes) = 0
	//   TimeStamp (8 bytes) - arbitrary
	//   ChallengeFromClient (8 bytes) - random
	//   Reserved3 (4 bytes) = 0
	//   AvPairs (variable) - minimal: just EOL
	clientBlob := make([]byte, 28+4) // 28 bytes header + 4 bytes for MsvAvEOL
	clientBlob[0] = 0x01             // RespType
	clientBlob[1] = 0x01             // HiRespType
	// TimeStamp at offset 8
	binary.LittleEndian.PutUint64(clientBlob[8:16], 132000000000000000) // arbitrary filetime
	// ChallengeFromClient at offset 16
	copy(clientBlob[16:24], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})
	// MsvAvEOL at offset 28 (4 bytes of zeros - avID=0, len=0)

	// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientBlob)
	h := hmac.New(md5.New, responseKeyNT)
	h.Write(serverChallenge)
	h.Write(clientBlob)
	ntProofStr := h.Sum(nil)

	// Full NT response = NTProofStr + ClientBlob
	ntResponse := append(ntProofStr, clientBlob...)

	// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
	sessionH := hmac.New(md5.New, responseKeyNT)
	sessionH.Write(ntProofStr)
	sessionBaseKey := sessionH.Sum(nil)

	// Encrypt a random session key with SessionBaseKey using RC4 (KEY_EXCH)
	randomSessionKey := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	var encryptedSessionKey []byte
	if clientFlags&ntlmFlagNegotiateKeyExch != 0 {
		cipher, _ := rc4.NewCipher(sessionBaseKey)
		encryptedSessionKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedSessionKey, randomSessionKey)
	}

	return ntResponse, encryptedSessionKey
}

// TestNewNTLMAuthenticator verifies initial state after construction.
func TestNewNTLMAuthenticator(t *testing.T) {
	users := map[string]string{"admin": "secret", "User1": "pass"}
	a := NewNTLMAuthenticator("MYSERVER", users, true)

	if a.targetName != "MYSERVER" {
		t.Errorf("targetName = %q, want %q", a.targetName, "MYSERVER")
	}
	if a.state != 0 {
		t.Errorf("state = %d, want 0", a.state)
	}
	if !a.allowGuest {
		t.Error("allowGuest should be true")
	}
	// Users should be normalized to uppercase keys
	if _, ok := a.users["ADMIN"]; !ok {
		t.Error("expected uppercase key ADMIN")
	}
	if _, ok := a.users["USER1"]; !ok {
		t.Error("expected uppercase key USER1")
	}
	if _, ok := a.users["admin"]; ok {
		t.Error("lowercase key admin should not exist")
	}
	if a.users["ADMIN"] != "secret" {
		t.Errorf("users[ADMIN] = %q, want %q", a.users["ADMIN"], "secret")
	}
}

func TestNewNTLMAuthenticator_NilUsers(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, false)
	if a.users == nil {
		t.Error("users map should be initialized (not nil)")
	}
	if len(a.users) != 0 {
		t.Errorf("users map should be empty, got %d entries", len(a.users))
	}
	if a.allowGuest {
		t.Error("allowGuest should be false")
	}
}

// TestGuestAuthFlow tests the guest authentication flow.
func TestGuestAuthFlow(t *testing.T) {
	a := NewNTLMAuthenticator("GUESTSVR", nil, true)

	// Step 1: Send Type 1 Negotiate
	type1Flags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM |
		ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateKeyExch)
	type1 := buildType1Message(type1Flags)

	result1, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}
	if result1.Success {
		t.Error("Type 1 should not succeed immediately (more processing required)")
	}
	if result1.ResponseBlob == nil {
		t.Fatal("Type 1 should return a response blob (SPNEGO-wrapped challenge)")
	}
	if a.state != 1 {
		t.Errorf("state after Type 1 = %d, want 1", a.state)
	}

	// Step 2: Send Type 3 with empty username (guest)
	type3 := buildType3Message("", "", make([]byte, 32), make([]byte, 16))
	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3 guest) error: %v", err)
	}
	if !result2.Success {
		t.Error("guest auth should succeed")
	}
	if !result2.IsGuest {
		t.Error("should be flagged as guest")
	}
}

// TestKnownUserAuthFlow tests authentication with valid credentials.
func TestKnownUserAuthFlow(t *testing.T) {
	users := map[string]string{"testuser": "testpass"}
	a := NewNTLMAuthenticator("AUTHSVR", users, false)

	// Step 1: Send Type 1 Negotiate
	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM |
		ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateKeyExch |
		ntlmFlagNegotiate128 | ntlmFlagNegotiateSign)
	type1 := buildType1Message(clientFlags)

	result1, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}
	if result1.Success {
		t.Error("Type 1 should not succeed immediately")
	}
	if result1.ResponseBlob == nil {
		t.Fatal("Type 1 should return challenge blob")
	}

	// Step 2: Compute valid NTLMv2 response and send Type 3
	ntResponse, encSessionKey := computeNTLMv2Response("testuser", "testpass", "", a.serverChallenge, clientFlags)
	type3 := buildType3Message("", "testuser", ntResponse, encSessionKey)

	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result2.Success {
		t.Error("valid user auth should succeed")
	}
	if result2.IsGuest {
		t.Error("should not be guest")
	}
	if result2.Username != "testuser" {
		t.Errorf("Username = %q, want %q", result2.Username, "testuser")
	}
	if result2.SessionKey == nil {
		t.Error("SessionKey should not be nil for authenticated user")
	}
	if a.state != 2 {
		t.Errorf("state after successful auth = %d, want 2", a.state)
	}
}

// TestKnownUserAuthFlow_CaseInsensitive verifies case-insensitive username matching.
func TestKnownUserAuthFlow_CaseInsensitive(t *testing.T) {
	users := map[string]string{"TestUser": "mypass"}
	a := NewNTLMAuthenticator("SRV", users, false)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM | ntlmFlagNegotiateKeyExch)
	type1 := buildType1Message(clientFlags)
	result1, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}
	if result1.ResponseBlob == nil {
		t.Fatal("expected challenge blob")
	}

	// Authenticate with lowercase version of username
	ntResponse, encSessionKey := computeNTLMv2Response("testuser", "mypass", "", a.serverChallenge, clientFlags)
	type3 := buildType3Message("", "testuser", ntResponse, encSessionKey)

	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result2.Success {
		t.Error("case-insensitive lookup should succeed")
	}
	if result2.IsGuest {
		t.Error("should not be guest")
	}
}

// TestUnknownUserWithGuest tests that an unknown user is treated as guest when allowGuest=true.
func TestUnknownUserWithGuest(t *testing.T) {
	users := map[string]string{"admin": "pass"}
	a := NewNTLMAuthenticator("SRV", users, true)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM)
	type1 := buildType1Message(clientFlags)
	result1, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}
	if result1.ResponseBlob == nil {
		t.Fatal("expected challenge blob")
	}

	// Send auth for unknown user "nobody"
	type3 := buildType3Message("", "nobody", make([]byte, 32), []byte{})
	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result2.Success {
		t.Error("unknown user with allowGuest=true should succeed")
	}
	if !result2.IsGuest {
		t.Error("unknown user should be flagged as guest")
	}
	if result2.Username != "nobody" {
		t.Errorf("Username = %q, want %q", result2.Username, "nobody")
	}
}

// TestUnknownUserWithoutGuest tests that an unknown user fails when allowGuest=false.
func TestUnknownUserWithoutGuest(t *testing.T) {
	users := map[string]string{"admin": "pass"}
	a := NewNTLMAuthenticator("SRV", users, false)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM)
	type1 := buildType1Message(clientFlags)
	result1, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}
	if result1.ResponseBlob == nil {
		t.Fatal("expected challenge blob")
	}

	// Send auth for unknown user "nobody"
	type3 := buildType3Message("", "nobody", make([]byte, 32), []byte{})
	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if result2.Success {
		t.Error("unknown user with allowGuest=false should fail")
	}
}

// TestGuestAuthFlow_AnonymousUsername tests that "anonymous" username is treated as guest.
func TestGuestAuthFlow_AnonymousUsername(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, true)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM)
	type1 := buildType1Message(clientFlags)
	_, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}

	type3 := buildType3Message("", "anonymous", make([]byte, 32), []byte{})
	result, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result.Success {
		t.Error("anonymous username should succeed as guest")
	}
	if !result.IsGuest {
		t.Error("anonymous should be flagged as guest")
	}
}

// TestGuestAuthFlow_GuestUsername tests that "guest" username (case-insensitive) is treated as guest.
func TestGuestAuthFlow_GuestUsername(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, true)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM)
	type1 := buildType1Message(clientFlags)
	_, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}

	type3 := buildType3Message("", "Guest", make([]byte, 32), []byte{})
	result, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result.Success || !result.IsGuest {
		t.Error("Guest username should be treated as guest")
	}
}

// TestGuestDeniedWhenDisabled tests that guest login is rejected when allowGuest=false.
func TestGuestDeniedWhenDisabled(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, false)

	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM)
	type1 := buildType1Message(clientFlags)
	_, err := a.Authenticate(type1)
	if err != nil {
		t.Fatalf("Authenticate(Type1) error: %v", err)
	}

	type3 := buildType3Message("", "", make([]byte, 32), []byte{})
	result, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if result.Success {
		t.Error("guest login should fail when allowGuest=false")
	}
}

// TestAuthenticate_NoNTLMSignature_GuestAllowed tests non-NTLM blobs with guest mode.
func TestAuthenticate_NoNTLMSignature_GuestAllowed(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, true)
	result, err := a.Authenticate([]byte("not-ntlm-data-at-all"))
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !result.Success || !result.IsGuest {
		t.Error("non-NTLM blob with allowGuest should return guest success")
	}
	if result.Username != "Guest" {
		t.Errorf("Username = %q, want %q", result.Username, "Guest")
	}
}

// TestAuthenticate_NoNTLMSignature_GuestDenied tests non-NTLM blobs without guest mode.
func TestAuthenticate_NoNTLMSignature_GuestDenied(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, false)
	result, err := a.Authenticate([]byte("not-ntlm-data-at-all"))
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if result.Success {
		t.Error("non-NTLM blob with allowGuest=false should fail")
	}
}

// TestAuthenticate_UnknownMessageType tests NTLM blob with unknown message type.
func TestAuthenticate_UnknownMessageType(t *testing.T) {
	a := NewNTLMAuthenticator("SRV", nil, false)
	msg := make([]byte, 16)
	copy(msg[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], 99) // Invalid type
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	result, err := a.Authenticate(msg)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if result.Success {
		t.Error("unknown NTLM message type should fail")
	}
}

// TestVerifyAndComputeSessionKey_ValidNTLMv2 tests the full NTLMv2 verification path.
func TestVerifyAndComputeSessionKey_ValidNTLMv2(t *testing.T) {
	a := &NTLMAuthenticator{
		serverChallenge: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		clientFlags:     ntlmFlagNegotiateKeyExch,
	}

	username := "testuser"
	password := "testpass"
	domain := "TESTDOM"

	ntResponse, encSessionKey := computeNTLMv2Response(username, password, domain, a.serverChallenge, a.clientFlags)

	sessionKey := a.verifyAndComputeSessionKey(username, password, domain, ntResponse, encSessionKey)
	if sessionKey == nil {
		t.Fatal("verifyAndComputeSessionKey returned nil for valid NTLMv2 response")
	}
	if len(sessionKey) != 16 {
		t.Errorf("session key length = %d, want 16", len(sessionKey))
	}

	// Verify the session key matches what we expect from the KEY_EXCH decryption
	// The computeNTLMv2Response helper uses a fixed random session key
	expectedSessionKey := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	if !bytes.Equal(sessionKey, expectedSessionKey) {
		t.Errorf("session key = %x, want %x", sessionKey, expectedSessionKey)
	}
}

// TestVerifyAndComputeSessionKey_NoKeyExch tests session key without KEY_EXCH flag.
func TestVerifyAndComputeSessionKey_NoKeyExch(t *testing.T) {
	a := &NTLMAuthenticator{
		serverChallenge: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		clientFlags:     0, // No KEY_EXCH
	}

	username := "user"
	password := "pass"
	domain := ""

	ntResponse, _ := computeNTLMv2Response(username, password, domain, a.serverChallenge, 0)

	sessionKey := a.verifyAndComputeSessionKey(username, password, domain, ntResponse, nil)
	if sessionKey == nil {
		t.Fatal("verifyAndComputeSessionKey returned nil")
	}
	if len(sessionKey) != 16 {
		t.Errorf("session key length = %d, want 16", len(sessionKey))
	}

	// Without KEY_EXCH, the session key should be the SessionBaseKey directly
	// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
	responseKeyNT := a.ntv2Hash(username, password, domain)
	ntProofStr := ntResponse[:16]
	h := hmac.New(md5.New, responseKeyNT)
	h.Write(ntProofStr)
	expectedSessionBaseKey := h.Sum(nil)

	if !bytes.Equal(sessionKey, expectedSessionBaseKey) {
		t.Errorf("session key = %x, want SessionBaseKey %x", sessionKey, expectedSessionBaseKey)
	}
}

// TestVerifyAndComputeSessionKey_ShortResponse tests fallback for short NT responses.
func TestVerifyAndComputeSessionKey_ShortResponse(t *testing.T) {
	a := &NTLMAuthenticator{
		serverChallenge: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		clientFlags:     0,
	}

	// Short response (< 24 bytes) triggers compatibility fallback
	shortResp := make([]byte, 16)
	sessionKey := a.verifyAndComputeSessionKey("user", "pass", "", shortResp, nil)
	if sessionKey == nil {
		t.Fatal("short response should still produce a session key (compatibility mode)")
	}
	if len(sessionKey) != 16 {
		t.Errorf("session key length = %d, want 16", len(sessionKey))
	}
}

// TestBuildChallengeMessage_MinimalFlags tests challenge message with minimal flags.
func TestBuildChallengeMessage_MinimalFlags(t *testing.T) {
	a := &NTLMAuthenticator{
		targetName:      "MIN",
		serverChallenge: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		clientFlags:     0,
	}

	msg := a.buildChallengeMessage()

	// Should still have NTLMSSP signature and type 2
	if !bytes.Equal(msg[0:8], ntlmSignature) {
		t.Error("missing NTLMSSP signature")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 2 {
		t.Error("message type != 2")
	}

	// Flags should include NTLM and TARGET_INFO (always added)
	flags := binary.LittleEndian.Uint32(msg[20:24])
	if flags&ntlmFlagNegotiateNTLM == 0 {
		t.Error("NEGOTIATE_NTLM missing from minimal flags")
	}
	if flags&ntlmFlagNegotiateTargetInfo == 0 {
		t.Error("NEGOTIATE_TARGET_INFO should always be set by buildChallengeMessage")
	}
}

// TestFullFlowWithSPNEGO tests the full flow where Type 1 is wrapped in SPNEGO.
func TestFullFlowWithSPNEGO(t *testing.T) {
	a := NewNTLMAuthenticator("SRVTEST", map[string]string{"alice": "wonderland"}, false)

	// Build Type 1 and wrap in SPNEGO
	clientFlags := uint32(ntlmFlagNegotiateUnicode | ntlmFlagNegotiateNTLM |
		ntlmFlagNegotiateExtendedSessionSec | ntlmFlagNegotiateKeyExch | ntlmFlagNegotiate128)
	type1 := buildType1Message(clientFlags)
	spnegoType1 := a.wrapInSPNEGO(type1)

	result1, err := a.Authenticate(spnegoType1)
	if err != nil {
		t.Fatalf("Authenticate(SPNEGO Type1) error: %v", err)
	}
	if result1.Success {
		t.Error("Type 1 should not succeed")
	}
	if result1.ResponseBlob == nil {
		t.Fatal("expected SPNEGO-wrapped challenge")
	}

	// Compute valid response using the server's challenge
	ntResponse, encSessionKey := computeNTLMv2Response("alice", "wonderland", "", a.serverChallenge, clientFlags)
	type3 := buildType3Message("", "alice", ntResponse, encSessionKey)

	result2, err := a.Authenticate(type3)
	if err != nil {
		t.Fatalf("Authenticate(Type3) error: %v", err)
	}
	if !result2.Success {
		t.Error("valid user authentication should succeed")
	}
	if result2.IsGuest {
		t.Error("should not be guest")
	}
	if result2.SessionKey == nil {
		t.Error("session key should not be nil")
	}
}
