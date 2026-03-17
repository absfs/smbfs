package smbfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// MechType identifies the authentication mechanism in a SPNEGO token.
type MechType int

const (
	MechUnknown    MechType = iota
	MechKerberos            // OID 1.2.840.113554.1.2.2
	MechMSKerberos          // OID 1.2.840.48018.1.2.2
	MechNTLM                // OID 1.3.6.1.4.1.311.2.2.10
)

// SPNEGO negState values for NegTokenResp.
const (
	NegStateAcceptCompleted  byte = 0x00
	NegStateAcceptIncomplete byte = 0x01
	NegStateReject           byte = 0x02
)

// DER-encoded OIDs used in SPNEGO negotiation.
//
// Note: oidKerberos, oidMSKerberos, oidKerberosRaw, and oidMSKerberosRaw are
// declared in auth_kerberos.go and shared across the package.
var (
	// oidSPNEGO is the SPNEGO mechanism OID (1.3.6.1.5.5.2) with tag+length prefix.
	oidSPNEGO = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// oidNTLM is NTLMSSP (1.3.6.1.4.1.311.2.2.10) with tag+length prefix.
	oidNTLM = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// oidNTLMRaw is the OID bytes without the tag/length prefix (1.3.6.1.4.1.311.2.2.10).
	oidNTLMRaw = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

// asn1ReadTagAndLength reads an ASN.1 tag and length from data, returning the
// tag byte, content length, and total header bytes consumed.
func asn1ReadTagAndLength(data []byte) (tag byte, length int, headerLen int, err error) {
	if len(data) < 2 {
		return 0, 0, 0, fmt.Errorf("spnego: data too short for ASN.1 TLV (need >=2, got %d)", len(data))
	}

	tag = data[0]
	b := data[1]

	if b < 0x80 {
		// Short form: length is the byte itself.
		return tag, int(b), 2, nil
	}

	if b == 0x81 {
		// Long form, 1 byte length.
		if len(data) < 3 {
			return 0, 0, 0, fmt.Errorf("spnego: data too short for 0x81 length form (need >=3, got %d)", len(data))
		}
		return tag, int(data[2]), 3, nil
	}

	if b == 0x82 {
		// Long form, 2 byte length.
		if len(data) < 4 {
			return 0, 0, 0, fmt.Errorf("spnego: data too short for 0x82 length form (need >=4, got %d)", len(data))
		}
		return tag, int(binary.BigEndian.Uint16(data[2:4])), 4, nil
	}

	return 0, 0, 0, fmt.Errorf("spnego: unsupported ASN.1 length encoding 0x%02x", b)
}

// spnegoWrap wraps data with an ASN.1 tag and length. This is the standalone
// equivalent of NTLMAuthenticator.asn1Wrap.
func spnegoWrap(tag byte, data []byte) []byte {
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
	binary.BigEndian.PutUint16(result[2:4], uint16(length))
	copy(result[4:], data)
	return result
}

// identifyMechOID identifies the MechType from a DER-encoded OID (with tag+length).
func identifyMechOID(oid []byte) MechType {
	if bytes.Equal(oid, oidKerberos) {
		return MechKerberos
	}
	if bytes.Equal(oid, oidMSKerberos) {
		return MechMSKerberos
	}
	if bytes.Equal(oid, oidNTLM) {
		return MechNTLM
	}
	return MechUnknown
}

// ParseSPNEGOInit parses a SPNEGO NegTokenInit and returns the preferred
// mechanism type and the mechanism token (AP-REQ for Kerberos, NTLM message
// for NTLM). Returns MechUnknown if the blob is not valid SPNEGO.
func ParseSPNEGOInit(blob []byte) (MechType, []byte, error) {
	if len(blob) == 0 {
		return MechUnknown, nil, fmt.Errorf("spnego: empty blob")
	}

	pos := 0

	// 1. Skip APPLICATION [0] (tag 0x60).
	tag, contentLen, hdrLen, err := asn1ReadTagAndLength(blob[pos:])
	if err != nil {
		return MechUnknown, nil, fmt.Errorf("spnego: reading outer APPLICATION: %w", err)
	}
	if tag != 0x60 {
		return MechUnknown, nil, fmt.Errorf("spnego: expected APPLICATION [0] (0x60), got 0x%02x", tag)
	}
	pos += hdrLen
	outerEnd := pos + contentLen
	if outerEnd > len(blob) {
		return MechUnknown, nil, fmt.Errorf("spnego: APPLICATION [0] length exceeds blob")
	}

	// 2. Skip the SPNEGO OID.
	if pos+len(oidSPNEGO) > outerEnd {
		return MechUnknown, nil, fmt.Errorf("spnego: too short for SPNEGO OID")
	}
	if !bytes.Equal(blob[pos:pos+len(oidSPNEGO)], oidSPNEGO) {
		return MechUnknown, nil, fmt.Errorf("spnego: expected SPNEGO OID at offset %d", pos)
	}
	pos += len(oidSPNEGO)

	// 3. Enter context [0] (0xa0) — NegotiationToken CHOICE [0] = NegTokenInit.
	tag, contentLen, hdrLen, err = asn1ReadTagAndLength(blob[pos:])
	if err != nil {
		return MechUnknown, nil, fmt.Errorf("spnego: reading context [0]: %w", err)
	}
	if tag != 0xa0 {
		return MechUnknown, nil, fmt.Errorf("spnego: expected context [0] (0xa0), got 0x%02x", tag)
	}
	pos += hdrLen
	_ = pos + contentLen // end of context [0]

	// 4. Enter SEQUENCE (0x30).
	tag, contentLen, hdrLen, err = asn1ReadTagAndLength(blob[pos:])
	if err != nil {
		return MechUnknown, nil, fmt.Errorf("spnego: reading NegTokenInit SEQUENCE: %w", err)
	}
	if tag != 0x30 {
		return MechUnknown, nil, fmt.Errorf("spnego: expected SEQUENCE (0x30), got 0x%02x", tag)
	}
	pos += hdrLen
	seqEnd := pos + contentLen
	if seqEnd > len(blob) {
		return MechUnknown, nil, fmt.Errorf("spnego: SEQUENCE length exceeds blob")
	}

	// 5. Walk through the SEQUENCE fields looking for context tags.
	var preferredMech MechType
	var mechToken []byte

	for pos < seqEnd {
		tag, contentLen, hdrLen, err = asn1ReadTagAndLength(blob[pos:])
		if err != nil {
			return MechUnknown, nil, fmt.Errorf("spnego: reading field at offset %d: %w", pos, err)
		}
		fieldStart := pos + hdrLen
		fieldEnd := fieldStart + contentLen
		if fieldEnd > seqEnd {
			return MechUnknown, nil, fmt.Errorf("spnego: field at offset %d exceeds SEQUENCE", pos)
		}

		switch tag {
		case 0xa0:
			// Context [0]: mechTypes — SEQUENCE of OIDs.
			preferredMech = parseMechTypes(blob[fieldStart:fieldEnd])

		case 0xa2:
			// Context [2]: mechToken — OCTET STRING.
			// The mechToken may be wrapped in an OCTET STRING (0x04) tag.
			mechToken = extractOctetString(blob[fieldStart:fieldEnd])
		}

		pos = fieldEnd
	}

	return preferredMech, mechToken, nil
}

// parseMechTypes parses the mechTypes SEQUENCE of OIDs and returns the
// preferred (first recognized) mechanism.
func parseMechTypes(data []byte) MechType {
	if len(data) < 2 {
		return MechUnknown
	}

	// Expect a SEQUENCE (0x30) wrapping the OIDs.
	tag, contentLen, hdrLen, err := asn1ReadTagAndLength(data)
	if err != nil || tag != 0x30 {
		return MechUnknown
	}

	pos := hdrLen
	end := hdrLen + contentLen
	if end > len(data) {
		return MechUnknown
	}

	preferred := MechUnknown
	for pos < end {
		tag, oidLen, oidHdrLen, err := asn1ReadTagAndLength(data[pos:])
		if err != nil || tag != 0x06 {
			break
		}
		oidEnd := pos + oidHdrLen + oidLen
		if oidEnd > end {
			break
		}

		// Match the full TLV (tag + length + value).
		fullOID := data[pos:oidEnd]
		mech := identifyMechOID(fullOID)
		if mech != MechUnknown && preferred == MechUnknown {
			preferred = mech
		}

		pos = oidEnd
	}

	return preferred
}

// extractOctetString extracts the value from an ASN.1 OCTET STRING (0x04).
// If the data doesn't start with 0x04, returns it as-is (the caller already
// stripped the context tag).
func extractOctetString(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	tag, contentLen, hdrLen, err := asn1ReadTagAndLength(data)
	if err != nil || tag != 0x04 {
		return data
	}
	end := hdrLen + contentLen
	if end > len(data) {
		return data
	}
	return data[hdrLen:end]
}

// ParseSPNEGOResponse parses a SPNEGO NegTokenResp (used for NTLM Type 3 in
// multi-stage auth). Returns the mechanism token (responseToken).
func ParseSPNEGOResponse(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("spnego: empty blob")
	}

	pos := 0

	// NegTokenResp starts with context [1] (0xa1).
	tag, contentLen, hdrLen, err := asn1ReadTagAndLength(blob[pos:])
	if err != nil {
		return nil, fmt.Errorf("spnego: reading outer tag: %w", err)
	}
	if tag != 0xa1 {
		return nil, fmt.Errorf("spnego: expected context [1] (0xa1), got 0x%02x", tag)
	}
	pos += hdrLen
	outerEnd := pos + contentLen
	if outerEnd > len(blob) {
		return nil, fmt.Errorf("spnego: NegTokenResp length exceeds blob")
	}

	// Enter SEQUENCE (0x30).
	tag, contentLen, hdrLen, err = asn1ReadTagAndLength(blob[pos:])
	if err != nil {
		return nil, fmt.Errorf("spnego: reading SEQUENCE: %w", err)
	}
	if tag != 0x30 {
		return nil, fmt.Errorf("spnego: expected SEQUENCE (0x30), got 0x%02x", tag)
	}
	pos += hdrLen
	seqEnd := pos + contentLen
	if seqEnd > outerEnd {
		return nil, fmt.Errorf("spnego: SEQUENCE length exceeds NegTokenResp")
	}

	// Walk through fields looking for context [2] (responseToken).
	for pos < seqEnd {
		tag, contentLen, hdrLen, err = asn1ReadTagAndLength(blob[pos:])
		if err != nil {
			return nil, fmt.Errorf("spnego: reading field at offset %d: %w", pos, err)
		}
		fieldStart := pos + hdrLen
		fieldEnd := fieldStart + contentLen
		if fieldEnd > seqEnd {
			return nil, fmt.Errorf("spnego: field at offset %d exceeds SEQUENCE", pos)
		}

		if tag == 0xa2 {
			// Context [2]: responseToken — extract from OCTET STRING.
			return extractOctetString(blob[fieldStart:fieldEnd]), nil
		}

		pos = fieldEnd
	}

	return nil, fmt.Errorf("spnego: no responseToken (context [2]) found in NegTokenResp")
}

// BuildSPNEGOResponse builds a SPNEGO NegTokenResp with the given state and
// response token. Used for both challenge (accept-incomplete) and final accept
// (accept-completed) responses.
//
// negState: NegStateAcceptCompleted (0x00), NegStateAcceptIncomplete (0x01),
//
//	or NegStateReject (0x02).
//
// mechOID: raw OID bytes (without 0x06 tag+length) for the supportedMech
//
//	field. Pass nil to omit the supportedMech field.
//
// responseToken: the authentication token to include. Pass nil to omit.
func BuildSPNEGOResponse(negState byte, mechOID []byte, responseToken []byte) []byte {
	// negState = [0] { ENUMERATED { value } }
	negStateField := spnegoWrap(0xa0, []byte{0x0a, 0x01, negState})

	content := make([]byte, 0, len(negStateField)+64)
	content = append(content, negStateField...)

	// supportedMech = [1] { OID }
	if mechOID != nil {
		supportedMech := spnegoWrap(0xa1, spnegoWrap(0x06, mechOID))
		content = append(content, supportedMech...)
	}

	// responseToken = [2] { OCTET STRING { token } }
	if responseToken != nil {
		respField := spnegoWrap(0xa2, spnegoWrap(0x04, responseToken))
		content = append(content, respField...)
	}

	// Wrap in SEQUENCE then context [1].
	return spnegoWrap(0xa1, spnegoWrap(0x30, content))
}

// MechOIDForType returns the raw OID bytes (without tag+length) for a given
// MechType. Returns nil for MechUnknown.
func MechOIDForType(m MechType) []byte {
	switch m {
	case MechKerberos:
		return oidKerberos[2:] // skip 0x06 + length byte
	case MechMSKerberos:
		return oidMSKerberos[2:] // skip 0x06 + length byte
	case MechNTLM:
		return oidNTLMRaw
	default:
		return nil
	}
}
