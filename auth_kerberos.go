package smbfs

import (
	"bytes"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
)

// Well-known Kerberos OIDs in DER-encoded form
var (
	// oidKerberos is 1.2.840.113554.1.2.2 (standard Kerberos 5)
	oidKerberos = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// oidMSKerberos is 1.2.840.48018.1.2.2 (Microsoft Kerberos)
	oidMSKerberos = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// oidKerberosRaw is the OID bytes without the tag/length prefix (1.2.840.113554.1.2.2)
	oidKerberosRaw = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// oidMSKerberosRaw is the OID bytes without the tag/length prefix (1.2.840.48018.1.2.2)
	oidMSKerberosRaw = []byte{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}
)

// KerberosAuthenticator implements Kerberos authentication for SMB via SPNEGO.
// Unlike NTLMAuthenticator, Kerberos auth is stateless on the server side:
// a single AP-REQ from the client is validated against the keytab in one step.
// One KerberosAuthenticator instance can be shared across all sessions.
type KerberosAuthenticator struct {
	keytab   *keytab.Keytab
	settings *service.Settings
	spn      string
	logger   ServerLogger
}

// NewKerberosAuthenticator creates a new Kerberos authenticator.
// kt is the keytab containing the service principal's key(s).
// spn is the service principal name (e.g., "cifs/server.example.com").
// logger is used for debug/warning output; if nil, a NullLogger is used.
func NewKerberosAuthenticator(kt *keytab.Keytab, spn string, logger ServerLogger) (*KerberosAuthenticator, error) {
	if kt == nil {
		return nil, fmt.Errorf("kerberos: keytab must not be nil")
	}
	if spn == "" {
		return nil, fmt.Errorf("kerberos: service principal name must not be empty")
	}
	if logger == nil {
		logger = &NullLogger{}
	}

	settings := service.NewSettings(kt, service.KeytabPrincipal(spn))

	return &KerberosAuthenticator{
		keytab:   kt,
		settings: settings,
		spn:      spn,
		logger:   logger,
	}, nil
}

// Authenticate processes a Kerberos authentication request wrapped in SPNEGO.
// It extracts the AP-REQ from the SPNEGO blob, verifies it against the keytab,
// and returns the session key and client identity on success.
//
// If the blob contains NTLM instead of Kerberos, an error is returned so the
// session setup handler can fall back to the NTLM authenticator.
func (a *KerberosAuthenticator) Authenticate(securityBlob []byte) (*AuthResult, error) {
	if len(securityBlob) == 0 {
		a.logger.Warn("Kerberos: received empty security blob")
		return nil, fmt.Errorf("kerberos: empty security blob")
	}

	a.logger.Debug("Kerberos: Authenticate called, blobLen=%d", len(securityBlob))

	// Extract the AP-REQ from the SPNEGO wrapper
	apReqBytes, err := a.extractAPReqFromSPNEGO(securityBlob)
	if err != nil {
		a.logger.Debug("Kerberos: failed to extract AP-REQ: %v", err)
		return nil, fmt.Errorf("kerberos: %w", err)
	}

	a.logger.Debug("Kerberos: extracted AP-REQ, len=%d", len(apReqBytes))

	// Parse the AP-REQ message
	var apReq messages.APReq
	if err := apReq.Unmarshal(apReqBytes); err != nil {
		a.logger.Warn("Kerberos: failed to unmarshal AP-REQ: %v", err)
		return nil, fmt.Errorf("kerberos: failed to parse AP-REQ: %w", err)
	}

	// Verify the AP-REQ against our keytab
	ok, creds, err := service.VerifyAPREQ(&apReq, a.settings)
	if err != nil {
		a.logger.Warn("Kerberos: AP-REQ verification error: %v", err)
		return &AuthResult{Success: false}, fmt.Errorf("kerberos: verification failed: %w", err)
	}
	if !ok {
		a.logger.Warn("Kerberos: AP-REQ verification returned false")
		return &AuthResult{Success: false}, fmt.Errorf("kerberos: ticket verification failed")
	}

	// Extract the session key from the decrypted ticket
	sessionKey := apReq.Ticket.DecryptedEncPart.Key.KeyValue
	if len(sessionKey) == 0 {
		a.logger.Warn("Kerberos: no session key in decrypted ticket")
		return &AuthResult{Success: false}, fmt.Errorf("kerberos: no session key in ticket")
	}

	// Extract username and realm from the verified credentials
	username := creds.UserName()
	domain := creds.Domain()

	a.logger.Debug("Kerberos: authentication successful, user=%s, domain=%s, sessionKeyLen=%d",
		username, domain, len(sessionKey))

	return &AuthResult{
		Success:      true,
		IsGuest:      false,
		Username:     username,
		Domain:       domain,
		SessionKey:   sessionKey,
		ResponseBlob: nil, // AP-REP not required for SMB; most clients don't expect it
	}, nil
}

// extractAPReqFromSPNEGO extracts the Kerberos AP-REQ from a SPNEGO NegTokenInit blob.
// Returns the raw AP-REQ bytes, or error if not found/not Kerberos.
func (a *KerberosAuthenticator) extractAPReqFromSPNEGO(blob []byte) ([]byte, error) {
	if len(blob) < 2 {
		return nil, fmt.Errorf("blob too short (%d bytes)", len(blob))
	}

	// Check if this contains an NTLM token (reject early for clear error)
	if containsNTLMSignature(blob) {
		return nil, fmt.Errorf("blob contains NTLM token, not Kerberos")
	}

	// Strategy 1: Look for Kerberos OID in the SPNEGO blob and extract the mech token.
	// SPNEGO NegTokenInit wraps the AP-REQ as the mechToken field.
	// We look for the Kerberos OID to confirm this is a Kerberos token,
	// then extract the AP-REQ from the mechToken.
	if apReq := a.extractMechTokenFromSPNEGO(blob); apReq != nil {
		return apReq, nil
	}

	// Strategy 2: Try to interpret the entire blob as an AP-REQ directly
	// (for clients that send raw Kerberos tokens without SPNEGO wrapping)
	if isAPReq(blob) {
		return blob, nil
	}

	return nil, fmt.Errorf("no Kerberos AP-REQ found in blob")
}

// extractMechTokenFromSPNEGO performs a simplified parse of the SPNEGO NegTokenInit
// ASN.1 structure to extract the mechToken field containing the AP-REQ.
//
// SPNEGO NegTokenInit structure (RFC 4178):
//
//	NegTokenInit ::= SEQUENCE {
//	    mechTypes       [0] MechTypeList,
//	    reqFlags        [1] ContextFlags OPTIONAL,
//	    mechToken       [2] OCTET STRING OPTIONAL,  <-- this is the AP-REQ
//	    mechListMIC     [3] OCTET STRING OPTIONAL,
//	}
func (a *KerberosAuthenticator) extractMechTokenFromSPNEGO(blob []byte) []byte {
	// Verify that a Kerberos OID is present in the blob
	if !bytes.Contains(blob, oidKerberosRaw) && !bytes.Contains(blob, oidMSKerberosRaw) {
		return nil
	}

	// Walk the ASN.1 structure looking for the mechToken field [2]
	// The SPNEGO wrapper starts with either:
	//   - Application tag [0] (0x60) for the initial NegotiateToken
	//   - Context tag [0] (0xa0) for NegTokenInit within the wrapper
	pos := 0

	// Skip the outermost GSS-API wrapper (Application 0 = 0x60)
	if pos < len(blob) && blob[pos] == 0x60 {
		pos++ // skip tag
		_, consumed := readASN1Length(blob[pos:])
		pos += consumed
		// Skip the SPNEGO OID (1.3.6.1.5.5.2) if present
		if pos < len(blob) && blob[pos] == 0x06 {
			oidLen, consumed := readASN1Length(blob[pos+1:])
			pos += 1 + consumed + oidLen
		}
	}

	// Now we should be at the NegTokenInit context tag [0] (0xa0)
	if pos < len(blob) && blob[pos] == 0xa0 {
		pos++ // skip tag
		_, consumed := readASN1Length(blob[pos:])
		pos += consumed
	}

	// Should be at SEQUENCE (0x30) for the NegTokenInit content
	if pos < len(blob) && blob[pos] == 0x30 {
		pos++ // skip tag
		seqLen, consumed := readASN1Length(blob[pos:])
		pos += consumed
		seqEnd := pos + seqLen
		if seqEnd > len(blob) {
			seqEnd = len(blob)
		}

		// Walk through the context-tagged fields
		for pos < seqEnd {
			if pos >= len(blob) {
				break
			}
			tag := blob[pos]
			pos++ // skip tag
			fieldLen, consumed := readASN1Length(blob[pos:])
			pos += consumed

			if pos+fieldLen > len(blob) {
				break
			}

			// Context tag [2] = mechToken (0xa2)
			if tag == 0xa2 {
				// The mechToken is an OCTET STRING inside this context tag
				fieldData := blob[pos : pos+fieldLen]
				if len(fieldData) > 2 && fieldData[0] == 0x04 {
					// Strip the OCTET STRING tag and length
					octetLen, consumed := readASN1Length(fieldData[1:])
					innerStart := 1 + consumed
					if innerStart+octetLen <= len(fieldData) {
						return fieldData[innerStart : innerStart+octetLen]
					}
				}
				// If no OCTET STRING wrapper, return the raw field data
				return fieldData
			}

			pos += fieldLen
		}
	}

	return nil
}

// readASN1Length reads a DER-encoded length and returns (length, bytes consumed).
func readASN1Length(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(data) < 1+numBytes {
		return 0, 1
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

// containsNTLMSignature checks if the blob contains the "NTLMSSP\0" signature
// anywhere in the first 256 bytes (covering SPNEGO-wrapped NTLM tokens).
func containsNTLMSignature(blob []byte) bool {
	limit := len(blob)
	if limit > 256 {
		limit = 256
	}
	return bytes.Contains(blob[:limit], []byte("NTLMSSP\x00"))
}

// isAPReq checks if the blob looks like a Kerberos AP-REQ message.
// AP-REQ starts with ASN.1 Application tag 14 (0x6e).
func isAPReq(blob []byte) bool {
	if len(blob) < 2 {
		return false
	}
	// AP-REQ is Application 14, which is 0x6e in DER
	return blob[0] == 0x6e
}

// NewKerberosAuthenticatorFromFile creates a KerberosAuthenticator by loading
// a keytab from the given file path. This is the typical entry point used
// by server initialization when KeytabPath is configured.
func NewKerberosAuthenticatorFromFile(keytabPath, spn string, logger ServerLogger) (*KerberosAuthenticator, error) {
	if keytabPath == "" {
		return nil, fmt.Errorf("kerberos: keytab path must not be empty")
	}
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("kerberos: failed to load keytab %q: %w", keytabPath, err)
	}
	return NewKerberosAuthenticator(kt, spn, logger)
}

// isKerberosBlob checks whether an SPNEGO security blob contains a Kerberos
// mechanism token (as opposed to NTLM). This is used by session setup to
// select the appropriate authenticator before the first Authenticate call.
func isKerberosBlob(blob []byte) bool {
	if len(blob) < 10 {
		return false
	}
	// Check for Kerberos OID presence (standard or Microsoft variant)
	if bytes.Contains(blob, oidKerberosRaw) || bytes.Contains(blob, oidMSKerberosRaw) {
		// Make sure it's not also an NTLM blob (some blobs list both OIDs
		// but carry an NTLM token — the mechToken determines the actual mech)
		if !containsNTLMSignature(blob) {
			return true
		}
	}
	// Also match raw AP-REQ (no SPNEGO wrapper)
	return isAPReq(blob)
}
