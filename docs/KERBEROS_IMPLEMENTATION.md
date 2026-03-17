# Kerberos Authentication Implementation Plan

## Problem

Windows 11 24H2 deprecated NTLM for SMB connections to non-AD servers. The native Windows SMB client rejects our NTLM Type 2 challenge at the SSPI layer with `SEC_E_INVALID_PARAMETER`, regardless of registry settings. Every SMB server that works with Windows 11 24H2 (Samba 4, Windows Server, updated NAS firmware) uses Kerberos.

## Goal

Add Kerberos authentication via SPNEGO to the smbfs server so that Windows 11 24H2 native SMB client can connect. NTLM remains as a fallback for older clients.

## Background

### Current Auth Architecture

The `Authenticator` interface (auth_guest.go) is already designed for pluggable auth:

```go
type Authenticator interface {
    Authenticate(securityBlob []byte) (*AuthResult, error)
}

type AuthResult struct {
    Success      bool
    IsGuest      bool
    Username     string
    Domain       string
    SessionKey   []byte    // Fed to DeriveSigningKey() for SMB signing
    ResponseBlob []byte    // Non-nil triggers STATUS_MORE_PROCESSING_REQUIRED
}
```

Session setup (smb2_session.go) creates an authenticator per session and calls `Authenticate()` with the SPNEGO security blob from each SESSION_SETUP request. The session key from `AuthResult` feeds directly into `DeriveSigningKey()` for signing — this path is auth-mechanism-agnostic and already works for Kerberos.

### Kerberos vs NTLM

| Aspect | NTLM | Kerberos |
|--------|------|----------|
| Roundtrips | 3 (negotiate, challenge, authenticate) | 1 (AP-REQ → AP-REP) |
| Server needs | User passwords | Keytab file |
| Session key | Derived from password hash | From service ticket |
| External dependency | None | KDC (Key Distribution Center) |

### SPNEGO Mechanism Selection

SPNEGO (RFC 4178) wraps the actual auth mechanism. The client sends a NegTokenInit listing supported mechanisms by OID. Our server currently only handles NTLM. With Kerberos support:

- **Kerberos OID**: `1.2.840.113554.1.2.2`
- **MS Kerberos OID**: `1.2.840.48018.1.2.2`
- **NTLM OID**: `1.3.6.1.4.1.311.2.2.10`

Windows sends Kerberos first in the preference list. If the server can't handle it, the client falls back to NTLM (which 24H2 then blocks).

## Implementation

### Dependencies

- `github.com/jcmturner/gokrb5/v8` — Go Kerberos library (v8.4.4)
  - `keytab` — Load keytab files
  - `service` — Server-side AP-REQ verification
  - `messages` — AP-REQ/AP-REP message types
  - `credentials` — Extracted client identity
  - `crypto` — Session key extraction

### Phase 1: KerberosAuthenticator

**New file: `auth_kerberos.go`**

```go
type KerberosAuthenticator struct {
    keytab   *keytab.Keytab
    settings *service.Settings
    spn      string
    logger   ServerLogger
}

func NewKerberosAuthenticator(keytabPath, spn string, logger ServerLogger) (*KerberosAuthenticator, error)

func (a *KerberosAuthenticator) Authenticate(securityBlob []byte) (*AuthResult, error)
```

The `Authenticate` method:
1. Parse SPNEGO NegTokenInit from `securityBlob`
2. Check if mechanism list includes Kerberos OID
3. Extract AP-REQ from MechToken field
4. Call `service.VerifyAPREQ(apReq, a.settings)` to validate against keytab
5. Extract session key from the decrypted ticket
6. Extract username and realm from the client credentials
7. Return `AuthResult{Success: true, SessionKey: sessionKey, Username: principal}`

If the SPNEGO token contains NTLM instead of Kerberos, return an error so the session setup handler can fall back to the NTLM authenticator.

### Phase 2: SPNEGO Negotiation Enhancement

**Modify: `auth_ntlm.go`** (extract SPNEGO parsing to shared code)

Create shared SPNEGO parsing utilities:

```go
// spnego.go (new file)

// MechType identifies the authentication mechanism in a SPNEGO token
type MechType int
const (
    MechUnknown  MechType = iota
    MechKerberos
    MechNTLM
)

// ParseSPNEGOInit parses a NegTokenInit and returns the preferred mechanism
// and the mechanism token (AP-REQ for Kerberos, Type 1/3 for NTLM)
func ParseSPNEGOInit(blob []byte) (MechType, []byte, error)

// BuildSPNEGOAccept builds a NegTokenResp for successful auth
// mechOID is the selected mechanism, responseToken is AP-REP or NTLM challenge
func BuildSPNEGOAccept(mechOID []byte, responseToken []byte) []byte

// BuildSPNEGOChallenge builds a NegTokenResp for STATUS_MORE_PROCESSING_REQUIRED
func BuildSPNEGOChallenge(mechOID []byte, responseToken []byte) []byte
```

This replaces the inline SPNEGO handling in `auth_ntlm.go` (`extractNTLMFromSPNEGO`, `wrapInSPNEGO`) with a shared implementation that both Kerberos and NTLM authenticators use.

### Phase 3: Session Setup Authenticator Selection

**Modify: `smb2_session.go`** (lines 98-111)

Currently hardcoded to create `NTLMAuthenticator`. Change to:

```go
// Create authenticator based on security blob mechanism
if session.Authenticator != nil {
    authenticator = session.Authenticator
} else {
    mechType, _, _ := ParseSPNEGOInit(securityBlob)
    switch mechType {
    case MechKerberos:
        if h.server.kerberosAuth != nil {
            authenticator = h.server.kerberosAuth
        } else {
            // Kerberos not configured, reject so client falls back
            return h.buildErrorResponse(), STATUS_LOGON_FAILURE
        }
    default:
        authenticator = NewNTLMAuthenticator(
            h.server.options.ServerName,
            h.server.options.Users,
            h.server.options.AllowGuest,
        )
    }
    session.Authenticator = authenticator
}
```

**Note**: Unlike NTLM (which needs per-session state for the 3-message exchange), Kerberos authentication is stateless on the server — a single `KerberosAuthenticator` instance can be shared across all sessions. It gets created once at server startup when a keytab is configured.

### Phase 4: Server Configuration

**Modify: `server_config.go`**

Add to `ServerOptions`:
```go
type ServerOptions struct {
    // ... existing fields ...

    // Kerberos authentication
    KeytabPath       string // Path to Kerberos keytab file
    ServicePrincipal string // SPN, e.g. "cifs/server.example.com@EXAMPLE.COM"
}
```

**Modify: `server.go`** (in `NewServer`)

```go
// Initialize Kerberos authenticator if keytab provided
if opts.KeytabPath != "" {
    kt, err := keytab.Load(opts.KeytabPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load keytab: %w", err)
    }
    kauth, err := NewKerberosAuthenticator(kt, opts.ServicePrincipal, logger)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize Kerberos: %w", err)
    }
    s.kerberosAuth = kauth
    logger.Info("Kerberos authentication enabled (SPN: %s)", opts.ServicePrincipal)
}
```

### Phase 5: Testing

**New file: `auth_kerberos_test.go`**

1. **Unit tests** (no KDC needed):
   - `TestKerberosAuthenticator_InvalidSPNEGO` — non-SPNEGO blob
   - `TestKerberosAuthenticator_NTLMBlob` — NTLM inside SPNEGO returns error (forces fallback)
   - `TestKerberosAuthenticator_MalformedAPREQ` — garbage inside Kerberos wrapper
   - `TestNewKerberosAuthenticator_InvalidKeytab` — bad keytab path
   - `TestNewKerberosAuthenticator_ValidKeytab` — load test keytab

2. **Integration tests** (with test keytab + gokrb5 client):
   - Generate a test keytab and ticket using gokrb5's test utilities
   - Construct a valid AP-REQ programmatically
   - Wrap in SPNEGO, send through Authenticate(), verify success
   - Verify session key extraction
   - Verify username/realm extraction

3. **SPNEGO tests**:
   - `TestParseSPNEGOInit_Kerberos` — blob with Kerberos OID
   - `TestParseSPNEGOInit_NTLM` — blob with NTLM OID
   - `TestParseSPNEGOInit_Both` — blob with both OIDs, verify Kerberos preferred
   - `TestBuildSPNEGOAccept` — verify correct ASN.1 encoding

4. **Full protocol flow test**:
   - Create server with keytab
   - Build NEGOTIATE → SESSION_SETUP(Kerberos AP-REQ) → TREE_CONNECT sequence
   - Verify signing works with Kerberos-derived session key

## Deployment Requirements

### KDC Setup

For non-AD environments, a standalone MIT Kerberos KDC is needed:

```bash
# On the KDC machine (e.g., Ash VM or Mac):
# 1. Install Kerberos
brew install krb5          # macOS
apt install krb5-kdc       # Linux

# 2. Create realm
kdb5_util create -s -r HOME.LOCAL

# 3. Add admin principal
kadmin.local -q "addprinc admin/admin@HOME.LOCAL"

# 4. Add SMB server principal
kadmin.local -q "addprinc -randkey cifs/fileserver.home.local@HOME.LOCAL"

# 5. Export keytab for SMB server
kadmin.local -q "ktadd -k /etc/smbfs.keytab cifs/fileserver.home.local@HOME.LOCAL"
```

### Windows Client Configuration

```powershell
# Add KDC mapping for the realm
ksetup /addkdc HOME.LOCAL kdc.home.local

# Map realm to DNS suffix
ksetup /addhosttorealmmap fileserver.home.local HOME.LOCAL

# Or via krb5.ini at %WINDIR%\krb5.ini:
# [libdefaults]
#   default_realm = HOME.LOCAL
# [realms]
#   HOME.LOCAL = { kdc = kdc.home.local }
# [domain_realm]
#   .home.local = HOME.LOCAL
```

### SMB Server Startup

```go
server, _ := smbfs.NewServer(smbfs.ServerOptions{
    Port:             445,
    ServerName:       "FILESERVER",
    KeytabPath:       "/etc/smbfs.keytab",
    ServicePrincipal: "cifs/fileserver.home.local@HOME.LOCAL",
    AllowGuest:       true,  // Fallback for non-Kerberos clients
})
server.AddShare(myFS, smbfs.ShareOptions{ShareName: "data"})
server.ListenAndServe()
```

## Files Modified/Created

| File | Action | Description |
|------|--------|-------------|
| `auth_kerberos.go` | Create | KerberosAuthenticator implementation |
| `auth_kerberos_test.go` | Create | Kerberos auth tests |
| `spnego.go` | Create | Shared SPNEGO parsing/building |
| `spnego_test.go` | Create | SPNEGO tests |
| `smb2_session.go` | Modify | Authenticator selection based on mechanism |
| `server_config.go` | Modify | Add KeytabPath, ServicePrincipal options |
| `server.go` | Modify | Initialize KerberosAuthenticator at startup |
| `auth_ntlm.go` | Modify | Use shared SPNEGO functions |
| `go.mod` | Modify | Add gokrb5/v8 dependency |

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| KDC requirement adds operational complexity | Document setup thoroughly; guest/NTLM fallback still works for Go clients |
| Clock skew between KDC, server, and client | gokrb5 default 5-minute tolerance; document NTP requirement |
| SPN must match DNS exactly | Document hostname requirements; add diagnostic logging |
| gokrb5 dependency is large | Only imported when keytab is configured; tree-shaken in builds |
| Windows local accounts (non-domain) may not get tickets | Document that domain join or explicit `ksetup` is needed |

## Release Plan

**No release until Kerberos lands.** The current v0.9.1 tag is the last release.

- **v0.10.0**: Tag after Kerberos auth is implemented and tested with Windows 11 24H2.
  This is the "server release" — working SMB server with Kerberos + NTLM + Guest auth,
  Windows native client support, 90%+ test coverage, and a stable server API surface.
- **Pre-release**: Fix `go 1.23` directive in go.mod — CI passes on Go 1.21+, so the
  directive should be lowered to `go 1.21` before release to avoid excluding consumers.
- **No v0.9.2**: The server API (`ServerOptions`, `Server`, etc.) will change with
  Kerberos (`KeytabPath`, `ServicePrincipal` fields). Releasing now would create a
  throwaway API version.

## Out of Scope

- **PKU2U / NEGOEX**: Certificate-based peer auth without KDC. Much harder, less documented.
- **SMB over QUIC**: UDP transport with TLS cert auth. Different protocol layer entirely.
- **Active Directory integration**: PAC validation, group policy, constrained delegation.
- **Encryption (SMB 3.x)**: Session encryption beyond signing. Separate feature.
