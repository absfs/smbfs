# Windows 11 24H2 SMB Compatibility Investigation

This document tracks the investigation into Windows 11 24H2 native SMB client compatibility issues with the smbfs SMB server implementation.

## Executive Summary (Last Updated: December 2025)

**Status**: Windows 11 24H2 native SMB client disconnects after NTLM Type 2 Challenge. Go clients work fine.

**Root Cause**: Unknown. Microsoft has removed NTLMv1 from Windows 11 24H2 and is phasing out NTLMv2. Many users report similar issues with NAS devices.

**Key Finding**: The `MSV1_0` registry key at `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` controls NTLM behavior. If this key is MISSING, NTLM defaults to "deny" on Windows 11 24H2.

**Reference Implementations**: Three working SMB servers have been cloned to `reference/` for study:
- SMBLibrary (C#) - Most mature
- macos-fuse-t/go-smb2 (Go) - Most relevant for our implementation
- Impacket (Python) - Industry standard

## Problem Statement

Windows 11 24H2 native SMB client connects to our server, completes NEGOTIATE, sends NTLM Type 1, receives our Type 2 Challenge, then immediately disconnects (TCP RST) without sending Type 3 Authenticate.

**Error seen by user**: `System error 67 - The network name cannot be found`

## What Works

| Client | Platform | Result |
|--------|----------|--------|
| go-smb2 | macOS localhost | ✅ Pass |
| go-smb2 | macOS network IP | ✅ Pass |
| go-smb2 | Windows 11 24H2 | ✅ Pass |
| Native SMB | Windows 11 24H2 | ❌ Fails after Type 2 |

## Connection Flow Analysis

```
1. TCP Connect                    ✅ Success
2. SMB NEGOTIATE Request          ✅ Received (SMB 2.0.2 through 3.1.1)
3. SMB NEGOTIATE Response         ✅ Sent (SMB 3.1.1 selected)
4. SESSION_SETUP Request #1       ✅ Received (NTLM Type 1 in SPNEGO)
5. SESSION_SETUP Response #1      ✅ Sent (NTLM Type 2 in SPNEGO, STATUS_MORE_PROCESSING_REQUIRED)
6. SESSION_SETUP Request #2       ❌ Never received - Windows sends TCP RST
```

## Things We Tried

### 1. SMB Signing Implementation
**Files**: `smb2_signing.go`, `smb2_session.go`, `server.go`

- Implemented HMAC-SHA256 signing for SMB 2.x
- Implemented AES-CMAC signing for SMB 3.x
- Implemented SP800-108 KDF for signing key derivation
- **Fixed**: Added missing `0x00` separator in KDF between label and context
- Implemented SMB 3.1.1 preauth integrity hash (SHA-512)

**Result**: Go client works with signing. Windows still fails.

### 2. NTLM KEY_EXCH Support
**File**: `auth_ntlm.go`

- Added RC4 decryption for encrypted session key when KEY_EXCH flag is set
- Session key is now correctly extracted from Type 3 message

**Result**: Signing works correctly with Go client.

### 3. MsvAvTimestamp in Target Info
**File**: `auth_ntlm.go`

- Added MsvAvTimestamp (0x0007) to NTLM Target Info
- Required for NTLMv2 MIC verification on modern Windows

**Result**: No change for Windows native client.

### 4. SIGNING_CAPABILITIES Negotiate Context
**File**: `smb2_negotiate.go`

Windows 11 24H2 sends 6 negotiate contexts:
- PREAUTH_INTEGRITY (0x0001)
- ENCRYPTION (0x0002)
- COMPRESSION (0x0003)
- SIGNING_CAPABILITIES (0x0008)
- NETNAME_NEGOTIATE (0x0005)
- RDMA_TRANSFORM (0x0007)

We added SIGNING_CAPABILITIES response (AES-CMAC).

**Result**: No change for Windows native client.

### 5. Disabled Signing Requirement
**File**: `examples/smb-server/main.go`

Added `-nosign` flag to test without signing requirement.

**Result**: No change - Windows still disconnects after Type 2.

### 6. Forced SMB 2.1 (No SMB 3.1.1)
**File**: `examples/smb-server/main.go`

Used `-smb2` flag to limit to SMB 2.x dialects, avoiding SMB 3.1.1 negotiate context complexity.

**Result**: No change - Windows still disconnects after Type 2.

## NTLM Analysis

### Client Type 1 Flags (Windows sends)
```
0xe2088297:
- NEGOTIATE_UNICODE (0x00000001) ✓
- NEGOTIATE_OEM (0x00000002) ✓
- REQUEST_TARGET (0x00000004) ✓
- NEGOTIATE_SIGN (0x00000010) ✓
- NEGOTIATE_LM_KEY (0x00000080) ✓
- NEGOTIATE_NTLM (0x00000200) ✓
- NEGOTIATE_ALWAYS_SIGN (0x00008000) ✓
- NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00020000) ✓
- NEGOTIATE_128 (0x02000000) ✓
- NEGOTIATE_KEY_EXCH (0x40000000) ✓
- NEGOTIATE_56 (0x80000000) ✓
```

### Server Type 2 Flags (We send)
```
0xe2888217:
- Same as above, plus:
- NEGOTIATE_TARGET_INFO (0x00800000) ✓ (required when including Target Info)
- Minus NEGOTIATE_LM_KEY (we don't support LM)
```

### SPNEGO Structure Analysis

Our Type 2 SPNEGO response:
```
a1 81a2           - NegTokenResp [1], length 162
  30 819f         - SEQUENCE, length 159
    a0 03         - negState [0], length 3
      0a 01 01    - ENUMERATED 1 (accept-incomplete)
    a1 0c         - supportedMech [1], length 12
      06 0a       - OID, length 10
        2b0601040182370202 0a - NTLM OID (1.3.6.1.4.1.311.2.2.10)
    a2 81 89      - responseToken [2], length 137
      04 81 86    - OCTET STRING, length 134
        4e544c4d... - NTLM Type 2 message
```

This structure appears correct per RFC 4178.

## Windows 11 24H2 NTLM Changes

### Official Microsoft Changes (December 2025 Research)

**Critical**: Microsoft has **completely removed NTLMv1** from Windows 11 24H2 and Windows Server 2025. NTLMv2 is planned for deprecation in future releases.

Key changes:
- NTLMv1 is completely removed (not just disabled)
- SMB signing is required by default for all connections
- Guest fallback is disabled in Windows 11 Pro
- New `BlockNTLMv1SSO` registry key controls NTLMv1-derived credential usage

### Registry Key Critical Behavior

The registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` controls NTLM behavior:
- **If this key is MISSING entirely**: NTLM defaults to "deny" on Windows 11 24H2
- **If present** (even with benign values like `BackConnectionHostNames`): NTLM can work
- Machines that previously had Windows Server Essentials connector may be missing this key

### Widespread Community Issues

Many users are experiencing identical issues connecting to NAS devices:
- [TrueNAS Forums](https://forums.truenas.com/t/ntlm-support-dropped-from-windows-11-24h2-smb-shares-not-accessible-on-home-network/36064): "Cannot access SMB shares on home network after 24H2 update"
- [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/3892952/authentication-failed-because-ntlm-authentication): Synology NAS connections failing
- [Microsoft Tech Community](https://techcommunity.microsoft.com/discussions/windows11/accessing-a-third-party-nas-with-smb-in-windows-11-24h2-may-fail-work-around/4391526): Official workaround discussion

Error message users see: "Authentication failed because NTLM authentication has been disabled"

### Known Workarounds (for NAS users)

1. **Registry Fix**: Ensure MSV1_0 key exists with proper values
2. **SMB Client Config**: `Set-SMbClientConfiguration -BlockNTLM $false`
3. **Windows Server Essentials Connector**: Running the Server 2016 client connector installer reportedly fixes the issue
4. **Relax SMB settings**: `AllowInsecureGuestAuth=1`, `RequireSecuritySignature=0`

### Windows Test Machine Configuration
```
BlockNTLM: False (NTLM enabled)
RequireSecuritySignature: False
EnableSecuritySignature: True
NtlmMinClientSec: 0x20000000 (SEAL required)
NtlmMinServerSec: 0x20000000 (SEAL required)
```

Our flags include NEGOTIATE_SEAL, so this shouldn't be the issue.

## Hypotheses

1. **SPNEGO structure mismatch**: Windows might expect slightly different ASN.1 encoding
2. **Missing negotiate context**: Windows might require a context we're not sending
3. **NTLM version mismatch**: Windows 11 24H2 might have stricter NTLMv2 requirements
4. **Timing/ordering issue**: Something about message ordering or timing

## Files Modified

- `smb2_signing.go` - Signing algorithms, KDF, preauth hash
- `auth_ntlm.go` - NTLM authentication, KEY_EXCH, MsvAvTimestamp, SPNEGO wrapper
- `smb2_negotiate.go` - Negotiate context handling, SIGNING_CAPABILITIES
- `smb2_session.go` - Session setup, signing key derivation
- `smb2_types.go` - RawBytes field for preauth hash
- `server.go` - Preauth hash updates in message loop
- `examples/smb-server/main.go` - Test flags (-nosign, -smb2)

## Reference Implementations (Downloaded)

Three working SMB server implementations have been cloned to `reference/` for study:

### 1. SMBLibrary (C#)
**Path**: `reference/SMBLibrary/`
**URL**: https://github.com/TalAloni/SMBLibrary

- Most mature open-source SMB implementation
- Supports SMB 1.0/CIFS, SMB 2.0, 2.1, and 3.0
- Works with Windows since NT 4.0
- Includes NTLM authentication
- Has Windows Integrated Authentication support

Key files to study:
- `SMBLibrary/Authentication/` - NTLM implementation
- `SMBLibrary/SMB2/` - SMB2 protocol handling

### 2. macos-fuse-t/go-smb2 (Go)
**Path**: `reference/go-smb2/`
**URL**: https://github.com/macos-fuse-t/go-smb2

- Lightweight SMB2/3 Server in Go
- From the author of FUSE-T (macOS FUSE implementation)
- Most relevant to our Go implementation
- Uses AGPL license (or commercial)

Key files to study:
- Session/connection handling
- NTLM authentication (if implemented)
- Message encoding/decoding

### 3. Impacket (Python)
**Path**: `reference/impacket/`
**URL**: https://github.com/fortra/impacket

- Industry-standard for SMB protocol work
- Used in penetration testing and security research
- Known to work with Windows clients
- Captures NTLM hashes successfully

Key files to study:
- `impacket/smbserver.py` - SMB server implementation
- `examples/smbserver.py` - Example usage
- NTLM message handling

## Implementation Comparison Analysis

After analyzing the three reference implementations, here are the key differences:

### Target Info (AV_PAIRS) Comparison

| AV_PAIR | smbfs (ours) | fuse-t/go-smb2 | SMBLibrary | Impacket |
|---------|--------------|----------------|------------|----------|
| MsvAvNbDomainName | ✅ | ✅ | ✅ | ✅ |
| MsvAvNbComputerName | ✅ | ✅ | ✅ | ✅ |
| MsvAvDnsDomainName | ❌ | ✅ | ❌ | ✅ |
| MsvAvDnsComputerName | ❌ | ✅ | ❌ | ✅ |
| MsvAvTimestamp | ✅ | ✅ | ❌ | ✅ |
| MsvAvEOL | ✅ | ✅ | ✅ | ✅ |

**Potential issue**: We're missing DNS domain and computer names that Windows 11 24H2 might require.

### SPNEGO Encoding Comparison

All implementations use similar SPNEGO NegTokenResp structure:
- **smbfs**: Manual ASN.1 encoding in `wrapInSPNEGO()`
- **fuse-t/go-smb2**: Go's encoding/asn1 package with ber library
- **Impacket**: Manual ASN.1 encoding

Our SPNEGO structure appears correct per RFC 4178.

### Critical Registry Key Finding

**IMPORTANT**: Research revealed that the `MSV1_0` registry key controls NTLM behavior:
- Location: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`
- **If this key is MISSING entirely**: NTLM defaults to "deny" on Windows 11 24H2
- **If present** (even with benign values): NTLM can work

**TODO**: Check if this key exists on the Windows test machine. Machines that previously had Windows Server Essentials connector installed may be missing this key.

## Next Steps

1. **Verify MSV1_0 registry key** exists on Windows test machine
2. **Add DNS AV_PAIRs** - Include MsvAvDnsDomainName and MsvAvDnsComputerName
3. **Test with Impacket smbserver** - Verify Windows can connect to a known-working Python SMB server
4. **Network capture comparison** - Byte-level comparison of Type 2 message with working server
5. **Test with older Windows versions** (10, Server 2019)
6. **Consider Kerberos** - As alternative to NTLM (but more complex)

## References

- [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
- [MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- [MS-SPNG]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/
- Davenport NTLM Reference: https://davenport.sourceforge.net/ntlm.html
- RFC 4178 (SPNEGO): https://tools.ietf.org/html/rfc4178
