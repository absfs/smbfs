# SMB Server Test Matrix - Windows 11 24H2 Compatibility

## Test Environment
- **Server**: macOS (192.168.1.161)
- **Client**: Windows 11 24H2 Build 26100 (192.168.1.170)
- **Port**: 445

## Windows Client Configuration Tests

| Setting | Value Tested | Result | Notes |
|---------|--------------|--------|-------|
| BlockNTLM | $true (default) | ❌ FAIL | Connection rejected |
| BlockNTLM | $false | ❌ FAIL | Still SEC_E_INVALID_PARAMETER |
| BlockNTLMServerExceptionList | "192.168.1.161" | ❌ FAIL | Still fails |
| RequireSecuritySignature | $true (default) | ❌ FAIL | - |
| RequireSecuritySignature | $false | ❌ FAIL | Tested 2025-12-12 |
| EnableSecuritySignature | $true | ❌ FAIL | - |
| EnableSecuritySignature | $false | ❌ FAIL | Tested 2025-12-12 |
| AllowInsecureGuestAuth (Registry) | 0 (default) | ❌ FAIL | - |
| AllowInsecureGuestAuth (Registry) | 1 | ❌ FAIL | Tested 2025-12-12 |
| MSV1_0\Auth132 | "IISSUBA" | ✅ SET | Already configured |
| MSV1_0\NtlmMinClientSec | 0x20000000 | ✅ SET | Already configured |
| MSV1_0\NtlmMinServerSec | 0x20000000 | ✅ SET | Already configured |
| Credential Manager | Manual entry | ❌ FAIL | Tested 2025-12-12 |
| All settings relaxed | Combined | ❌ FAIL | Tested 2025-12-12 |
| Non-guest username | testuser | ❌ FAIL | Tested 2025-12-12 |
| LanmanWorkstation restart | Yes | ✅ DONE | No effect |

## Server Configuration Tests

| Setting | Value Tested | Result | Notes |
|---------|--------------|--------|-------|
| SMB Dialect | 3.1.1 (default) | ❌ FAIL | Windows disconnects after Type 2 |
| SMB Dialect | 2.1 only (-smb2 flag) | ❌ FAIL | Same behavior |
| SMB Signing | Required | ❌ FAIL | - |
| SMB Signing | Disabled (-nosign) | ❌ FAIL | - |
| Guest Session Key | nil | ❌ FAIL | Go client worked, Windows failed |
| Guest Session Key | Computed | ❌ FAIL | Fixed for Go, Windows still fails |

## NTLM Configuration Tests

| Setting | Value Tested | Result | Notes |
|---------|--------------|--------|-------|
| Target Info | Full (DNS + NetBIOS + Timestamp) | ❌ FAIL | - |
| Target Info | Minimal (NetBIOS only) | ❌ FAIL | Go client broke |
| Target Info | None | ❌ FAIL | Go client broke |
| NTLM Flags | Echo client flags | ❌ FAIL | Current approach |
| MsvAvTimestamp | Included | ❌ FAIL | Required for NTLMv2 |
| KEY_EXCH | Supported | ✅ Works for Go | Windows never sends Type 3 |

## Connection Flow Analysis

| Step | Our Server | Windows Behavior |
|------|------------|------------------|
| TCP Connect | ✅ | ✅ Connects |
| NEGOTIATE | ✅ Responds | ✅ Accepts |
| SESSION_SETUP Type 1 | ✅ Receives | ✅ Sends NTLM Negotiate |
| SESSION_SETUP Type 2 | ✅ Sends Challenge | ❌ TCP RST immediately |
| SESSION_SETUP Type 3 | Never received | Never sent |

## What Windows Event Log Shows
- Error: `SEC_E_INVALID_PARAMETER (0x80090308)`
- Location: During `InitializeSecurityContext` (SSPI)
- This means Windows SSPI rejects our Type 2 Challenge

## Open Source Implementations to Test

| Implementation | Language | Port | Tested | Result |
|----------------|----------|------|--------|--------|
| macOS Built-in SMB | Closed | 445 | ❓ NO | Needs System Prefs |
| Samba (Homebrew) | C | 445 | ❓ NO | Needs sudo |
| FUSE-T go-smb2 | Go | 8445 | ✅ Go client works | Can't test Win on 8445 |
| FUSE-T go-smb2 | Go | 445 | ❓ NO | Needs sudo |
| Impacket smbserver | Python | 445 | ❓ NO | Needs sudo |

## Run Script for Testing Other Servers

Run with: `sudo bash /Users/joshua/ws/active/absfs/smbfs/docs/test_servers.sh`

## Combinations NOT Yet Tested

1. RequireSecuritySignature=$false + EnableSecuritySignature=$false + AllowInsecureGuestAuth=1
2. Adding credentials to Windows Credential Manager manually
3. Using a non-guest username with password
4. macOS built-in SMB as baseline test
5. Samba with proper NTLMv2 config

## Next Steps

1. Test macOS built-in SMB (baseline - does Windows connect to ANYTHING?)
2. Test Samba via Homebrew
3. Test remaining Windows client configurations
4. If any work, capture packets and compare
