# Obtained Credentials (Redacted)

This file documents the **types and sources** of credentials obtained during HTB Active Directory labs.
---

## Credential

| Field | Value |
|------|--------|
| Username | `<DOMAIN>\<USER>` |
| Type | Domain User |
| Source | Kerberoasting |
| Service | MSSQL / HTTP / etc |
| Privilege Level | Standard User / Local Admin / Domain Admin |
| Notes | Cracked from TGS ticket |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT.LOCAL\forend:Klmcargo2` |
| Type | Domain User |
| Source | Responder (LLMNR/NBT-NS poisoning → NetNTLMv2 → cracked) |
| Usage | Kerberos Authentication |
| Service | - |
| Privilege Level | - |
| Notes | - |

---

## Legend

- **Source** = How the credential was obtained
- **Type** = Domain / Local / Service
- **Usage** = How it can be abused (PtH, WinRM, SMB, RDP, etc.)

