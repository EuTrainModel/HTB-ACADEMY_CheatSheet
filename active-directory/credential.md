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
| Username | `INLANEFREIGHT\forend:Klmcargo2` |
| Type | Domain User |
| Source | Responder (LLMNR/NBT-NS poisoning → NetNTLMv2 → cracked) |
| Usage | Kerberos Authentication |
| Service | - |
| Privilege Level | Standard Domain User? |
| Notes | Initial access used for SPN enumeration |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\sqldev:database!` |
| Type | Service Account |
| Source | Kerberoasting (TGS request → offline crack) |
| Usage | Domain administration, SQL service authentication |
| Service | MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 |
| Privilege Level | Domain Admin |
| Notes | Service account running SQL Server; over-privileged |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\SAPService:!SapperFi2` |
| Type | Service Account |
| Source | Kerberoasting (TGS request → offline crack) |
| Usage | SAP application service authentication |
| Service | SAPService/srv01.inlanefreight.local |
| Privilege Level | Account Operators |
| Notes | Service account cracked from Kerberos TGS; member of built-in Account Operators group |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\svc_vmwaresso:Virtual01` |
| Type | Service Account |
| Source | Kerberoasting |
| Service | VMware |
| ServicePrincipalName | `vmware/inlanefreight.local` |
| Privilege Level | Standard Domain User |
| Notes | Password cracked from Kerberos TGS ticket |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\wley:transporter@4` |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\adunn:SyncMaster757` |
| Extras | User can be used for DCSync Attack |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\proxyagent:Pr0xy_ILFREIGHT!` |
| Notes | User with the option "Store password using reversible encryption" set. |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\syncron:Mycleart3xtP@ss!` |
| Notes | User with the option "Store password using reversible encryption" set. |

---

## Legend

- **Source** = How the credential was obtained
- **Type** = Domain / Local / Service
- **Usage** = How it can be abused (PtH, WinRM, SMB, RDP, etc.)

