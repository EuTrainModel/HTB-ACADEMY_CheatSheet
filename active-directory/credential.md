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
| Username | `INLANEFREIGHT\forend` |
| Password | `Klmcargo2` |
| Type | Domain User |
| Source | Responder (LLMNR/NBT-NS poisoning → NetNTLMv2 → cracked) |
| Usage | Initial foothold authentication |
| Service | N/A |
| Privilege Level | Standard Domain User |
| Notes | First valid domain credential obtained via Responder + Hashcat |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\sqldev` |
| Password | `database!` |
| Type | Service Account |
| Source | Kerberoasting (TGS request → offline crack) |
| Usage | SQL service authentication |
| Service | `MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433` |
| Privilege Level | Domain Admin |
| Notes | Highly over-privileged service account cracked from Kerberos TGS |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\SAPService` |
| Password | `!SapperFi2` |
| Type | Service Account |
| Source | Kerberoasting (TGS request → offline crack) |
| Usage | SAP application authentication |
| Service | `SAPService/srv01.inlanefreight.local` |
| Privilege Level | Account Operators |
| Notes | Member of built-in “Account Operators” group – elevated privileges |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\svc_vmwaresso` |
| Password | `Virtual01` |
| Type | Service Account |
| Source | Kerberoasting |
| Service | `vmware/inlanefreight.local` |
| Privilege Level | Standard Domain User |
| Notes | Password cracked from Kerberos TGS ticket |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\wley` |
| Password | `transporter@4` |
| Type | Domain User |
| Source | Responder + Hashcat (NetNTLMv2 crack) |
| Usage | Used for ACL abuse escalation chain |
| Privilege Level | Standard Domain User |
| Notes | Starting point user for ACL abuse path toward adunn |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\adunn` |
| Password | `SyncMaster757` |
| Type | Domain User |
| Source | Obtained via ACL abuse chain |
| Usage | DCSync attack capability |
| Privilege Level | Replication Admin (DCSync rights) |
| Notes | User explicitly granted DS-Replication-Get-Changes and DS-Replication-Get-Changes-All permissions, allowing full domain credential extraction |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\administrator` |
| Type | Built-in Domain Administrator |
| Source | DCSync attack using secretsdump.py |
| Credential Type | NTLM Hash |
| NTLM Hash | `88ad09182de639ccc6579eb0849751cf` |
| Usage | Domain Administrator authentication / Pass-the-Hash |
| Privilege Level | Domain Admin |
| Notes | Hash extracted directly from NTDS.dit via DCSync |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\krbtgt` |
| Type | Kerberos Service Account |
| Source | DCSync attack |
| Credential Type | NTLM Hash |
| NTLM Hash | `16e26ba33e455a8c338142af8d89ffbc` |
| Usage | Potential Golden Ticket creation |
| Privilege Level | Critical Domain Secret |
| Notes | krbtgt hash allows forging Kerberos tickets if abused |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\proxyagent` |
| Password | `Pr0xy_ILFREIGHT!` |
| Type | Domain User |
| Source | DCSync dump – reversible encryption enabled |
| Usage | Direct authentication |
| Privilege Level | Standard Domain User |
| Notes | Password recovered in cleartext because account is configured with “Store password using reversible encryption” |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\syncron` |
| Password | `Mycleart3xtP@ss!` |
| Type | Domain User |
| Source | DCSync attack (lab question result) |
| Usage | Direct authentication |
| Privilege Level | Standard Domain User |
| Notes | Account identified during DCSync task as another user with reversible encryption enabled |

---

| Field | Value |
|------|--------|
| Username | `INLANEFREIGHT\khartsfield` |
| Type | Domain User |
| Source | DCSync attack |
| Credential Type | NTLM Hash |
| NTLM Hash | `4bb3b317845f0954200a6b0acc9b9f9a` |
| Usage | Pass-the-Hash authentication |
| Privilege Level | Unknown (not specified in module) |
| Notes | NTLM hash explicitly extracted as part of DCSync exercise |

---

## Legend

- **Source** = How the credential was obtained  
- **Type** = Domain / Local / Service  
- **Usage** = How it can be abused (PtH, WinRM, SMB, RDP, etc.)  
- **Privilege Level** = Impact level of the credential  

---

## Notes

- Credentials marked “Unknown privilege level” reflect lack of explicit info in the lab notes.
- No details were added beyond what was explicitly provided in previous documentation.
