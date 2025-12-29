# OSCP Cheatsheet

## Table of Contents

- [Scanning & Enumeration](#scanning--enumeration)
  - [Nmap Basics](#nmap-basics)
  - [Service Enumeration](#service-enumeration)
    - [SMB](#smb)
    - [NFS](#nfs)
    - [FTP](#ftp)
- [Privilege Escalation](#privilege-escalation)
  - [Linux](#linux)
    - [SUID Files](#suid-files)

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
