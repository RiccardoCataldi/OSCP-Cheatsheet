# OSCP Cheatsheet

## Nmap

### Version Detection

* **Version Detection Scan** - Probes open ports to determine service/version information

```bash
nmap -sV <target>
```

* `-sV`: Enables version detection, which probes open ports to determine what service and version is running on them

### SMB Enumeration

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
