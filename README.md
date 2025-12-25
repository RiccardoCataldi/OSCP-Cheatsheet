# OSCP Cheatsheet

## Nmap

### Version Detection

* **Version Detection Scan** - Probes open ports to determine service/version information

```bash
nmap -sV <target>
```

* `-sV`: Enables version detection, which probes open ports to determine what service and version is running on them
