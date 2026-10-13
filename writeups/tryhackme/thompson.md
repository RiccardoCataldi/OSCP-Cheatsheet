## Thompson - TryHackMe

### Info
- IP Target: 10.114.167.33
- Attacker IP: 192.168.204.33
- Difficulty: Easy
- OS: Linux (Ubuntu)

### Enumeration
- Open ports: 22 (SSH), 8009 (AJP), 8080 (Tomcat 8.5.5)
- Tool: nmap -sC -sV

### Foothold
- Browsed to http://10.114.167.33:8080/manager/html
- The 401 Unauthorized page reveals credentials in the error message:
  username="tomcat" password="s3cret"
- Accessed Tomcat Manager with tomcat:s3cret
- Deployed WAR reverse shell -> shell as user tomcat

### Privilege Escalation
- Found `/home/jack/id.sh` writable
- Cron job runs `id.sh` as root
- Overwrote it with a bash reverse shell
- Root shell
