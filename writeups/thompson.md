## Thompson - TryHackMe

### Info
- IP Target: 10.114.167.33
- Attacker IP: 192.168.204.33
- Difficoltà: Easy
- OS: Linux (Ubuntu)

### Enumeration
- Porte aperte: 22 (SSH), 8009 (AJP), 8080 (Tomcat 8.5.5)
- Tool: nmap -sC -sV

### Foothold
- Navigato su http://10.114.167.33:8080/manager/html
- Pagina 401 Unauthorized rivela credenziali nel messaggio di errore:
  username="tomcat" password="s3cret"
- Accesso al Tomcat Manager con tomcat:s3cret
- Deploy WAR reverse shell → shell come utente tomcat

### Privilege Escalation
- Trovato /home/jack/id.sh writable
- Cron job esegue id.sh come root
- Overwrite con bash reverse shell
- Shell come root
