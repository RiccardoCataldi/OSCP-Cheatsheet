# Writeups

Box writeups, organized by platform (following the
[NetSecFocus Trophy Room / TJnull OSCP-prep list](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview)).

## HackTheBox

| Box | OS | Difficulty | Key topics |
|-----|----|-----------|-----------|
| [Timelapse](hackthebox/timelapse.md) | Windows (DC) | Easy | Guest SMB enum, encrypted ZIP/PFX cracking, cert-based WinRM, PS history, LAPS |
| [Sauna](hackthebox/sauna.md) | Windows (DC) | Easy | AS-REP roasting, WinRM, autologon creds, DCSync, Pass-the-Hash |
| [Monteverde](hackthebox/monteverde.md) | Windows (DC) | Medium | Null session enum, user-as-password spray, Azure AD Connect creds |
| [Return](hackthebox/return.md) | Windows (DC) | Easy | Printer panel rogue-LDAP creds, WinRM, Server Operators service abuse |

## TryHackMe

| Box | OS | Difficulty | Key topics |
|-----|----|-----------|-----------|
| [Alfred](tryhackme/alfred.md) | Windows | Easy | Jenkins RCE, token impersonation (Incognito) |
| [Ignite](tryhackme/ignite.md) | Linux | Easy | CMS RCE |
| [HackPark](tryhackme/hackpark.md) | Windows | Medium | HTTP brute force, BlogEngine RCE, service misconfig |
| [Corp](tryhackme/corp.md) | Windows (Domain) | Medium | AppLocker bypass, Kerberoasting, PowerUp, unattended install creds |
| [Thompson](tryhackme/thompson.md) | Linux | Easy | Tomcat manager, WAR deploy |
