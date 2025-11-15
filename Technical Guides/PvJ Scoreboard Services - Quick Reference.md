# 🎯 PvJ Scoreboard Services - Quick Reference

Services that appear on the PvJ scoreboard based on participant experiences

## 📊 Scoreboard Basics

•Updates every 3 minutes

•Green = Service Up | Red = Service Down

•DNS failure = ALL dependent services fail

•Service uptime = Primary scoring factor

## 🌐 DNS Services (CRITICAL - ALL SCORING DEPENDS ON THIS)

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|DNS Server|53|BIND|If this fails, everything else fails|

## 🌐 Web Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|HTTP|80|Windows/*nix|Common on most machines|
|HTTPS|443|Windows/*nix|Secure web services|
|Web Applications|8080, 8443|Windows/*nix|Custom web apps|

## 📧 Mail Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|SMTP|25|Windows/*nix|Mail sending|
|POP3|110|Windows/*nix|Mail retrieval|
|IMAP|143|Windows/*nix|Mail access|
|IMAPS|993|Windows/*nix|Secure IMAP|
|POP3S|995|Windows/*nix|Secure POP3|

## 🗂️ File Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|SMB/CIFS|445|Windows|Windows file sharing|
|FTP|21|*nix|File transfer|
|SFTP|22|*nix|Secure file transfer|
|NFS|2049|*nix|Network file system|

## 🔐 Authentication Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|Active Directory|389|Windows|LDAP authentication|
|Kerberos|88|Windows|AD authentication|
|SSH|22|*nix|Remote access|

## 🗄️ Database Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|SQL Server|1433|Windows|Microsoft database|
|MySQL|3306|*nix|Common database|
|PostgreSQL|5432|*nix|Enterprise database|

## 🖥️ Remote Access Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|RDP|3389|Windows|Remote desktop|
|VNC|5900|*nix|Remote desktop|
|SSH|22|*nix|Command line access|

## 📞 Specialized Services

|   |   |   |   |
|---|---|---|---|
|Service|Port|Team|Notes|
|PBX|Various|Windows/*nix|Phone system (mentioned in 2023)|
|Jira|8080|Windows/*nix|Ticketing system (mentioned in 2023)|
|DHCP|67|Windows|IP assignment|
|SNMP|161|Firewall|Network monitoring|

## 📈 Typical Layout

### Per-Machine Services

Each machine on scoreboard typically shows:

•DNS (if DNS server)

•HTTP/HTTPS (if web server)

•SSH (if Linux) or RDP (if Windows)

•Mail services (if mail server)

•Database (if database server)

•File services (SMB, FTP, NFS)

•Specialized apps (Jira, PBX, etc.)

### Team Overview

•Total machines: Start ~12, grow to ~37

•Update frequency: Every 3 minutes

•Scoring period: While the range is live over 2+ days


## 🎯 Scoreboard Strategy

### Priority Order

1.DNS - Fix immediately, affects everything

2.Web services - High visibility, high points

3.Mail services - Common and valuable

4.File services - Consistent scoring

5.Specialized apps - Bonus points

### Quick Triage

•All services red? → Check DNS first

•Some services red? → Check individual service

•Intermittent red? → Check network/firewall

•New red services? → Red team added something

### Team Coordination

•BIND team monitors DNS health constantly

•Firewall team ensures scoring traffic flows

•Service teams focus on keeping services running

•All teams communicate DNS issues immediately