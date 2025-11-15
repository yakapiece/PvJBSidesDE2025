# 🎯 PvJ Scored Services & Ports by Subteam

*Based on official sources, participant experiences (2015-2023), and common enterprise environments*

## 📊 Scoring Overview

### Primary Scoring Components
- **Service Uptime** (Health & Welfare checks) - Primary scoring factor
- **Beacons** (Red team compromise indicators) - Negative scoring
- **Flags** (Integrity/offense flags) - Secondary scoring
- **Marketplace Effects** - Variable positive/negative impacts

### Key Constraints
- **Cannot block scored services** - Firewall must allow all traffic to scored services
- **DNS dependency** - ALL scoring starts with DNS resolution
- **3-minute intervals** - Scorebot checks every 3 minutes
- **Service availability** - Uptime is more important than security

---

## 🪟 Windows Team Services

### Core Windows Services
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **Active Directory** | 389, 636, 3268, 3269 | TCP/UDP | CRITICAL | LDAP/LDAPS, Global Catalog |
| **DNS (Windows)** | 53 | TCP/UDP | CRITICAL | Often integrated with AD |
| **Kerberos** | 88 | TCP/UDP | CRITICAL | AD authentication |
| **SMB/CIFS** | 445 | TCP | HIGH | File sharing, admin access |
| **NetBIOS** | 137-139 | TCP/UDP | MEDIUM | Legacy Windows networking |
| **RPC Endpoint Mapper** | 135 | TCP | HIGH | Windows RPC services |
| **WinRM** | 5985, 5986 | TCP | MEDIUM | Remote management |

### Application Services
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **IIS Web Server** | 80, 443 | TCP | HIGH | Common web services |
| **Exchange Mail** | 25, 110, 143, 993, 995 | TCP | HIGH | Email services |
| **SQL Server** | 1433 | TCP | HIGH | Database services |
| **Terminal Services** | 3389 | TCP | MEDIUM | RDP access |
| **DHCP** | 67, 68 | UDP | MEDIUM | IP assignment |

### Monitoring Focus
- **Event Logs** - Security, System, Application
- **Service Status** - Critical Windows services
- **User Accounts** - Unauthorized additions/changes
- **Scheduled Tasks** - Persistence mechanisms
- **Registry Changes** - System modifications

---

## 🐧 *nix Team Services

### Core Linux/Unix Services
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **SSH** | 22 | TCP | CRITICAL | Remote access, often targeted |
| **Apache/Nginx** | 80, 443 | TCP | HIGH | Web services |
| **BIND DNS** | 53 | TCP/UDP | CRITICAL | Name resolution |
| **Postfix/Sendmail** | 25 | TCP | HIGH | Mail transfer |
| **IMAP/POP3** | 143, 993, 110, 995 | TCP | MEDIUM | Mail access |
| **NFS** | 2049, 111 | TCP/UDP | MEDIUM | Network file system |
| **Samba** | 139, 445 | TCP | MEDIUM | Windows file sharing |

### Database Services
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **MySQL/MariaDB** | 3306 | TCP | HIGH | Common database |
| **PostgreSQL** | 5432 | TCP | HIGH | Enterprise database |
| **MongoDB** | 27017 | TCP | MEDIUM | NoSQL database |
| **Redis** | 6379 | TCP | MEDIUM | Key-value store |

### Application Services
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **FTP** | 20, 21 | TCP | MEDIUM | File transfer |
| **SFTP** | 22 | TCP | HIGH | Secure file transfer |
| **Rsync** | 873 | TCP | LOW | File synchronization |
| **SNMP** | 161, 162 | UDP | LOW | Network monitoring |

### Monitoring Focus
- **Process Lists** - Unauthorized processes
- **Cron Jobs** - Scheduled persistence
- **Log Files** - /var/log/* analysis
- **Network Connections** - Unusual outbound traffic
- **File Permissions** - SUID/SGID changes

---

## 🔥 Firewall Team Services

### Network Infrastructure (Monitor Only)
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **HTTP Traffic** | 80 | TCP | CRITICAL | **MONITOR ONLY - DO NOT BLOCK** |
| **HTTPS Traffic** | 443 | TCP | CRITICAL | **MONITOR ONLY - DO NOT BLOCK** |
| **DNS Queries** | 53 | TCP/UDP | CRITICAL | **MONITOR ONLY - DO NOT BLOCK** |
| **Email Traffic** | 25, 110, 143, 993, 995 | TCP | HIGH | **MONITOR ONLY - DO NOT BLOCK** |
| **SSH Traffic** | 22 | TCP | HIGH | **MONITOR ONLY - DO NOT BLOCK** |
| **SMB Traffic** | 445 | TCP | HIGH | **MONITOR ONLY - DO NOT BLOCK** |
| **RDP Traffic** | 3389 | TCP | MEDIUM | **MONITOR ONLY - DO NOT BLOCK** |

### Firewall Management
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **pfSense WebGUI** | 443, 80 | TCP | CRITICAL | Firewall management |
| **Cisco ASA ASDM** | 443 | TCP | CRITICAL | Cisco firewall management |
| **SNMP** | 161 | UDP | MEDIUM | Monitoring interface |
| **Syslog** | 514 | UDP | HIGH | Log collection |

### Traffic Analysis Focus
- **Connection Patterns** - Unusual outbound connections
- **Bandwidth Usage** - Data exfiltration indicators
- **Protocol Analysis** - Non-standard protocol usage
- **Geolocation** - Connections to suspicious countries
- **Beacon Detection** - Regular callback patterns

### ⚠️ CRITICAL FIREWALL RULES
```
# NEVER BLOCK THESE - REQUIRED FOR SCORING
ALLOW ALL to scored_services_subnet
ALLOW DNS (53) to DNS_servers
ALLOW HTTP/HTTPS to web_services
ALLOW SMTP to mail_servers
ALLOW scorebot_source to ALL_services
```

---

## 🌐 BIND Team Services

### DNS Infrastructure (CRITICAL)
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **DNS Queries** | 53 | UDP | CRITICAL | Primary DNS resolution |
| **DNS Zone Transfers** | 53 | TCP | CRITICAL | Secondary DNS servers |
| **DNS over TLS** | 853 | TCP | MEDIUM | Secure DNS (if implemented) |
| **DNS over HTTPS** | 443 | TCP | MEDIUM | DoH (if implemented) |

### BIND Management
| Service | Port(s) | Protocol | Priority | Notes |
|---------|---------|----------|----------|-------|
| **RNDC** | 953 | TCP | HIGH | Remote name daemon control |
| **SSH** | 22 | TCP | HIGH | Server management |
| **SNMP** | 161 | UDP | MEDIUM | Monitoring |
| **Syslog** | 514 | UDP | HIGH | Log collection |

### DNS Record Types to Monitor
- **A Records** - IPv4 address resolution
- **AAAA Records** - IPv6 address resolution  
- **CNAME Records** - Canonical name aliases
- **MX Records** - Mail exchange servers
- **NS Records** - Name server delegation
- **PTR Records** - Reverse DNS lookups
- **SOA Records** - Start of authority
- **TXT Records** - Text records (SPF, DKIM, etc.)

### Critical DNS Dependencies
```
ALL SCORING DEPENDS ON DNS RESOLUTION
DNS Failure = ZERO points for all dependent services

Scoring Chain:
1. Scorebot queries DNS for service hostname
2. If DNS fails → No further checks performed
3. If DNS succeeds → Service-specific checks proceed
4. Service uptime recorded based on response
```

### DNS Security Monitoring
- **Query Patterns** - Unusual DNS requests
- **Zone Transfer Attempts** - Unauthorized transfers
- **Cache Poisoning** - DNS response manipulation
- **Subdomain Enumeration** - Reconnaissance attempts
- **DNS Tunneling** - Data exfiltration via DNS

---

## 🔄 Cross-Team Coordination

### Shared Responsibilities
| Task | Primary Team | Supporting Teams | Frequency |
|------|--------------|------------------|-----------|
| **DNS Health Checks** | BIND | All teams | Every 30 minutes |
| **Service Availability** | Service owner | Firewall (monitoring) | Every 3 minutes |
| **Incident Response** | All teams | Firewall (traffic analysis) | As needed |
| **Log Correlation** | All teams | *nix (log aggregation) | Continuous |

### Communication Protocols
- **DNS Issues** → BIND team alerts ALL teams immediately
- **Service Down** → Service team alerts Firewall team for traffic analysis
- **Suspicious Traffic** → Firewall team alerts relevant service team
- **Compromise Detected** → All teams coordinate response

---

## 📈 Typical Environment Scale

### Machine Count Progression
- **Start of Day 1**: ~12 machines per team
- **End of Day 2**: ~37 machines per team
- **Service Growth**: Red team adds services throughout competition

### Service Distribution (Estimated)
- **Windows Services**: 40-50% of scored services
- ***nix Services**: 35-45% of scored services  
- **Network Services**: 10-15% of scored services
- **Specialized Apps**: 5-10% of scored services (Jira, PBX, etc.)

---

## 🎯 Scoring Strategy by Team

### Windows Team Priority
1. **Active Directory** - Foundation for all Windows services
2. **DNS (if Windows-based)** - Critical for all scoring
3. **Web Services** - High visibility, high points
4. **Mail Services** - Common target, high value
5. **File Services** - Consistent scoring opportunity

### *nix Team Priority  
1. **SSH** - Primary access method, always targeted
2. **Web Services** - Apache/Nginx, high scoring value
3. **DNS (BIND)** - If separate from Windows DNS
4. **Mail Services** - Postfix/Sendmail
5. **Database Services** - Backend for applications

### Firewall Team Priority
1. **Traffic Monitoring** - Detect compromise patterns
2. **Service Accessibility** - Ensure scoring traffic flows
3. **Threat Intelligence** - Identify attack patterns
4. **Log Analysis** - Support other teams' investigations
5. **Performance Monitoring** - Prevent service degradation

### BIND Team Priority
1. **DNS Availability** - Absolute highest priority
2. **Zone Integrity** - Prevent DNS manipulation
3. **Query Performance** - Fast resolution for scoring
4. **Security Monitoring** - Detect DNS-based attacks
5. **Backup/Recovery** - Quick restoration capabilities

---

## 📚 Sources & References

- System Overlord Blog (2015, 2018) - Blue team experiences
- ip3c4c First-Time Participant (2023) - Recent competition details
- BSides Las Vegas Official Documentation
- ProsVJoes.net Official Website
- Common enterprise service standards
- Participant write-ups and technical analyses

*Last Updated: Based on 2023 competition data and historical trends*

