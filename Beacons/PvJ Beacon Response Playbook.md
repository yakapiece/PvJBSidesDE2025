# PvJ Beacon Response Playbook

**Date:** 2025-07-12  
**Version:** 1.0  
**Classification:** Competition Use Only

## Executive Summary

This playbook provides comprehensive response procedures for detected beaconing activity in Pros vs Joes (PvJ) CTF competitions. It covers immediate containment, investigation, eradication, and recovery procedures tailored explicitly for the PvJ environment.

## Table of Contents

1. [Immediate Response Procedures](#immediate-response-procedures)
2. [Beacon Classification and Triage](#beacon-classification-and-triage)
3. [Investigation Procedures](#investigation-procedures)
4. [Containment Strategies](#containment-strategies)
5. [Eradication Procedures](#eradication-procedures)
6. [Recovery and Hardening](#recovery-and-hardening)
7. [Documentation and Lessons Learned](#documentation-and-lessons-learned)
8. [Automated Response Scripts](#automated-response-scripts)

---

## Immediate Response Procedures

### Phase 1: Detection Confirmation (0-5 minutes)

**Objective:** Verify the beacon detection and assess immediate threat level.

#### Step 1: Validate Detection
```bash
# Confirm network beaconing with netstat
netstat -an | grep -E "(ESTABLISHED|TIME_WAIT)" | sort

# Check for suspicious processes
ps aux | grep -E "(powershell|cmd|rundll32|regsvr32|mshta|certutil)"

# Verify DNS queries
tail -f /var/log/dns.log | grep -E "(pastebin|github|hastebin)"
```

#### Step 2: Initial Assessment
- **Beacon Type:** HTTP/HTTPS, DNS, or SMB
- **Frequency:** Regular intervals or irregular patterns
- **Destination:** Internal or external C2 server
- **Affected Systems:** Single host or multiple systems

#### Step 3: Alert Team
```powershell
# PowerShell notification script
$alertMessage = @"
BEACON DETECTED - IMMEDIATE RESPONSE REQUIRED
Time: $(Get-Date)
Host: $env:COMPUTERNAME
Type: [BEACON_TYPE]
Destination: [C2_SERVER]
Confidence: [HIGH/MEDIUM/LOW]
"@

# Send to team communication channel
Write-Host $alertMessage -ForegroundColor Red
```

### Phase 2: Rapid Containment (5-15 minutes)

**Objective:** Prevent beacon from causing further damage while preserving evidence.

#### Network Isolation Options

**Option A: Selective Blocking (Preferred)**
```bash
# Block specific C2 server
iptables -A OUTPUT -d [C2_IP] -j DROP
iptables -A INPUT -s [C2_IP] -j DROP

# Block suspicious domains via DNS
echo "127.0.0.1 [suspicious_domain]" >> /etc/hosts
```

**Option B: Process Termination**
```powershell
# Windows: Kill suspicious processes
Get-Process | Where-Object {$_.ProcessName -match "suspicious_pattern"} | Stop-Process -Force

# Terminate network connections
netsh advfirewall firewall add rule name="Block_C2" dir=out action=block remoteip=[C2_IP]
```

**Option C: Full Network Isolation (Last Resort)**
```bash
# Complete network isolation
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
```

---

## Beacon Classification and Triage

### Beacon Severity Matrix

| **Factor** | **Critical** | **High** | **Medium** | **Low** |
|------------|--------------|----------|------------|---------|
| **Frequency** | < 60 seconds | 1-5 minutes | 5-30 minutes | > 30 minutes |
| **Persistence** | System-level | User-level | Session-only | Temporary |
| **Privileges** | SYSTEM/root | Administrator | Standard User | Limited |
| **Data Access** | Sensitive files | User documents | Public data | No data |
| **Lateral Movement** | Multiple hosts | Single host | No movement | Isolated |

### Response Priority

**Critical (P1):** Immediate response, full team mobilization
- Active data exfiltration
- Multiple compromised systems
- Administrative privileges
- Persistent mechanisms

**High (P2):** Rapid response within 15 minutes
- Single system compromise
- User-level access
- No immediate data loss
- Limited persistence

**Medium (P3):** Response within 1 hour
- Suspicious activity
- No confirmed compromise
- Monitoring required

**Low (P4):** Response within 4 hours
- False positive likely
- Minimal risk
- Documentation only

---

## Investigation Procedures

### Evidence Collection

#### Network Evidence
```bash
# Capture network traffic
tcpdump -i any -w beacon_capture_$(date +%Y%m%d_%H%M%S).pcap host [C2_IP]

# Extract connection details
ss -tuln > network_connections_$(date +%Y%m%d_%H%M%S).txt
netstat -rn > routing_table_$(date +%Y%m%d_%H%M%S).txt
```

#### Process Evidence
```powershell
# Windows process analysis
Get-Process | Select-Object Name,Id,Path,StartTime,CPU | Export-Csv -Path "processes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Get process command lines
Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine | Export-Csv -Path "process_cmdlines_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Check process network connections
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -Path "network_connections_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
```

#### Memory Analysis
```bash
# Linux memory dump
dd if=/proc/[PID]/mem of=process_memory_[PID]_$(date +%Y%m%d_%H%M%S).dump

# Windows memory dump (requires admin)
# Use ProcDump or similar tool
procdump.exe -ma [PID] beacon_memory_dump.dmp
```

#### File System Evidence
```bash
# Check for dropped files
find /tmp /var/tmp /home -type f -newer /tmp/beacon_detection_start -ls

# Windows file system check
Get-ChildItem -Path C:\Users -Recurse -Force | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-1)} | Select-Object FullName,LastWriteTime
```

### Timeline Reconstruction

#### Log Analysis
```bash
# System logs
grep -E "(beacon|C2|suspicious_process)" /var/log/syslog | tail -100

# Authentication logs
grep -E "(login|su|sudo)" /var/log/auth.log | tail -50

# Network logs
grep -E "([C2_IP]|suspicious_domain)" /var/log/network.log
```

#### Windows Event Analysis
```powershell
# Security events
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-2)} | Where-Object {$_.Id -in @(4624,4625,4648,4672)}

# PowerShell events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).AddHours(-2)}

# Process creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-2)}
```

---

## Containment Strategies

### Network-Level Containment

#### Firewall Rules
```bash
# Linux iptables rules
iptables -A OUTPUT -d [C2_IP] -j LOG --log-prefix "BLOCKED_C2: "
iptables -A OUTPUT -d [C2_IP] -j DROP

# Block by domain (requires DNS filtering)
iptables -A OUTPUT -p tcp --dport 53 -m string --string "[suspicious_domain]" --algo bm -j DROP
```

#### DNS Sinkholing
```bash
# Redirect malicious domains to sinkhole
echo "127.0.0.1 [malicious_domain]" >> /etc/hosts
echo "127.0.0.1 [c2_domain]" >> /etc/hosts

# Windows DNS sinkholing
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "127.0.0.1 [malicious_domain]"
```

### Host-Level Containment

#### Process Isolation
```powershell
# Windows: Suspend suspicious processes
$suspiciousProcesses = Get-Process | Where-Object {$_.ProcessName -match "suspicious_pattern"}
foreach ($proc in $suspiciousProcesses) {
    $proc.Suspend()
    Write-Host "Suspended process: $($proc.ProcessName) (PID: $($proc.Id))"
}
```

#### Service Management
```bash
# Linux: Stop suspicious services
systemctl stop [suspicious_service]
systemctl disable [suspicious_service]

# Windows: Stop suspicious services
Stop-Service -Name [suspicious_service] -Force
Set-Service -Name [suspicious_service] -StartupType Disabled
```

### User Account Containment

#### Account Lockdown
```powershell
# Disable compromised user accounts
Disable-ADAccount -Identity [compromised_user]

# Reset passwords
Set-ADAccountPassword -Identity [compromised_user] -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force)

# Force logoff sessions
quser | Where-Object {$_ -match "[compromised_user]"} | ForEach-Object {
    $sessionId = ($_ -split '\s+')[2]
    logoff $sessionId
}
```

---

## Eradication Procedures

### Beacon Removal

#### Process Termination
```bash
# Linux: Kill beacon processes
pkill -f [beacon_pattern]
kill -9 [beacon_pid]

# Remove from process tree
pstree -p [parent_pid] | grep -o '([0-9]*)' | grep -o '[0-9]*' | xargs kill -9
```

#### File Removal
```powershell
# Windows: Remove beacon files
$beaconFiles = Get-ChildItem -Path C:\ -Recurse -Force | Where-Object {
    $_.Name -match "beacon|implant|payload" -or
    $_.LastWriteTime -gt (Get-Date).AddHours(-2)
}

foreach ($file in $beaconFiles) {
    Remove-Item -Path $file.FullName -Force
    Write-Host "Removed: $($file.FullName)"
}
```

### Persistence Removal

#### Registry Cleanup
```powershell
# Remove malicious registry entries
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    $entries = Get-ItemProperty -Path $key
    $entries.PSObject.Properties | Where-Object {
        $_.Value -match "suspicious_pattern|temp|appdata"
    } | ForEach-Object {
        Remove-ItemProperty -Path $key -Name $_.Name
        Write-Host "Removed registry entry: $($_.Name)"
    }
}
```

#### Scheduled Task Cleanup
```powershell
# Remove malicious scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.TaskName -match "^[a-f0-9]{8,}$" -or
    $_.Actions.Execute -match "powershell|cmd|certutil"
} | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
    Write-Host "Removed scheduled task: $($_.TaskName)"
}
```

#### Service Cleanup
```bash
# Linux: Remove malicious services
systemctl list-units --type=service | grep -E "(suspicious|unknown)" | while read service; do
    systemctl stop $service
    systemctl disable $service
    rm -f /etc/systemd/system/$service
done

systemctl daemon-reload
```

### Network Artifact Cleanup

#### Clear DNS Cache
```bash
# Linux
systemctl flush-dns

# Windows
ipconfig /flushdns
Clear-DnsClientCache
```

#### Reset Network Connections
```powershell
# Windows: Reset network stack
netsh winsock reset
netsh int ip reset
netsh advfirewall reset
```

---

## Recovery and Hardening

### System Restoration

#### Service Restoration
```bash
# Restart essential services
systemctl start [essential_service]
systemctl enable [essential_service]

# Verify service status
systemctl status [essential_service]
```

#### Network Restoration
```bash
# Remove temporary firewall rules
iptables -D OUTPUT -d [C2_IP] -j DROP
iptables -D INPUT -s [C2_IP] -j DROP

# Restore normal network access
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
```

### Security Hardening

#### Patch Management
```bash
# Linux: Update system
apt update && apt upgrade -y
yum update -y

# Windows: Install updates
Install-Module PSWindowsUpdate
Get-WUInstall -AcceptAll -AutoReboot
```

#### Configuration Hardening
```powershell
# Windows: Harden PowerShell
Set-ExecutionPolicy Restricted -Force

# Enable PowerShell logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Enable process creation auditing
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
```

#### Monitoring Enhancement
```bash
# Install additional monitoring
# Sysmon for Windows
# OSSEC/Wazuh for Linux

# Configure log forwarding
rsyslog_config="/etc/rsyslog.d/50-beacon-monitoring.conf"
echo "*.* @@[log_server]:514" > $rsyslog_config
systemctl restart rsyslog
```

---

## Documentation and Lessons Learned

### Incident Report Template

```markdown
# PvJ Beacon Incident Report

**Incident ID:** PVJ-BEACON-[YYYYMMDD]-[###]
**Date/Time:** [YYYY-MM-DD HH:MM:SS]
**Reporter:** [Name]
**Severity:** [Critical/High/Medium/Low]

## Executive Summary
[Brief description of the incident]

## Timeline
- **Detection:** [Time] - [Description]
- **Containment:** [Time] - [Description]
- **Investigation:** [Time] - [Description]
- **Eradication:** [Time] - [Description]
- **Recovery:** [Time] - [Description]

## Technical Details
- **Beacon Type:** [HTTP/DNS/SMB]
- **C2 Server:** [IP/Domain]
- **Affected Systems:** [List]
- **Attack Vector:** [Description]
- **Persistence Mechanism:** [Description]

## Response Actions
- [List of actions taken]

## Lessons Learned
- [What worked well]
- [What could be improved]
- [Recommendations]

## Artifacts
- [List of collected evidence]
```

### Post-Incident Activities

#### Team Debrief
1. **What happened?** - Factual timeline
2. **Why did it happen?** - Root cause analysis
3. **How can we prevent it?** - Preventive measures
4. **How can we detect it faster?** - Detection improvements
5. **How can we respond better?** - Response improvements

#### Process Improvements
- Update detection rules
- Enhance monitoring coverage
- Improve response procedures
- Conduct additional training

---

## Automated Response Scripts

### Beacon Killer Script
```bash
#!/bin/bash
# beacon_killer.sh - Automated beacon termination script

BEACON_IP="$1"
BEACON_DOMAIN="$2"

if [ -z "$BEACON_IP" ]; then
    echo "Usage: $0 <beacon_ip> [beacon_domain]"
    exit 1
fi

echo "Initiating automated beacon response for $BEACON_IP"

# Block network traffic
iptables -A OUTPUT -d $BEACON_IP -j DROP
iptables -A INPUT -s $BEACON_IP -j DROP

# Kill suspicious processes
ps aux | grep -E "(powershell|cmd|rundll32)" | grep -v grep | awk '{print $2}' | xargs kill -9

# Block domain if provided
if [ ! -z "$BEACON_DOMAIN" ]; then
    echo "127.0.0.1 $BEACON_DOMAIN" >> /etc/hosts
fi

# Clear DNS cache
systemctl flush-dns 2>/dev/null || service dns-clean restart 2>/dev/null

echo "Automated response completed for $BEACON_IP"
```

### Windows Beacon Response Script
```powershell
# BeaconResponse.ps1 - Automated Windows beacon response

param(
    [Parameter(Mandatory=$true)]
    [string]$BeaconIP,
    
    [Parameter(Mandatory=$false)]
    [string]$BeaconDomain
)

Write-Host "Initiating automated beacon response for $BeaconIP" -ForegroundColor Red

# Block network traffic
netsh advfirewall firewall add rule name="Block_Beacon_$BeaconIP" dir=out action=block remoteip=$BeaconIP
netsh advfirewall firewall add rule name="Block_Beacon_$BeaconIP" dir=in action=block remoteip=$BeaconIP

# Kill suspicious processes
$suspiciousProcesses = Get-Process | Where-Object {
    $_.ProcessName -match "powershell|cmd|rundll32|regsvr32|mshta|certutil"
}

foreach ($proc in $suspiciousProcesses) {
    try {
        Stop-Process -Id $proc.Id -Force
        Write-Host "Killed process: $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to kill process $($proc.ProcessName): $($_.Exception.Message)"
    }
}

# Block domain if provided
if ($BeaconDomain) {
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "127.0.0.1 $BeaconDomain"
    Write-Host "Blocked domain: $BeaconDomain" -ForegroundColor Yellow
}

# Clear DNS cache
Clear-DnsClientCache
ipconfig /flushdns

Write-Host "Automated response completed for $BeaconIP" -ForegroundColor Green
```

### Continuous Monitoring Script
```python
#!/usr/bin/env python3
# beacon_monitor.py - Continuous beacon monitoring

import time
import subprocess
import json
from datetime import datetime

class BeaconMonitor:
    def __init__(self):
        self.known_beacons = set()
        self.alert_threshold = 5
        
    def check_network_connections(self):
        """Check for suspicious network connections."""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            connections = result.stdout.split('\n')
            
            suspicious_connections = []
            for conn in connections:
                if 'ESTABLISHED' in conn:
                    parts = conn.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        
                        # Check for suspicious patterns
                        if self.is_suspicious_connection(remote_addr):
                            suspicious_connections.append({
                                'local': local_addr,
                                'remote': remote_addr,
                                'timestamp': datetime.now().isoformat()
                            })
            
            return suspicious_connections
        except Exception as e:
            print(f"Error checking connections: {e}")
            return []
    
    def is_suspicious_connection(self, remote_addr):
        """Determine if a connection is suspicious."""
        # Add your suspicious IP/domain logic here
        suspicious_indicators = [
            '192.168.1.100',  # Example C2 server
            'suspicious-domain.com'
        ]
        
        return any(indicator in remote_addr for indicator in suspicious_indicators)
    
    def respond_to_beacon(self, connection):
        """Automated response to detected beacon."""
        remote_ip = connection['remote'].split(':')[0]
        
        if remote_ip not in self.known_beacons:
            self.known_beacons.add(remote_ip)
            
            print(f"BEACON DETECTED: {remote_ip}")
            
            # Execute automated response
            subprocess.run(['./beacon_killer.sh', remote_ip])
            
            # Log the incident
            with open('beacon_incidents.log', 'a') as f:
                f.write(json.dumps(connection) + '\n')
    
    def monitor(self):
        """Main monitoring loop."""
        print("Starting beacon monitoring...")
        
        while True:
            try:
                suspicious_connections = self.check_network_connections()
                
                for conn in suspicious_connections:
                    self.respond_to_beacon(conn)
                
                time.sleep(30)  # Check every 30 seconds
                
            except KeyboardInterrupt:
                print("Monitoring stopped by user")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(60)

if __name__ == '__main__':
    monitor = BeaconMonitor()
    monitor.monitor()
```

---

## Conclusion

This playbook provides comprehensive procedures for responding to beacon detections in PvJ competitions. The key to a successful beacon response is:

1. **Speed** - Rapid detection and containment
2. **Precision** - Targeted response without disrupting legitimate services
3. **Documentation** - Thorough evidence collection and reporting
4. **Learning** - Continuous improvement based on incidents

Regular practice and simulation exercises are essential for effective implementation of these procedures during actual competition scenarios.

**Remember:** In PvJ competitions, the goal is to maintain service availability while eliminating threats. Balance security response with operational requirements.

