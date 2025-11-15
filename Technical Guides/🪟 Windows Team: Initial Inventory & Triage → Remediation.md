# 🪟 Windows Team: Initial Inventory & Triage → Remediation

*Task-based guide for Windows subteam - Complete these tasks before moving to ongoing operations*

---

## 🚨 V2 Safety Protocols - READ FIRST

### Critical Rules for Windows Team
- **DNS Dependency**: If DNS fails, ALL Windows services score ZERO points
- **Change Testing**: Test ALL changes on least critical system first
- **Service Priority**: 80% effort on service restoration, 15% understanding, 5% evidence
- **No Snapshots**: Reverts cost points and take time - avoid breaking changes
- **Team Coordination**: Share service-affecting findings immediately

---

## 📋 Task 1: Immediate System Assessment (15 minutes max)

### Baseline Documentation
```powershell
# Document current state
Get-Process | Export-Csv C:\temp\baseline_processes.csv
Get-Service | Where-Object {$_.Status -eq "Running"} | Export-Csv C:\temp\baseline_services.csv
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Export-Csv C:\temp\baseline_connections.csv
Get-LocalUser | Export-Csv C:\temp\baseline_users.csv
```

### Critical Service Status Check
```powershell
# Check scoring-critical services
$CriticalServices = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP", "WinRM")
foreach ($service in $CriticalServices) {
    Get-Service $service -ErrorAction SilentlyContinue | Select Name, Status, StartType
}

# Check IIS application pools
Import-Module WebAdministration
Get-IISAppPool | Select Name, State
```

### Immediate Threat Detection (5 minutes only)
```powershell
# Quick process check for obvious threats
Get-Process | Where-Object {$_.ProcessName -match "nc|netcat|powershell|cmd"} | Select Name, Id, Path

# Check for suspicious network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemotePort -in @(443,80,53,4444,8080)} | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Recent logon events (last hour only)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} | Select -First 10 | Select TimeCreated, Id, LevelDisplayName, Message
```

**⏰ Time Limit**: Stop investigation after 15 minutes total - move to service restoration

---

## 📋 Task 2: DNS Health Verification (Critical - Work with BIND Team)

### DNS Service Status
```powershell
# Check DNS service
Get-Service DNS
Get-DnsServerZone
Get-DnsServerForwarder

# Test DNS resolution
nslookup localhost
nslookup [your-domain-name]
```

### **🤝 Coordinate with BIND Team**: Share DNS server IPs and verify resolution chain

### DNS Client Configuration
```powershell
# Check DNS client settings
Get-DnsClientServerAddress
Get-DnsClient

# Test external DNS resolution
nslookup google.com
nslookup 8.8.8.8
```

**🚨 Critical**: If DNS issues found, escalate to BIND team immediately - this affects ALL scoring

---

## 📋 Task 3: Account Security Lockdown

### User Account Audit
```powershell
# Check for new/suspicious accounts
Get-LocalUser | Where-Object {$_.LastLogon -gt (Get-Date).AddDays(-1)}
Get-LocalGroupMember Administrators
Get-LocalGroupMember "Remote Desktop Users"

# Check for accounts with no password expiry
Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true}
```

### Disable Risky Accounts (Test First!)
```powershell
# Document before changes
Get-LocalUser | Export-Csv C:\temp\users_before_changes.csv

# Disable suspicious accounts (VERIFY FIRST - don't break scoring!)
# Disable-LocalUser -Name "suspicious_account" -Confirm

# Change default passwords
# $SecurePassword = ConvertTo-SecureString "NewComplexPassword123!" -AsPlainText -Force
# Set-LocalUser -Name "Administrator" -Password $SecurePassword
```

### **🤝 Coordinate with *nix Team**: Share suspicious account names and patterns

---

## 📋 Task 4: Service Restoration Priority

### Critical Service Recovery
```powershell
# Restart failed critical services
$CriticalServices = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP")
foreach ($service in $CriticalServices) {
    $svc = Get-Service $service -ErrorAction SilentlyContinue
    if ($svc.Status -ne "Running") {
        Write-Host "Restarting $service"
        Restart-Service $service -Force
        Start-Sleep 5
        Get-Service $service
    }
}

# Check IIS application pools
Import-Module WebAdministration
Get-IISAppPool | Where-Object {$_.State -ne "Started"} | Start-WebAppPool
```

### Service Configuration Verification
```powershell
# Verify service startup types
$CriticalServices = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP")
foreach ($service in $CriticalServices) {
    Get-Service $service | Select Name, Status, StartType
    # Set to automatic if needed
    # Set-Service $service -StartupType Automatic
}
```

---

## 📋 Task 5: Network Security Assessment

### RDP Security (Work with Firewall Team)
```powershell
# Check RDP configuration
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber

# Check RDP users
Get-LocalGroupMember "Remote Desktop Users"
```

### **🤝 Coordinate with Firewall Team**: Share RDP port and access requirements for monitoring

### SMB Security
```powershell
# Check SMB configuration
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature
Get-SmbShare | Select Name, Path, Description

# Disable SMBv1 if enabled (TEST FIRST!)
# Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
```

---

## 📋 Task 6: Windows Firewall Configuration

### Firewall Status Check
```powershell
# Check Windows Firewall status
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Check critical firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True" -and $_.Direction -eq "Inbound"} | Select DisplayName, Action, Direction, Protocol, LocalPort
```

### **🚨 V2 Safety**: Windows Firewall for Monitoring Only
```powershell
# Enable logging for monitoring (DO NOT BLOCK SCORED SERVICES)
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767

# Check that scored services are NOT blocked
Get-NetFirewallRule | Where-Object {$_.Action -eq "Block" -and $_.Enabled -eq "True"} | Select DisplayName, LocalPort, RemotePort
```

**🚨 Critical**: Ensure no firewall rules block scored services - coordinate with Firewall team

---

## 📋 Task 7: Event Log Configuration & Analysis

### Enable Enhanced Logging
```powershell
# Enable PowerShell logging
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $RegPath)) { New-Item $RegPath -Force }
Set-ItemProperty $RegPath -Name EnableScriptBlockLogging -Value 1

# Enable process creation logging
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

### Critical Event Analysis (10 minutes max)
```powershell
# Failed logon attempts (last 2 hours)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-2)} | Select -First 20 | Select TimeCreated, Message

# Successful logons (last hour)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} | Select -First 10 | Select TimeCreated, Message

# Service start/stop events
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036; StartTime=(Get-Date).AddHours(-2)} | Select -First 20 | Select TimeCreated, Id, LevelDisplayName, Message
```

**⏰ Time Limit**: 10 minutes maximum for log analysis - focus on service restoration

---

## 📋 Task 8: Persistence Mechanism Check

### Startup Programs
```powershell
# Check startup items
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User

# Check scheduled tasks (focus on suspicious ones)
Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.TaskPath -notlike "\Microsoft\*"} | Select TaskName, TaskPath, State
```

### Registry Persistence Points
```powershell
# Check common persistence locations
$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $PersistenceKeys) {
    if (Test-Path $key) {
        Get-ItemProperty $key | Select PSPath, *
    }
}
```

**⏰ Time Limit**: 10 minutes maximum - document findings, don't deep-dive

---

## 📋 Task 9: Service-Specific Hardening

### IIS Security (if applicable)
```powershell
# Check IIS configuration
Import-Module WebAdministration
Get-Website | Select Name, State, PhysicalPath, Bindings
Get-WebBinding | Select Protocol, BindingInformation, SslFlags

# Basic IIS hardening (TEST FIRST!)
# Remove default website if not needed
# Remove-Website -Name "Default Web Site" -Confirm
```

### SQL Server Security (if applicable)
```powershell
# Check SQL Server services
Get-Service | Where-Object {$_.Name -like "*SQL*"} | Select Name, Status, StartType

# Basic SQL security check (if SQL tools available)
# sqlcmd -S localhost -Q "SELECT name FROM sys.databases"
```

---

## 📋 Task 10: Documentation & Handoff Preparation

### Change Documentation
```powershell
# Document all changes made
$ChangeLog = @"
Windows Team Change Log - $(Get-Date)
=====================================
Services Restarted: [List services]
Accounts Modified: [List accounts]
Firewall Changes: [List changes]
Configuration Changes: [List changes]
Issues Found: [List issues]
Coordination Needed: [List items for other teams]
"@

$ChangeLog | Out-File C:\temp\windows_changes.txt
```

### **🤝 Cross-Team Coordination Summary**
- **BIND Team**: DNS server status, resolution issues
- **Firewall Team**: RDP ports, SMB traffic, Windows Firewall rules
- ***nix Team**: Suspicious account patterns, cross-platform threats
- **All Teams**: Service status affecting scoring

### Status Report Template
```
WINDOWS TEAM STATUS - [TIME]
============================
Critical Services: [GREEN/YELLOW/RED]
DNS Resolution: [WORKING/ISSUES]
Security Issues: [COUNT] found, [COUNT] resolved
Immediate Needs: [List urgent items]
Next Phase: Ready for Ongoing Ops / Need [X] more time
```

---

## 🎯 Transition to Ongoing Ops

### Readiness Checklist
- [ ] All critical services running and verified
- [ ] DNS resolution working (confirmed with BIND team)
- [ ] Immediate security threats contained
- [ ] Account security baseline established
- [ ] Logging and monitoring configured
- [ ] Change documentation completed
- [ ] Cross-team coordination items communicated

### **When to Transition**
- All critical tasks completed OR
- 2 hours elapsed (whichever comes first)
- Move to "Windows Team: Ongoing Ops" guide

---

## 🚨 Emergency Procedures

### Service Down Emergency
1. **Check DNS first** (coordinate with BIND team)
2. **Restart service**: `Restart-Service [ServiceName] -Force`
3. **Check dependencies**: `Get-Service [ServiceName] -DependentServices`
4. **Verify configuration**: Check service-specific config files
5. **Escalate if needed**: Inform team lead within 10 minutes

### System Lockout Emergency
1. **Don't panic** - document what was changed
2. **Try safe mode** or alternate access method
3. **Contact team lead** immediately
4. **Consider marketplace revert** (costs points but may be faster)
5. **Document lessons learned** for team

---

*Focus on service restoration over perfect security. When in doubt, communicate with your team and prioritize scoring services.*

**Remember: Simple solutions often work better than complex ones in PvJ environment.**

