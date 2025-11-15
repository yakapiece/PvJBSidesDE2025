# 🪟 Windows Team: Ongoing Operations

*Time-based operational guide for Windows subteam - Continuous monitoring and maintenance*

---

## 🚨 V2 Safety Protocols - Always Remember

### Ongoing Operations Rules
- **DNS Check Every 30 Minutes**: DNS failure = zero points for all services
- **Test Before Deploy**: All changes tested on least critical system first
- **Service First**: 80% effort on keeping services running
- **15-Minute Investigation Limit**: Don't get lost in rabbit holes
- **Communicate Changes**: Share service-affecting changes immediately

---

## ⏰ Hour 1-2: Stabilization Phase

### Every 30 Minutes: DNS Health Check
```powershell
# Quick DNS verification (2 minutes max)
nslookup localhost
nslookup [your-domain]
Get-Service DNS | Select Name, Status
```
**🤝 Coordinate with BIND Team**: Report any DNS issues immediately

### Every 15 Minutes: Critical Service Status
```powershell
# Service health check (3 minutes max)
$CriticalServices = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP", "WinRM")
foreach ($service in $CriticalServices) {
    $svc = Get-Service $service -ErrorAction SilentlyContinue
    if ($svc.Status -ne "Running") {
        Write-Host "ALERT: $service is $($svc.Status)" -ForegroundColor Red
        # Auto-restart if stopped
        if ($svc.Status -eq "Stopped") {
            Restart-Service $service -Force
            Start-Sleep 3
            Get-Service $service
        }
    }
}
```

### Continuous Monitoring Setup
```powershell
# Set up basic monitoring script
$MonitorScript = @'
while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Check critical services
    $services = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP")
    foreach ($svc in $services) {
        $status = (Get-Service $svc -ErrorAction SilentlyContinue).Status
        if ($status -ne "Running") {
            Write-Host "$timestamp - ALERT: $svc is $status" | Tee-Object -FilePath C:\temp\service_alerts.log -Append
        }
    }
    
    Start-Sleep 300  # Check every 5 minutes
}
'@

# Save and optionally run monitoring script
$MonitorScript | Out-File C:\temp\service_monitor.ps1
# Start-Process powershell -ArgumentList "-File C:\temp\service_monitor.ps1" -WindowStyle Minimized
```

---

## ⏰ Hour 2-4: Active Defense Phase

### Every 30 Minutes: Security Monitoring
```powershell
# Quick security check (5 minutes max)
# New processes since last check
Get-Process | Where-Object {$_.StartTime -gt (Get-Date).AddMinutes(-30)} | Select Name, Id, StartTime, Path

# New network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.CreationTime -gt (Get-Date).AddMinutes(-30)} | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Failed logon attempts (last 30 minutes)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 10 -ErrorAction SilentlyContinue | Select TimeCreated, Message
```

### Every Hour: Account Security Review
```powershell
# Account activity check (3 minutes max)
# Recent successful logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20 -ErrorAction SilentlyContinue | Select TimeCreated, Message

# Check for new local accounts
$CurrentUsers = Get-LocalUser | Select Name, Enabled, LastLogon
$CurrentUsers | Export-Csv C:\temp\current_users_$(Get-Date -Format 'HHmm').csv

# Compare with baseline (if exists)
if (Test-Path C:\temp\baseline_users.csv) {
    $BaselineUsers = Import-Csv C:\temp\baseline_users.csv
    $NewUsers = Compare-Object $BaselineUsers.Name $CurrentUsers.Name | Where-Object {$_.SideIndicator -eq "=>"}
    if ($NewUsers) {
        Write-Host "NEW USERS DETECTED: $($NewUsers.InputObject)" -ForegroundColor Red
    }
}
```

### **🤝 Coordinate with Firewall Team**: Share suspicious network activity patterns

---

## ⏰ Hour 4-6: Optimization Phase

### Every 45 Minutes: Performance Monitoring
```powershell
# System performance check (3 minutes max)
# CPU and memory usage
Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3
Get-Counter "\Memory\Available MBytes" -SampleInterval 1 -MaxSamples 3

# Disk space check
Get-WmiObject -Class Win32_LogicalDisk | Select DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB,2)}}, @{Name="PercentFree";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}

# Service response times (if web services)
if (Get-Service W3SVC -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost" -TimeoutSec 10 -UseBasicParsing
        Write-Host "Web service response time: $($response.Headers.'X-Response-Time')" -ForegroundColor Green
    } catch {
        Write-Host "Web service check failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

### Service Optimization (if performance issues)
```powershell
# IIS optimization (if applicable)
Import-Module WebAdministration
# Check application pool recycling
Get-IISAppPool | Select Name, State, @{Name="WorkerProcesses";Expression={(Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -eq "w3wp.exe"}).Count}}

# SQL Server optimization (if applicable)
# Check SQL connections
# sqlcmd -S localhost -Q "SELECT COUNT(*) as ActiveConnections FROM sys.dm_exec_sessions WHERE status = 'running'"
```

---

## ⏰ Hour 6-8: Endgame Phase

### Every 20 Minutes: Critical Service Verification
```powershell
# Intensive service monitoring (2 minutes max)
$CriticalServices = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP", "WinRM")
foreach ($service in $CriticalServices) {
    $svc = Get-Service $service -ErrorAction SilentlyContinue
    if ($svc) {
        $status = $svc.Status
        $startType = $svc.StartType
        Write-Host "$service: $status ($startType)" -ForegroundColor $(if($status -eq "Running"){"Green"}else{"Red"})
        
        # Auto-restart critical services if stopped
        if ($status -eq "Stopped" -and $startType -eq "Automatic") {
            Write-Host "Auto-restarting $service" -ForegroundColor Yellow
            Start-Service $service
            Start-Sleep 3
        }
    }
}
```

### Final Security Sweep
```powershell
# Last-hour security check (5 minutes max)
# Check for any new persistence mechanisms
Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.Date -gt (Get-Date).AddHours(-1)} | Select TaskName, TaskPath, Date

# Check for new startup items
Get-CimInstance Win32_StartupCommand | Where-Object {$_.Name -notmatch "Microsoft|Windows|Intel|AMD"}

# Final process check
Get-Process | Where-Object {$_.ProcessName -match "nc|netcat|powershell|cmd" -and $_.StartTime -gt (Get-Date).AddHours(-1)} | Select Name, Id, StartTime, Path
```

### **🤝 Final Coordination with All Teams**
- Share any last-minute findings
- Confirm all services are stable
- Prepare for final scoring push

---

## 🔄 Continuous Tasks (Throughout Competition)

### Real-Time Monitoring Commands
```powershell
# Keep these running in separate PowerShell windows

# Window 1: Service Monitor
while ($true) {
    Clear-Host
    Write-Host "=== Windows Service Status - $(Get-Date) ===" -ForegroundColor Cyan
    $services = @("DNS", "W3SVC", "MSSQLSERVER", "Spooler", "DHCP", "WinRM")
    foreach ($svc in $services) {
        $status = (Get-Service $svc -ErrorAction SilentlyContinue).Status
        $color = if ($status -eq "Running") {"Green"} else {"Red"}
        Write-Host "$svc : $status" -ForegroundColor $color
    }
    Start-Sleep 30
}

# Window 2: Network Monitor
while ($true) {
    Clear-Host
    Write-Host "=== Network Connections - $(Get-Date) ===" -ForegroundColor Cyan
    Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select LocalAddress, LocalPort, RemoteAddress, RemotePort | Format-Table -AutoSize
    Start-Sleep 60
}

# Window 3: Event Monitor
while ($true) {
    Clear-Host
    Write-Host "=== Recent Security Events - $(Get-Date) ===" -ForegroundColor Cyan
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 5 -ErrorAction SilentlyContinue | Select TimeCreated, Id, Message | Format-Table -Wrap
    Start-Sleep 120
}
```

---

## 🚨 Incident Response Procedures

### Service Down Response (5-minute max)
1. **Immediate Check**:
   ```powershell
   Get-Service [ServiceName] | Select Name, Status, StartType
   Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10
   ```

2. **Quick Restart**:
   ```powershell
   Restart-Service [ServiceName] -Force
   Start-Sleep 5
   Get-Service [ServiceName]
   ```

3. **If Restart Fails**:
   ```powershell
   # Check dependencies
   Get-Service [ServiceName] -DependentServices
   Get-Service [ServiceName] -RequiredServices
   
   # Check service executable
   $service = Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "[ServiceName]"}
   Test-Path $service.PathName.Split('"')[1]
   ```

4. **Escalate**: If not resolved in 5 minutes, escalate to team lead

### Security Incident Response (15-minute max)
1. **Document**: Screenshot/copy evidence immediately
2. **Contain**: Isolate affected system if possible (coordinate with Firewall team)
3. **Assess Impact**: Check if scoring services affected
4. **Communicate**: Inform team lead and relevant teams
5. **Remediate**: Focus on service restoration, not perfect forensics

---

## 📊 Status Reporting Templates

### Hourly Status Report
```
WINDOWS TEAM - HOUR [X] STATUS
==============================
Time: [HH:MM]
Critical Services: [X/Y] Running
DNS Status: [WORKING/ISSUES]
Security Alerts: [COUNT] this hour
Performance: [GOOD/DEGRADED/POOR]
Issues Resolved: [LIST]
Current Focus: [ACTIVITY]
Next Hour Priority: [PRIORITY]
Team Coordination Needed: [ITEMS]
```

### End-of-Competition Summary
```
WINDOWS TEAM - FINAL REPORT
===========================
Total Uptime: [PERCENTAGE]
Services Managed: [LIST]
Incidents Handled: [COUNT]
Security Issues Found: [COUNT]
Cross-Team Coordination: [SUMMARY]
Lessons Learned: [KEY POINTS]
Recommendations: [FOR NEXT TIME]
```

---

## 🎯 Optimization Tips for Long Competition

### Energy Management
- **Rotate monitoring duties** every 2 hours
- **Take 5-minute breaks** every hour
- **Stay hydrated** and maintain blood sugar
- **Communicate regularly** to avoid isolation

### Technical Efficiency
- **Use PowerShell ISE** for script development
- **Keep command history** for repeated tasks
- **Use aliases** for frequently used commands
- **Prepare scripts** for common tasks

### Team Coordination
- **Regular check-ins** with other teams every 30 minutes
- **Share findings immediately** if they affect other teams
- **Document everything** for handoffs and lessons learned
- **Ask for help** if stuck for more than 15 minutes

---

## 🔧 Emergency Command Reference

### Quick Service Commands
```powershell
# Service management
Get-Service [name]
Start-Service [name]
Stop-Service [name]
Restart-Service [name] -Force
Set-Service [name] -StartupType Automatic

# Process management
Get-Process [name]
Stop-Process -Name [name] -Force
Stop-Process -Id [PID] -Force

# Network troubleshooting
Test-NetConnection [host] -Port [port]
Get-NetTCPConnection -State Established
netstat -an | findstr [port]

# Event logs
Get-WinEvent -LogName System -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
Get-EventLog -LogName Application -Newest 20
```

### Emergency Recovery
```powershell
# System file check
sfc /scannow

# DNS flush
ipconfig /flushdns
ipconfig /registerdns

# Network reset
netsh winsock reset
netsh int ip reset

# Service dependency check
sc query [servicename]
sc qc [servicename]
```

---

*Remember: In the final hours, focus on stability over optimization. Keep services running and communicate with your team. Simple solutions are often the best solutions.*

**Stay calm, stay focused, and prioritize service availability above all else.**

