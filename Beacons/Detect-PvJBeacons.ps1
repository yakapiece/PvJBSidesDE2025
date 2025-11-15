# Detect-PvJBeacons.ps1
# PowerShell script for detecting beaconing activity in Pros vs Joes CTF competitions
# Author: Manus AI
# Date: 2025-07-12
# Version: 1.0

<#
.SYNOPSIS
    Detects beaconing activity commonly used in Pros vs Joes CTF competitions.

.DESCRIPTION
    This script implements multiple detection methods for identifying beacon activity:
    - Network connection pattern analysis
    - Process behavior monitoring
    - Named pipe detection (Cobalt Strike)
    - Registry persistence checks
    - Scheduled task analysis
    - PowerShell execution monitoring

.PARAMETER Duration
    Monitoring duration in seconds (default: 300)

.PARAMETER OutputFile
    Output file for detection results (default: beacon_detection_results.json)

.PARAMETER Verbose
    Enable verbose output

.EXAMPLE
    .\Detect-PvJBeacons.ps1 -Duration 600 -Verbose

.EXAMPLE
    .\Detect-PvJBeacons.ps1 -OutputFile "pvj_scan_results.json"
#>

[CmdletBinding()]
param(
    [int]$Duration = 300,
    [string]$OutputFile = "beacon_detection_results.json",
    [switch]$Verbose
)

# Global variables
$Global:DetectionResults = @()
$Global:StartTime = Get-Date
$Global:SuspiciousProcesses = @(
    'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe',
    'bitsadmin.exe', 'wmic.exe', 'net.exe', 'net1.exe'
)

$Global:CobaltStrikeIndicators = @(
    'BeaconDataParse', 'BeaconOutput', 'polling', 'jitter',
    'spawnto', 'jquery', 'dllhost.exe', 'msagent_', 'postex_'
)

function Write-DetectionLog {
    param(
        [string]$Type,
        [string]$Message,
        [hashtable]$Details = @{}
    )
    
    $logEntry = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Type = $Type
        Message = $Message
        Details = $Details
    }
    
    $Global:DetectionResults += $logEntry
    
    if ($Verbose) {
        Write-Host "[$($logEntry.Timestamp)] $Type: $Message" -ForegroundColor Yellow
        if ($Details.Count -gt 0) {
            $Details.GetEnumerator() | ForEach-Object {
                Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
            }
        }
    }
}

function Test-BeaconingPattern {
    param(
        [array]$Timestamps,
        [int]$MinConnections = 5,
        [double]$MaxJitter = 0.3,
        [int]$MinInterval = 30,
        [int]$MaxInterval = 3600
    )
    
    if ($Timestamps.Count -lt $MinConnections) {
        return $false
    }
    
    # Calculate intervals
    $intervals = @()
    for ($i = 1; $i -lt $Timestamps.Count; $i++) {
        $interval = ($Timestamps[$i] - $Timestamps[$i-1]).TotalSeconds
        $intervals += $interval
    }
    
    if ($intervals.Count -lt 3) {
        return $false
    }
    
    # Statistical analysis
    $meanInterval = ($intervals | Measure-Object -Average).Average
    $stdevInterval = if ($intervals.Count -gt 1) {
        [Math]::Sqrt(($intervals | ForEach-Object { [Math]::Pow($_ - $meanInterval, 2) } | Measure-Object -Sum).Sum / ($intervals.Count - 1))
    } else { 0 }
    
    $coefficientOfVariation = if ($meanInterval -gt 0) { $stdevInterval / $meanInterval } else { 1 }
    
    # Check beaconing characteristics
    return ($meanInterval -ge $MinInterval -and 
            $meanInterval -le $MaxInterval -and 
            $coefficientOfVariation -le $MaxJitter)
}

function Detect-NetworkBeacons {
    Write-Host "Analyzing network connections for beaconing patterns..." -ForegroundColor Green
    
    $connectionHistory = @{}
    $endTime = (Get-Date).AddSeconds($Duration)
    
    while ((Get-Date) -lt $endTime) {
        try {
            $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
            
            foreach ($conn in $connections) {
                $key = "$($conn.LocalAddress):$($conn.RemoteAddress):$($conn.RemotePort)"
                $timestamp = Get-Date
                
                if (-not $connectionHistory.ContainsKey($key)) {
                    $connectionHistory[$key] = @()
                }
                $connectionHistory[$key] += $timestamp
            }
            
            Start-Sleep -Seconds 5
        }
        catch {
            Write-Warning "Error monitoring network connections: $($_.Exception.Message)"
        }
    }
    
    # Analyze patterns
    foreach ($key in $connectionHistory.Keys) {
        $timestamps = $connectionHistory[$key]
        
        if (Test-BeaconingPattern -Timestamps $timestamps) {
            $parts = $key -split ':'
            $localAddr = $parts[0]
            $remoteAddr = $parts[1]
            $remotePort = $parts[2]
            
            # Calculate statistics
            $intervals = @()
            for ($i = 1; $i -lt $timestamps.Count; $i++) {
                $intervals += ($timestamps[$i] - $timestamps[$i-1]).TotalSeconds
            }
            
            $avgInterval = ($intervals | Measure-Object -Average).Average
            $stdev = if ($intervals.Count -gt 1) {
                [Math]::Sqrt(($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Sum).Sum / ($intervals.Count - 1))
            } else { 0 }
            $jitter = if ($avgInterval -gt 0) { $stdev / $avgInterval } else { 0 }
            
            Write-DetectionLog -Type "NETWORK_BEACON" -Message "Regular network beaconing detected" -Details @{
                LocalAddress = $localAddr
                RemoteAddress = $remoteAddr
                RemotePort = $remotePort
                ConnectionCount = $timestamps.Count
                AverageInterval = [Math]::Round($avgInterval, 2)
                JitterCoefficient = [Math]::Round($jitter, 3)
                RegularityScore = [Math]::Round(1 - $jitter, 3)
            }
        }
    }
}

function Detect-ProcessBeacons {
    Write-Host "Monitoring processes for suspicious beacon-like behavior..." -ForegroundColor Green
    
    $processActivity = @{}
    $endTime = (Get-Date).AddSeconds($Duration)
    
    while ((Get-Date) -lt $endTime) {
        try {
            $processes = Get-Process | Where-Object {
                $_.ProcessName -in $Global:SuspiciousProcesses -or
                $_.ProcessName -match "^[a-f0-9]{8,}$" -or  # Random hex names
                $_.Path -match "temp|appdata|programdata"
            }
            
            foreach ($proc in $processes) {
                try {
                    $connections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
                    
                    if ($connections) {
                        $timestamp = Get-Date
                        
                        if (-not $processActivity.ContainsKey($proc.Id)) {
                            $processActivity[$proc.Id] = @{
                                ProcessName = $proc.ProcessName
                                Path = $proc.Path
                                Timestamps = @()
                            }
                        }
                        $processActivity[$proc.Id].Timestamps += $timestamp
                        
                        # Immediate alert for suspicious processes with network activity
                        if ($proc.ProcessName -in $Global:SuspiciousProcesses) {
                            Write-DetectionLog -Type "SUSPICIOUS_PROCESS" -Message "Suspicious process with network activity" -Details @{
                                ProcessName = $proc.ProcessName
                                PID = $proc.Id
                                Path = $proc.Path
                                ConnectionCount = $connections.Count
                                CommandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                            }
                        }
                    }
                }
                catch {
                    # Process may have exited or access denied
                    continue
                }
            }
            
            Start-Sleep -Seconds 10
        }
        catch {
            Write-Warning "Error monitoring processes: $($_.Exception.Message)"
        }
    }
    
    # Analyze process activity patterns
    foreach ($pid in $processActivity.Keys) {
        $activity = $processActivity[$pid]
        $timestamps = $activity.Timestamps
        
        if (Test-BeaconingPattern -Timestamps $timestamps) {
            $intervals = @()
            for ($i = 1; $i -lt $timestamps.Count; $i++) {
                $intervals += ($timestamps[$i] - $timestamps[$i-1]).TotalSeconds
            }
            
            $avgInterval = ($intervals | Measure-Object -Average).Average
            $stdev = if ($intervals.Count -gt 1) {
                [Math]::Sqrt(($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Sum).Sum / ($intervals.Count - 1))
            } else { 0 }
            $jitter = if ($avgInterval -gt 0) { $stdev / $avgInterval } else { 0 }
            
            Write-DetectionLog -Type "PROCESS_BEACON" -Message "Regular activity pattern in process" -Details @{
                ProcessName = $activity.ProcessName
                PID = $pid
                Path = $activity.Path
                ActivityCount = $timestamps.Count
                AverageInterval = [Math]::Round($avgInterval, 2)
                JitterCoefficient = [Math]::Round($jitter, 3)
            }
        }
    }
}

function Detect-NamedPipes {
    Write-Host "Scanning for suspicious named pipes (Cobalt Strike indicators)..." -ForegroundColor Green
    
    try {
        # Get named pipe events from Security log
        $pipeEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5145} -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Where-Object {$_.Message -match "\\\\\.\\pipe\\"}
        
        foreach ($event in $pipeEvents) {
            $message = $event.Message
            
            # Extract pipe name
            if ($message -match "\\\\\.\\pipe\\([^\\s]+)") {
                $pipeName = $matches[1]
                
                # Check for Cobalt Strike default pipe names
                if ($pipeName -match "^(msagent_|postex_|status_|screenshot_|keylogger_)") {
                    Write-DetectionLog -Type "COBALT_STRIKE_PIPE" -Message "Cobalt Strike named pipe detected" -Details @{
                        PipeName = $pipeName
                        EventTime = $event.TimeCreated
                        ProcessId = $event.ProcessId
                        EventId = $event.Id
                    }
                }
                
                # Check for other suspicious patterns
                if ($pipeName -match "^[a-f0-9]{8,}$" -or $pipeName -match "beacon|implant|shell") {
                    Write-DetectionLog -Type "SUSPICIOUS_PIPE" -Message "Suspicious named pipe detected" -Details @{
                        PipeName = $pipeName
                        EventTime = $event.TimeCreated
                        ProcessId = $event.ProcessId
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error scanning named pipes: $($_.Exception.Message)"
    }
}

function Detect-PersistenceMechanisms {
    Write-Host "Checking for beacon persistence mechanisms..." -ForegroundColor Green
    
    # Check registry run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $runKeys) {
        try {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            
            if ($entries) {
                $entries.PSObject.Properties | Where-Object {
                    $_.Name -notmatch "^PS" -and
                    ($_.Value -match "powershell|cmd|certutil|bitsadmin" -or
                     $_.Value -match "temp|appdata|programdata" -or
                     $_.Value -match "http|ftp|\.ps1|\.bat|\.vbs")
                } | ForEach-Object {
                    Write-DetectionLog -Type "SUSPICIOUS_PERSISTENCE" -Message "Suspicious registry persistence entry" -Details @{
                        RegistryKey = $key
                        EntryName = $_.Name
                        EntryValue = $_.Value
                    }
                }
            }
        }
        catch {
            Write-Warning "Error checking registry key $key : $($_.Exception.Message)"
        }
    }
    
    # Check scheduled tasks
    try {
        $tasks = Get-ScheduledTask | Where-Object {
            $_.TaskName -match "^[a-f0-9]{8,}$" -or
            $_.Actions.Execute -match "powershell|cmd|certutil|bitsadmin" -or
            $_.Actions.Arguments -match "http|ftp|\.ps1|\.bat|\.vbs"
        }
        
        foreach ($task in $tasks) {
            Write-DetectionLog -Type "SUSPICIOUS_SCHEDULED_TASK" -Message "Suspicious scheduled task detected" -Details @{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Execute = $task.Actions.Execute
                Arguments = $task.Actions.Arguments
            }
        }
    }
    catch {
        Write-Warning "Error checking scheduled tasks: $($_.Exception.Message)"
    }
}

function Detect-PowerShellActivity {
    Write-Host "Monitoring PowerShell execution for beacon indicators..." -ForegroundColor Green
    
    try {
        # Check PowerShell event logs
        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 500 -ErrorAction SilentlyContinue
        
        foreach ($event in $psEvents) {
            $scriptBlock = $event.Message
            
            # Check for suspicious PowerShell patterns
            $suspiciousPatterns = @(
                'IEX\s*\(',
                'Invoke-Expression',
                'DownloadString',
                'WebClient',
                'Net\.WebClient',
                'System\.Net\.WebClient',
                'certutil.*-decode',
                'certutil.*-urlcache',
                'bitsadmin.*transfer',
                'Start-Process.*Hidden',
                'bypass.*execution.*policy',
                'EncodedCommand',
                'FromBase64String',
                'ComObject.*WScript\.Shell'
            )
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($scriptBlock -match $pattern) {
                    Write-DetectionLog -Type "SUSPICIOUS_POWERSHELL" -Message "Suspicious PowerShell execution detected" -Details @{
                        EventTime = $event.TimeCreated
                        ProcessId = $event.ProcessId
                        Pattern = $pattern
                        ScriptBlock = $scriptBlock.Substring(0, [Math]::Min(500, $scriptBlock.Length))
                    }
                    break
                }
            }
            
            # Check for Cobalt Strike indicators
            foreach ($indicator in $Global:CobaltStrikeIndicators) {
                if ($scriptBlock -match $indicator) {
                    Write-DetectionLog -Type "COBALT_STRIKE_POWERSHELL" -Message "Cobalt Strike PowerShell indicator detected" -Details @{
                        EventTime = $event.TimeCreated
                        ProcessId = $event.ProcessId
                        Indicator = $indicator
                        ScriptBlock = $scriptBlock.Substring(0, [Math]::Min(500, $scriptBlock.Length))
                    }
                    break
                }
            }
        }
    }
    catch {
        Write-Warning "Error monitoring PowerShell activity: $($_.Exception.Message)"
    }
}

function Detect-DNSBeacons {
    Write-Host "Analyzing DNS queries for beaconing patterns..." -ForegroundColor Green
    
    try {
        # Monitor DNS queries (requires DNS logging to be enabled)
        $dnsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; ID=3008} -MaxEvents 1000 -ErrorAction SilentlyContinue
        
        $dnsQueries = @{}
        
        foreach ($event in $dnsEvents) {
            if ($event.Message -match "Query Name:\s*([^\s]+)") {
                $queryName = $matches[1].TrimEnd('.')
                $timestamp = $event.TimeCreated
                
                if (-not $dnsQueries.ContainsKey($queryName)) {
                    $dnsQueries[$queryName] = @()
                }
                $dnsQueries[$queryName] += $timestamp
            }
        }
        
        # Analyze DNS query patterns
        foreach ($domain in $dnsQueries.Keys) {
            $timestamps = $dnsQueries[$domain]
            
            if (Test-BeaconingPattern -Timestamps $timestamps) {
                $intervals = @()
                for ($i = 1; $i -lt $timestamps.Count; $i++) {
                    $intervals += ($timestamps[$i] - $timestamps[$i-1]).TotalSeconds
                }
                
                $avgInterval = ($intervals | Measure-Object -Average).Average
                $stdev = if ($intervals.Count -gt 1) {
                    [Math]::Sqrt(($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Sum).Sum / ($intervals.Count - 1))
                } else { 0 }
                $jitter = if ($avgInterval -gt 0) { $stdev / $avgInterval } else { 0 }
                
                Write-DetectionLog -Type "DNS_BEACON" -Message "DNS beaconing pattern detected" -Details @{
                    Domain = $domain
                    QueryCount = $timestamps.Count
                    AverageInterval = [Math]::Round($avgInterval, 2)
                    JitterCoefficient = [Math]::Round($jitter, 3)
                }
            }
            
            # Check for suspicious domains
            $suspiciousDomains = @('pastebin.com', 'hastebin.com', 'github.com', 'githubusercontent.com')
            if ($suspiciousDomains | Where-Object { $domain -match $_ }) {
                Write-DetectionLog -Type "SUSPICIOUS_DNS" -Message "DNS query to suspicious domain" -Details @{
                    Domain = $domain
                    QueryCount = $timestamps.Count
                    FirstQuery = $timestamps[0]
                    LastQuery = $timestamps[-1]
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing DNS queries: $($_.Exception.Message)"
    }
}

function Generate-Report {
    Write-Host "Generating detection report..." -ForegroundColor Green
    
    $report = @{
        ScanTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Duration = $Duration
        TotalAlerts = $Global:DetectionResults.Count
        AlertSummary = @{}
        Alerts = $Global:DetectionResults
    }
    
    # Summarize alerts by type
    $Global:DetectionResults | Group-Object Type | ForEach-Object {
        $report.AlertSummary[$_.Name] = $_.Count
    }
    
    # Convert to JSON and save
    $jsonReport = $report | ConvertTo-Json -Depth 10
    $jsonReport | Out-File -FilePath $OutputFile -Encoding UTF8
    
    # Display summary
    Write-Host "`nDetection Report Generated: $OutputFile" -ForegroundColor Green
    Write-Host "Total Alerts: $($report.TotalAlerts)" -ForegroundColor Yellow
    
    if ($report.AlertSummary.Count -gt 0) {
        Write-Host "Alert Summary:" -ForegroundColor Yellow
        $report.AlertSummary.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "No suspicious activity detected." -ForegroundColor Green
    }
    
    return $report
}

# Main execution
Write-Host "PvJ Beacon Detection Script v1.0" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Cyan
Write-Host "Monitoring Duration: $Duration seconds" -ForegroundColor Yellow
Write-Host "Output File: $OutputFile" -ForegroundColor Yellow
Write-Host ""

try {
    # Run all detection methods
    Detect-NetworkBeacons
    Detect-ProcessBeacons
    Detect-NamedPipes
    Detect-PersistenceMechanisms
    Detect-PowerShellActivity
    Detect-DNSBeacons
    
    # Generate final report
    $report = Generate-Report
    
    Write-Host "`nDetection completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Error during detection: $($_.Exception.Message)"
    Generate-Report
}
finally {
    Write-Host "Scan completed at $(Get-Date)" -ForegroundColor Gray
}

