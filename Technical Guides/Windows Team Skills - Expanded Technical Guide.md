# 🪟 Windows Team Skills - Expanded Technical Guide

## Core Technical Skills

### **Windows Server Administration**

#### **Basic Level**: Navigate Server Manager, understand roles/features, basic service management
- **Skills**: Server Manager navigation, role/feature installation, basic service operations
- **Time to Develop**: 2-3 weeks with consistent practice

**Essential Commands with Examples:**
```powershell
# Service Management
Get-Service | Where-Object {$_.Status -eq "Running"}
Start-Service -Name "Spooler"
Stop-Service -Name "Spooler" -Force
Restart-Service -Name "Spooler"
Set-Service -Name "Spooler" -StartupType Automatic

# Server Role Management
Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"}
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Remove-WindowsFeature -Name Web-Server
Get-WindowsFeature -Name "*IIS*"

# System Information
Get-ComputerInfo
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
Get-EventLog -LogName System -Newest 50 | Where-Object {$_.EntryType -eq "Error"}

# Basic Network Configuration
Get-NetIPConfiguration
Get-NetAdapter
Test-NetConnection -ComputerName "google.com" -Port 80
```

**Online Learning Resources:**
- [Microsoft Learn - Windows Server](https://docs.microsoft.com/en-us/learn/browse/?products=windows-server) - Official Microsoft training paths
- [Windows Server Documentation](https://docs.microsoft.com/en-us/windows-server/) - Comprehensive official documentation
- [TechNet Virtual Labs](https://www.microsoft.com/handsonlabs) - Free hands-on practice environments
- [Pluralsight Windows Server](https://www.pluralsight.com/browse/it-ops/windows-server) - Structured video training
- [CBT Nuggets Windows Server](https://www.cbtnuggets.com/it-training/microsoft-windows-server) - Interactive training modules

**Books & References:**
- **"Windows Server 2022 Administration Fundamentals" by Bekim Dauti** - Comprehensive server administration
- **"Mastering Windows Server 2019" by Jordan Krause** - Advanced server management
- **"Windows Server 2019 Inside Out" by Orin Thomas** - In-depth technical reference
- **"Windows Server Cookbook" by Robbie Allen** - Practical solutions and recipes

#### **Intermediate Level**: Install/configure IIS, Active Directory basics, PowerShell fundamentals
- **Skills**: IIS configuration, basic AD operations, PowerShell scripting, system troubleshooting
- **Time to Develop**: 1-3 months with hands-on practice

**Essential Commands with Examples:**
```powershell
# IIS Management
Import-Module WebAdministration
Get-Website
New-Website -Name "TestSite" -Port 8080 -PhysicalPath "C:\inetpub\testsite"
Remove-Website -Name "TestSite"
Get-WebBinding -Name "Default Web Site"
New-WebBinding -Name "Default Web Site" -Protocol https -Port 443

# Active Directory Basics
Import-Module ActiveDirectory
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com"
Set-ADUser -Identity "jdoe" -Enabled $true
Get-ADGroup -Filter * | Select-Object Name, GroupScope

# PowerShell Fundamentals
Get-Command -Module ActiveDirectory
Get-Help Get-ADUser -Examples
$users = Get-ADUser -Filter {Enabled -eq $true}
$users | Export-Csv -Path "C:\temp\users.csv" -NoTypeInformation

# System Monitoring
Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 5
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
```

**Online Learning Resources:**
- [IIS.NET Documentation](https://www.iis.net/learn) - Comprehensive IIS learning center
- [Active Directory Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/) - Official AD DS documentation
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/) - Complete PowerShell reference
- [Windows Server Academy](https://academy.microsoft.com/) - Microsoft's official training platform
- [Petri IT Knowledgebase](https://petri.com/windows-server) - Practical Windows Server tutorials

**Repositories & Tools:**
- [PowerShell Gallery](https://www.powershellgallery.com/) - Official PowerShell module repository
- [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) - Advanced system utilities
- [Windows Admin Center](https://www.microsoft.com/en-us/windows-server/windows-admin-center) - Modern server management
- [IIS Administration API](https://github.com/Microsoft/IIS.Administration) - REST API for IIS management

#### **Advanced Level**: Complex AD troubleshooting, Group Policy management, advanced PowerShell scripting
- **Skills**: Advanced troubleshooting, GPO management, complex automation, performance optimization
- **Time to Develop**: 3-6 months with enterprise experience

**Essential Commands with Examples:**
```powershell
# Advanced Active Directory Troubleshooting
repadmin /showrepl
dcdiag /v
nltest /dsgetdc:domain.com
Get-ADReplicationFailure -Target "DC01.domain.com"
Get-ADReplicationPartnerMetadata -Target "DC01.domain.com"

# Group Policy Management
Import-Module GroupPolicy
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime
New-GPO -Name "Security Policy" -Comment "Enhanced security settings"
Set-GPRegistryValue -Name "Security Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "NoAutoUpdate" -Type DWord -Value 1
Get-GPOReport -Name "Security Policy" -ReportType Html -Path "C:\temp\gpo-report.html"

# Advanced PowerShell Scripting
function Get-SystemHealth {
    param(
        [string[]]$ComputerName = $env:COMPUTERNAME
    )
    
    foreach ($Computer in $ComputerName) {
        $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
        $CPU = Get-WmiObject -Class Win32_Processor -ComputerName $Computer
        $Memory = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Computer
        
        [PSCustomObject]@{
            ComputerName = $Computer
            OSVersion = $OS.Caption
            CPUUsage = (Get-Counter "\Processor(_Total)\% Processor Time" -ComputerName $Computer).CounterSamples.CookedValue
            MemoryGB = [math]::Round(($Memory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
            FreeSpaceGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
        }
    }
}

# Performance Monitoring and Optimization
Get-Counter "\Memory\Available MBytes" -Continuous
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 50
Get-EventLog -LogName Application -EntryType Error -Newest 20
```

**Advanced Learning Resources:**
- [Microsoft Virtual Academy](https://mva.microsoft.com/) - Advanced technical training
- [Windows Server TechCenter](https://techcommunity.microsoft.com/t5/windows-server/ct-p/Windows-Server) - Technical community and resources
- [PowerShell.org](https://powershell.org/) - Community-driven PowerShell resources
- [Group Policy Central](https://gpsearch.azurewebsites.net/) - Comprehensive GPO reference
- [Active Directory Security](https://adsecurity.org/) - Advanced AD security topics

**Advanced Tools & Repositories:**
- [PowerShell DSC](https://github.com/PowerShell/PowerShellDSC) - Desired State Configuration
- [Pester](https://github.com/pester/Pester) - PowerShell testing framework
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - PowerShell code analysis
- [Active Directory Assessment](https://github.com/canix1/ADACLScanner) - AD security assessment tools

#### **SME Level**: Enterprise AD design, automation frameworks, disaster recovery planning
- **Skills**: Enterprise architecture, strategic planning, automation frameworks, disaster recovery
- **Time to Develop**: 6+ months to years of enterprise experience

**Essential Commands with Examples:**
```powershell
# Enterprise Active Directory Management
# Forest and Domain Health Assessment
$Forest = Get-ADForest
$Domains = Get-ADDomain -Filter *
foreach ($Domain in $Domains) {
    Write-Host "Domain: $($Domain.DNSRoot)"
    $DCs = Get-ADDomainController -Filter * -Server $Domain.DNSRoot
    foreach ($DC in $DCs) {
        Write-Host "  DC: $($DC.Name) - Site: $($DC.Site)"
        $Replication = Get-ADReplicationPartnerMetadata -Target $DC.Name
        Write-Host "    Last Replication: $($Replication.LastReplicationSuccess)"
    }
}

# Automation Framework Example
class ADUserManager {
    [string]$Domain
    [string]$OU
    
    ADUserManager([string]$Domain, [string]$OU) {
        $this.Domain = $Domain
        $this.OU = $OU
    }
    
    [void]CreateUser([hashtable]$UserData) {
        $params = @{
            Name = $UserData.Name
            SamAccountName = $UserData.SamAccountName
            UserPrincipalName = "$($UserData.SamAccountName)@$($this.Domain)"
            Path = $this.OU
            Enabled = $true
            PasswordNeverExpires = $false
            ChangePasswordAtLogon = $true
        }
        New-ADUser @params
    }
    
    [void]BulkCreateUsers([array]$Users) {
        foreach ($User in $Users) {
            try {
                $this.CreateUser($User)
                Write-Host "Created user: $($User.Name)" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create user: $($User.Name) - $($_.Exception.Message)"
            }
        }
    }
}

# Disaster Recovery Automation
function Backup-ADEnvironment {
    param(
        [string]$BackupPath = "C:\ADBackup\$(Get-Date -Format 'yyyyMMdd')"
    )
    
    # Create backup directory
    New-Item -Path $BackupPath -ItemType Directory -Force
    
    # Backup Group Policy Objects
    Backup-GPO -All -Path "$BackupPath\GPO"
    
    # Export AD Schema
    ldifde -f "$BackupPath\schema.ldf" -s localhost -d "CN=Schema,CN=Configuration,DC=domain,DC=com"
    
    # Export all users
    Get-ADUser -Filter * -Properties * | Export-Csv "$BackupPath\users.csv" -NoTypeInformation
    
    # Export all groups
    Get-ADGroup -Filter * -Properties * | Export-Csv "$BackupPath\groups.csv" -NoTypeInformation
    
    # System State Backup
    wbadmin start systemstatebackup -backupTarget:$BackupPath -quiet
    
    Write-Host "AD Environment backup completed: $BackupPath"
}

# Performance Monitoring and Alerting
function Monitor-ADHealth {
    $HealthReport = @()
    
    # Check DC Services
    $Services = @('ADWS', 'DNS', 'DFS', 'DFSR', 'Eventlog', 'EventSystem', 'KDC', 'lanmanserver', 'lanmanworkstation', 'Netlogon', 'NTDS', 'RpcSs', 'SamSs', 'W32Time')
    foreach ($Service in $Services) {
        $ServiceStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
        $HealthReport += [PSCustomObject]@{
            Component = "Service"
            Name = $Service
            Status = if ($ServiceStatus) { $ServiceStatus.Status } else { "Not Found" }
            Healthy = ($ServiceStatus.Status -eq "Running")
        }
    }
    
    # Check Replication
    $ReplPartners = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME
    foreach ($Partner in $ReplPartners) {
        $HealthReport += [PSCustomObject]@{
            Component = "Replication"
            Name = $Partner.Partner
            Status = $Partner.LastReplicationResult
            Healthy = ($Partner.LastReplicationResult -eq 0)
        }
    }
    
    return $HealthReport
}
```

**Strategic Learning Resources:**
- [Microsoft Enterprise Mobility + Security](https://docs.microsoft.com/en-us/enterprise-mobility-security/) - Enterprise identity and security
- [Windows Server Technical Documentation](https://docs.microsoft.com/en-us/windows-server/get-started/) - Comprehensive technical reference
- [PowerShell Team Blog](https://devblogs.microsoft.com/powershell/) - Latest PowerShell developments
- [Active Directory Security Blog](https://adsecurity.org/) - Advanced security topics and research
- [Microsoft Security Response Center](https://msrc.microsoft.com/) - Security advisories and updates

**Enterprise Tools & Frameworks:**
- [Microsoft System Center](https://www.microsoft.com/en-us/cloud-platform/system-center) - Enterprise management suite
- [Azure AD Connect](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/) - Hybrid identity integration
- [PowerShell Universal](https://github.com/ironmansoftware/universal-dashboard) - Enterprise PowerShell automation
- [Desired State Configuration](https://docs.microsoft.com/en-us/powershell/scripting/dsc/) - Configuration management

---

### **PowerShell & Command Line**

#### **Basic Level**: Basic cmdlets, pipeline understanding
- **Skills**: Fundamental cmdlets, pipeline operations, basic scripting concepts
- **Time to Develop**: 1-2 weeks with daily practice

**Essential Commands with Examples:**
```powershell
# Core Cmdlets
Get-Command | Measure-Object  # Count all available commands
Get-Help Get-Process -Examples
Get-Process | Where-Object {$_.CPU -gt 100}
Get-Service | Sort-Object Status | Format-Table Name, Status, StartType

# Pipeline Operations
Get-EventLog -LogName System -Newest 100 | Where-Object {$_.EntryType -eq "Error"} | Select-Object TimeGenerated, Source, Message
Get-ChildItem C:\ -Recurse | Where-Object {$_.Length -gt 100MB} | Sort-Object Length -Descending

# Basic Variables and Objects
$services = Get-Service
$runningServices = $services | Where-Object {$_.Status -eq "Running"}
$runningServices.Count

# File Operations
Get-ChildItem -Path "C:\Windows\System32" -Filter "*.exe" | Select-Object Name, Length, LastWriteTime
Copy-Item -Path "C:\source\file.txt" -Destination "C:\destination\"
Remove-Item -Path "C:\temp\*" -Recurse -Force

# Basic Output and Formatting
Get-Process | Export-Csv -Path "C:\temp\processes.csv" -NoTypeInformation
Get-Service | ConvertTo-Html | Out-File "C:\temp\services.html"
Get-EventLog -LogName Application -Newest 10 | Format-List *
```

**Online Learning Resources:**
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/) - Official Microsoft PowerShell docs
- [PowerShell.org](https://powershell.org/) - Community-driven learning resources
- [Learn PowerShell in a Month of Lunches](https://www.manning.com/books/learn-powershell-in-a-month-of-lunches) - Structured learning approach
- [PowerShell Gallery](https://www.powershellgallery.com/) - Module repository and examples
- [Microsoft Virtual Academy PowerShell](https://mva.microsoft.com/en-us/training-courses/getting-started-with-powershell-3-0-jump-start-8276) - Free video training

**Books & References:**
- **"Learn PowerShell in a Month of Lunches" by Don Jones and Jeffrey Hicks** - Beginner-friendly structured approach
- **"PowerShell in Depth" by Don Jones, Jeffrey Hicks, and Richard Siddaway** - Comprehensive technical reference
- **"Windows PowerShell Cookbook" by Lee Holmes** - Practical solutions and examples
- **"PowerShell for Sysadmins" by Adam Bertram** - Real-world automation scenarios

#### **Intermediate Level**: Script writing, remote management, WMI queries, error handling
- **Skills**: Script development, remote PowerShell, WMI/CIM operations, error handling
- **Time to Develop**: 1-3 months with regular scripting practice

**Essential Commands with Examples:**
```powershell
# Script Writing Fundamentals
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName,
    [string]$LogPath = "C:\temp\system-report.txt"
)

function Get-SystemReport {
    param([string]$Computer)
    
    try {
        $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
        $CPU = Get-WmiObject -Class Win32_Processor -ComputerName $Computer -ErrorAction Stop
        $Memory = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Computer -ErrorAction Stop
        
        $Report = [PSCustomObject]@{
            ComputerName = $Computer
            OSVersion = $OS.Caption
            TotalMemoryGB = [math]::Round(($Memory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
            CPUName = $CPU.Name
            Timestamp = Get-Date
        }
        
        return $Report
    }
    catch {
        Write-Error "Failed to get system report for $Computer`: $($_.Exception.Message)"
        return $null
    }
}

# Remote Management
$cred = Get-Credential
$session = New-PSSession -ComputerName "Server01" -Credential $cred
Invoke-Command -Session $session -ScriptBlock {
    Get-Service | Where-Object {$_.Status -eq "Stopped"}
}
Remove-PSSession $session

# WMI and CIM Queries
Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | 
    Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}, 
    @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}

Get-CimInstance -ClassName Win32_Service | Where-Object {$_.State -eq "Running"} | 
    Select-Object Name, ProcessId, StartMode

# Error Handling
try {
    $result = Get-Service -Name "NonExistentService" -ErrorAction Stop
}
catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
    Write-Warning "Service not found: $($_.Exception.Message)"
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
}
finally {
    Write-Host "Cleanup completed"
}

# Advanced Pipeline Operations
Get-EventLog -LogName System -Newest 1000 | 
    Where-Object {$_.EntryType -eq "Error" -and $_.TimeGenerated -gt (Get-Date).AddDays(-7)} |
    Group-Object Source | 
    Sort-Object Count -Descending |
    Select-Object Name, Count, @{Name="LatestError";Expression={($_.Group | Sort-Object TimeGenerated -Descending | Select-Object -First 1).Message}}
```

**Advanced Learning Resources:**
- [PowerShell Team Blog](https://devblogs.microsoft.com/powershell/) - Latest developments and best practices
- [PowerShell.org eBooks](https://leanpub.com/u/powershellorg) - Free and paid advanced topics
- [Iron Scripter](https://ironscripter.us/) - PowerShell challenges and competitions
- [PowerShell Magazine](http://www.powershellmagazine.com/) - Technical articles and tutorials
- [Reddit PowerShell Community](https://www.reddit.com/r/PowerShell/) - Community discussions and help

**Tools & Repositories:**
- [PowerShell ISE](https://docs.microsoft.com/en-us/powershell/scripting/components/ise/) - Integrated scripting environment
- [Visual Studio Code with PowerShell Extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell) - Modern development environment
- [Pester](https://github.com/pester/Pester) - PowerShell testing framework
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - Code quality analysis

#### **Advanced Level**: Advanced functions, modules, DSC basics, complex automation
- **Skills**: Module development, DSC implementation, advanced automation, performance optimization
- **Time to Develop**: 3-6 months with complex project experience

**Essential Commands with Examples:**
```powershell
# Advanced Function Development
function Get-SystemInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("CN","MachineName")]
        [string[]]$ComputerName,
        
        [Parameter()]
        [ValidateSet("Hardware","Software","Network","All")]
        [string]$InventoryType = "All",
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$IncludeErrors
    )
    
    begin {
        Write-Verbose "Starting system inventory collection"
        $ErrorActionPreference = if ($IncludeErrors) { "Continue" } else { "SilentlyContinue" }
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Processing computer: $Computer"
            
            $sessionParams = @{
                ComputerName = $Computer
                ErrorAction = "Stop"
            }
            if ($Credential) { $sessionParams.Credential = $Credential }
            
            try {
                $session = New-PSSession @sessionParams
                
                $inventory = Invoke-Command -Session $session -ScriptBlock {
                    param($Type)
                    
                    $result = [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        Hardware = $null
                        Software = $null
                        Network = $null
                        CollectionTime = Get-Date
                    }
                    
                    if ($Type -in @("Hardware", "All")) {
                        $result.Hardware = @{
                            OS = (Get-WmiObject Win32_OperatingSystem).Caption
                            CPU = (Get-WmiObject Win32_Processor).Name
                            Memory = [math]::Round((Get-WmiObject Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
                            Disks = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | 
                                Select-Object DeviceID, @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}}
                        }
                    }
                    
                    if ($Type -in @("Software", "All")) {
                        $result.Software = @{
                            InstalledPrograms = Get-WmiObject Win32_Product | Select-Object Name, Version, Vendor
                            Services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, StartType
                            Processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, WorkingSet
                        }
                    }
                    
                    if ($Type -in @("Network", "All")) {
                        $result.Network = @{
                            IPConfiguration = Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Up"}
                            OpenPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
                                Select-Object LocalAddress, LocalPort, OwningProcess
                        }
                    }
                    
                    return $result
                } -ArgumentList $InventoryType
                
                Remove-PSSession $session
                Write-Output $inventory
            }
            catch {
                if ($IncludeErrors) {
                    Write-Error "Failed to collect inventory from $Computer`: $($_.Exception.Message)"
                }
            }
        }
    }
    
    end {
        Write-Verbose "System inventory collection completed"
    }
}

# Module Development Structure
# Create module manifest
New-ModuleManifest -Path ".\SystemTools.psd1" -ModuleVersion "1.0.0" -Author "Your Name" -Description "System administration tools"

# Module structure example
# SystemTools/
#   ├── SystemTools.psd1 (manifest)
#   ├── SystemTools.psm1 (main module)
#   ├── Public/
#   │   ├── Get-SystemInventory.ps1
#   │   └── Set-SystemConfiguration.ps1
#   ├── Private/
#   │   └── Helper-Functions.ps1
#   └── Tests/
#       └── SystemTools.Tests.ps1

# DSC Configuration Example
Configuration WebServerConfig {
    param(
        [string[]]$ComputerName = "localhost"
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node $ComputerName {
        WindowsFeature IIS {
            Ensure = "Present"
            Name = "IIS-WebServerRole"
        }
        
        WindowsFeature IISManagement {
            Ensure = "Present"
            Name = "IIS-ManagementConsole"
            DependsOn = "[WindowsFeature]IIS"
        }
        
        File WebContent {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\inetpub\wwwroot\myapp"
            DependsOn = "[WindowsFeature]IIS"
        }
        
        Registry DisableIEESC {
            Ensure = "Present"
            Key = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            ValueName = "IsInstalled"
            ValueData = "0"
            ValueType = "Dword"
        }
    }
}

# Complex Automation Example
class ServerManager {
    [string]$ServerName
    [System.Management.Automation.PSCredential]$Credential
    [System.Management.Automation.Runspaces.PSSession]$Session
    
    ServerManager([string]$ServerName, [System.Management.Automation.PSCredential]$Credential) {
        $this.ServerName = $ServerName
        $this.Credential = $Credential
        $this.Connect()
    }
    
    [void]Connect() {
        try {
            $this.Session = New-PSSession -ComputerName $this.ServerName -Credential $this.Credential
            Write-Host "Connected to $($this.ServerName)" -ForegroundColor Green
        }
        catch {
            throw "Failed to connect to $($this.ServerName): $($_.Exception.Message)"
        }
    }
    
    [object]InvokeCommand([scriptblock]$ScriptBlock) {
        if (-not $this.Session) {
            throw "No active session to $($this.ServerName)"
        }
        return Invoke-Command -Session $this.Session -ScriptBlock $ScriptBlock
    }
    
    [void]InstallFeature([string]$FeatureName) {
        $result = $this.InvokeCommand({
            param($Feature)
            Install-WindowsFeature -Name $Feature -IncludeManagementTools
        }.GetNewClosure()) -ArgumentList $FeatureName
        
        if ($result.Success) {
            Write-Host "Feature $FeatureName installed successfully on $($this.ServerName)" -ForegroundColor Green
        } else {
            Write-Error "Failed to install feature $FeatureName on $($this.ServerName)"
        }
    }
    
    [void]Disconnect() {
        if ($this.Session) {
            Remove-PSSession $this.Session
            $this.Session = $null
            Write-Host "Disconnected from $($this.ServerName)" -ForegroundColor Yellow
        }
    }
}
```

**Expert Learning Resources:**
- [PowerShell Conference EU](https://psconf.eu/) - Annual European PowerShell conference
- [PowerShell + DevOps Global Summit](https://powershell.org/summit/) - Premier PowerShell event
- [PowerShell DSC Documentation](https://docs.microsoft.com/en-us/powershell/scripting/dsc/) - Desired State Configuration
- [PowerShell Classes Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes) - Object-oriented PowerShell
- [Advanced PowerShell Scripting](https://www.pluralsight.com/courses/advanced-powershell-scripting) - Advanced techniques

**Advanced Tools & Frameworks:**
- [PowerShell Universal](https://ironmansoftware.com/powershell-universal) - Enterprise PowerShell platform
- [Polaris](https://github.com/PowerShell/Polaris) - PowerShell web framework
- [ImportExcel](https://github.com/dfinke/ImportExcel) - Excel manipulation without Excel
- [PoshBot](https://github.com/poshbotio/PoshBot) - PowerShell-based chatbot framework

#### **SME Level**: Framework development, security best practices, enterprise automation
- **Skills**: Enterprise frameworks, security architecture, advanced automation, team leadership
- **Time to Develop**: 6+ months to years of enterprise experience

**Essential Commands with Examples:**
```powershell
# Enterprise Framework Development
# PowerShell Module for Enterprise Management
@"
# EnterpriseTools.psm1
using namespace System.Management.Automation
using namespace System.Collections.Generic

class EnterpriseLogger {
    [string]$LogPath
    [string]$LogLevel
    
    EnterpriseLogger([string]$LogPath, [string]$LogLevel = "Info") {
        $this.LogPath = $LogPath
        $this.LogLevel = $LogLevel
        $this.InitializeLog()
    }
    
    [void]InitializeLog() {
        if (-not (Test-Path (Split-Path $this.LogPath))) {
            New-Item -Path (Split-Path $this.LogPath) -ItemType Directory -Force
        }
        $this.WriteLog("Info", "Logger initialized")
    }
    
    [void]WriteLog([string]$Level, [string]$Message) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $this.LogPath -Value $logEntry
        
        switch ($Level) {
            "Error" { Write-Error $Message }
            "Warning" { Write-Warning $Message }
            "Info" { Write-Information $Message -InformationAction Continue }
            "Verbose" { Write-Verbose $Message }
        }
    }
}

class EnterpriseConfigManager {
    [hashtable]$Configuration
    [string]$ConfigPath
    [EnterpriseLogger]$Logger
    
    EnterpriseConfigManager([string]$ConfigPath, [EnterpriseLogger]$Logger) {
        $this.ConfigPath = $ConfigPath
        $this.Logger = $Logger
        $this.LoadConfiguration()
    }
    
    [void]LoadConfiguration() {
        try {
            if (Test-Path $this.ConfigPath) {
                $this.Configuration = Get-Content $this.ConfigPath | ConvertFrom-Json -AsHashtable
                $this.Logger.WriteLog("Info", "Configuration loaded from $($this.ConfigPath)")
            } else {
                $this.Configuration = @{}
                $this.Logger.WriteLog("Warning", "Configuration file not found, using empty configuration")
            }
        }
        catch {
            $this.Logger.WriteLog("Error", "Failed to load configuration: $($_.Exception.Message)")
            $this.Configuration = @{}
        }
    }
    
    [object]GetSetting([string]$Key, [object]$DefaultValue = $null) {
        if ($this.Configuration.ContainsKey($Key)) {
            return $this.Configuration[$Key]
        }
        $this.Logger.WriteLog("Warning", "Setting '$Key' not found, using default value")
        return $DefaultValue
    }
    
    [void]SetSetting([string]$Key, [object]$Value) {
        $this.Configuration[$Key] = $Value
        $this.SaveConfiguration()
        $this.Logger.WriteLog("Info", "Setting '$Key' updated")
    }
    
    [void]SaveConfiguration() {
        try {
            $this.Configuration | ConvertTo-Json -Depth 10 | Set-Content $this.ConfigPath
            $this.Logger.WriteLog("Info", "Configuration saved to $($this.ConfigPath)")
        }
        catch {
            $this.Logger.WriteLog("Error", "Failed to save configuration: $($_.Exception.Message)")
        }
    }
}

# Security Best Practices Implementation
function Invoke-SecureCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$UseSSL,
        
        [Parameter()]
        [int]$TimeoutSeconds = 300
    )
    
    begin {
        # Input validation and sanitization
        if ($ScriptBlock.ToString() -match "(Invoke-Expression|iex|&|cmd|powershell)") {
            throw "Potentially dangerous commands detected in script block"
        }
        
        # Audit logging
        $auditEntry = @{
            Timestamp = Get-Date
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            ScriptBlock = $ScriptBlock.ToString()
            ComputerName = $ComputerName
            UseSSL = $UseSSL
        }
        
        # Log to security event log
        Write-EventLog -LogName "Application" -Source "PowerShell Security" -EventId 1001 -EntryType Information -Message ($auditEntry | ConvertTo-Json)
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            try {
                $sessionOptions = New-PSSessionOption -SkipCACheck:$false -SkipCNCheck:$false
                
                $sessionParams = @{
                    ComputerName = $Computer
                    SessionOption = $sessionOptions
                    ErrorAction = "Stop"
                }
                
                if ($Credential) { $sessionParams.Credential = $Credential }
                if ($UseSSL) { $sessionParams.UseSSL = $true }
                
                $session = New-PSSession @sessionParams
                
                # Execute with timeout
                $job = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -AsJob
                $result = Wait-Job -Job $job -Timeout $TimeoutSeconds
                
                if ($result) {
                    $output = Receive-Job -Job $job
                    Remove-Job -Job $job
                    Remove-PSSession $session
                    
                    Write-Output $output
                } else {
                    Remove-Job -Job $job -Force
                    Remove-PSSession $session
                    throw "Command execution timed out after $TimeoutSeconds seconds"
                }
            }
            catch {
                Write-Error "Failed to execute command on $Computer`: $($_.Exception.Message)"
            }
        }
    }
}

# Enterprise Automation Framework
class EnterpriseAutomation {
    [EnterpriseLogger]$Logger
    [EnterpriseConfigManager]$Config
    [hashtable]$TaskQueue
    [bool]$IsRunning
    
    EnterpriseAutomation([string]$ConfigPath, [string]$LogPath) {
        $this.Logger = [EnterpriseLogger]::new($LogPath)
        $this.Config = [EnterpriseConfigManager]::new($ConfigPath, $this.Logger)
        $this.TaskQueue = @{}
        $this.IsRunning = $false
    }
    
    [void]RegisterTask([string]$TaskName, [scriptblock]$TaskScript, [string]$Schedule) {
        $task = @{
            Name = $TaskName
            Script = $TaskScript
            Schedule = $Schedule
            LastRun = $null
            NextRun = $this.CalculateNextRun($Schedule)
            Status = "Registered"
        }
        
        $this.TaskQueue[$TaskName] = $task
        $this.Logger.WriteLog("Info", "Task '$TaskName' registered with schedule '$Schedule'")
    }
    
    [datetime]CalculateNextRun([string]$Schedule) {
        # Simple schedule parser - extend as needed
        switch -Regex ($Schedule) {
            "^Daily at (\d{2}):(\d{2})$" {
                $hour = [int]$Matches[1]
                $minute = [int]$Matches[2]
                $nextRun = (Get-Date).Date.AddHours($hour).AddMinutes($minute)
                if ($nextRun -lt (Get-Date)) {
                    $nextRun = $nextRun.AddDays(1)
                }
                return $nextRun
            }
            "^Every (\d+) minutes$" {
                $minutes = [int]$Matches[1]
                return (Get-Date).AddMinutes($minutes)
            }
            default {
                return (Get-Date).AddHours(1) # Default to 1 hour
            }
        }
    }
    
    [void]StartScheduler() {
        $this.IsRunning = $true
        $this.Logger.WriteLog("Info", "Enterprise automation scheduler started")
        
        while ($this.IsRunning) {
            $currentTime = Get-Date
            
            foreach ($taskName in $this.TaskQueue.Keys) {
                $task = $this.TaskQueue[$taskName]
                
                if ($currentTime -ge $task.NextRun -and $task.Status -ne "Running") {
                    $this.ExecuteTask($taskName)
                }
            }
            
            Start-Sleep -Seconds 60 # Check every minute
        }
    }
    
    [void]ExecuteTask([string]$TaskName) {
        $task = $this.TaskQueue[$TaskName]
        $task.Status = "Running"
        $task.LastRun = Get-Date
        
        $this.Logger.WriteLog("Info", "Executing task '$TaskName'")
        
        try {
            $result = & $task.Script
            $task.Status = "Completed"
            $task.NextRun = $this.CalculateNextRun($task.Schedule)
            $this.Logger.WriteLog("Info", "Task '$TaskName' completed successfully")
        }
        catch {
            $task.Status = "Failed"
            $this.Logger.WriteLog("Error", "Task '$TaskName' failed: $($_.Exception.Message)")
        }
        
        $this.TaskQueue[$TaskName] = $task
    }
    
    [void]StopScheduler() {
        $this.IsRunning = $false
        $this.Logger.WriteLog("Info", "Enterprise automation scheduler stopped")
    }
}
"@ | Set-Content -Path "EnterpriseTools.psm1"

# Usage Example
$automation = [EnterpriseAutomation]::new("C:\Config\enterprise.json", "C:\Logs\enterprise.log")

$automation.RegisterTask("SystemHealth", {
    Get-Service | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"} | 
        ForEach-Object { Start-Service $_.Name -ErrorAction SilentlyContinue }
}, "Every 30 minutes")

$automation.RegisterTask("DiskCleanup", {
    Get-ChildItem "C:\temp" -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} | 
        Remove-Item -Force -Recurse
}, "Daily at 02:00")

# Start the automation scheduler
$automation.StartScheduler()
```

**Strategic Learning Resources:**
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/security/powershell-security-best-practices) - Official security guidance
- [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) - Security constraints
- [Just Enough Administration (JEA)](https://docs.microsoft.com/en-us/powershell/scripting/security/remoting/jea/) - Privileged access management
- [PowerShell Execution Policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) - Security policies
- [Enterprise PowerShell Architecture](https://docs.microsoft.com/en-us/powershell/scripting/security/) - Enterprise deployment

**Enterprise Frameworks & Tools:**
- [PowerShell Universal](https://ironmansoftware.com/powershell-universal) - Enterprise automation platform
- [Azure Automation](https://docs.microsoft.com/en-us/azure/automation/) - Cloud-based automation
- [System Center Orchestrator](https://docs.microsoft.com/en-us/system-center/orchestrator/) - Enterprise workflow automation
- [PowerShell Desired State Configuration](https://docs.microsoft.com/en-us/powershell/scripting/dsc/) - Configuration management

---

### **Active Directory & Authentication**

#### **Basic Level**: User/group management, basic OU structure, password resets
- **Skills**: Basic AD operations, user lifecycle management, group administration
- **Time to Develop**: 2-3 weeks with hands-on practice

**Essential Commands with Examples:**
```powershell
# User Management
Import-Module ActiveDirectory

# Create new user
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@contoso.com" -GivenName "John" -Surname "Doe" -DisplayName "John Doe" -Path "OU=Users,DC=contoso,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -Enabled $true

# Modify user properties
Set-ADUser -Identity "jdoe" -Title "System Administrator" -Department "IT" -Manager "manager@contoso.com"

# Reset password
Set-ADAccountPassword -Identity "jdoe" -NewPassword (ConvertTo-SecureString "NewP@ssw0rd123" -AsPlainText -Force) -Reset

# Unlock account
Unlock-ADAccount -Identity "jdoe"

# Disable/Enable user
Disable-ADAccount -Identity "jdoe"
Enable-ADAccount -Identity "jdoe"

# Group Management
New-ADGroup -Name "IT Administrators" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=contoso,DC=com"
Add-ADGroupMember -Identity "IT Administrators" -Members "jdoe"
Remove-ADGroupMember -Identity "IT Administrators" -Members "jdoe" -Confirm:$false
Get-ADGroupMember -Identity "IT Administrators"

# OU Management
New-ADOrganizationalUnit -Name "IT Department" -Path "DC=contoso,DC=com"
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Basic Queries
Get-ADUser -Filter {Enabled -eq $true} | Select-Object Name, SamAccountName, LastLogonDate
Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-30)} | Select-Object Name, LastLogonDate
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory
```

**Online Learning Resources:**
- [Active Directory Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/) - Official Microsoft AD DS documentation
- [Active Directory Fundamentals](https://docs.microsoft.com/en-us/learn/paths/identity-with-azure-ad/) - Microsoft Learn path
- [Petri Active Directory](https://petri.com/active-directory) - Practical AD tutorials and guides
- [TechNet Active Directory](https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-domain-services-survival-guide.aspx) - Community knowledge base
- [Active Directory Pro](https://activedirectorypro.com/) - Specialized AD learning resources

**Books & References:**
- **"Active Directory" by Brian Desmond, Joe Richards, Robbie Allen, and Alistair Lowe-Norris** - Comprehensive AD reference
- **"Mastering Active Directory" by Dishan Francis** - Practical AD administration
- **"Active Directory Cookbook" by Laura Hunter and Robbie Allen** - Solutions-oriented approach
- **"Windows Server 2019 Active Directory" by Sander Berkouwer** - Modern AD implementation

#### **Intermediate Level**: Group Policy basics, trust relationships, LDAP queries
- **Skills**: GPO management, domain trusts, LDAP operations, advanced user management
- **Time to Develop**: 1-3 months with enterprise exposure

**Essential Commands with Examples:**
```powershell
# Group Policy Management
Import-Module GroupPolicy

# Create and configure GPO
New-GPO -Name "Security Baseline" -Comment "Enterprise security settings"
Set-GPRegistryValue -Name "Security Baseline" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "NoAutoUpdate" -Type DWord -Value 1

# Link GPO to OU
New-GPLink -Name "Security Baseline" -Target "OU=Workstations,DC=contoso,DC=com" -LinkEnabled Yes

# Generate GPO reports
Get-GPOReport -Name "Security Baseline" -ReportType Html -Path "C:\temp\gpo-report.html"
Get-GPOReport -All -ReportType Xml -Path "C:\temp\all-gpos.xml"

# GPO troubleshooting
Get-GPResultantSetOfPolicy -Computer "WORKSTATION01" -User "contoso\jdoe" -ReportType Html -Path "C:\temp\rsop.html"

# Trust Relationships
# View existing trusts
Get-ADTrust -Filter *

# Create trust (requires appropriate permissions)
# New-ADTrust -Name "partnerdomain.com" -Type External -Direction Bidirectional

# Test trust
Test-ComputerSecureChannel -Verbose
nltest /sc_query:contoso.com

# LDAP Queries
# Basic LDAP search
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=contoso,DC=com")
$searcher.Filter = "(&(objectClass=user)(sAMAccountName=jdoe))"
$result = $searcher.FindOne()
$result.Properties

# Advanced LDAP queries
$searcher.Filter = "(&(objectClass=user)(lastLogonTimestamp<=$((Get-Date).AddDays(-30).ToFileTime())))"
$inactiveUsers = $searcher.FindAll()

# Using .NET DirectoryServices
Add-Type -AssemblyName System.DirectoryServices
$domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=contoso,DC=com")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
$searcher.Filter = "(&(objectClass=computer)(operatingSystem=Windows Server*))"
$servers = $searcher.FindAll()

# Advanced User Management
# Bulk user creation from CSV
$users = Import-Csv "C:\temp\users.csv"
foreach ($user in $users) {
    $params = @{
        Name = "$($user.FirstName) $($user.LastName)"
        SamAccountName = $user.Username
        UserPrincipalName = "$($user.Username)@contoso.com"
        GivenName = $user.FirstName
        Surname = $user.LastName
        DisplayName = "$($user.FirstName) $($user.LastName)"
        Path = $user.OU
        Department = $user.Department
        Title = $user.Title
        AccountPassword = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
        Enabled = $true
        ChangePasswordAtLogon = $true
    }
    
    try {
        New-ADUser @params
        Write-Host "Created user: $($user.Username)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create user $($user.Username): $($_.Exception.Message)"
    }
}

# Group membership management
$groupMembers = Get-ADGroupMember -Identity "Domain Admins"
$groupMembers | ForEach-Object {
    $user = Get-ADUser -Identity $_.SamAccountName -Properties LastLogonDate, PasswordLastSet
    [PSCustomObject]@{
        Name = $user.Name
        SamAccountName = $user.SamAccountName
        LastLogon = $user.LastLogonDate
        PasswordAge = if ($user.PasswordLastSet) { (Get-Date) - $user.PasswordLastSet } else { "Never" }
    }
}
```

**Advanced Learning Resources:**
- [Group Policy Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/) - Official GPO documentation
- [LDAP Query Basics](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx) - LDAP syntax reference
- [Active Directory Trusts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models) - Trust relationship planning
- [PowerShell for Active Directory](https://docs.microsoft.com/en-us/powershell/module/addsadministration/) - AD PowerShell module reference
- [Group Policy Central](https://gpsearch.azurewebsites.net/) - GPO settings database

**Tools & Repositories:**
- [Group Policy Management Console (GPMC)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc725932(v=ws.10)) - GPO management tool
- [Active Directory Administrative Center](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-administrative-center) - Modern AD management
- [LDP.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772839(v=ws.10)) - LDAP browser and editor
- [ADSIEdit](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773354(v=ws.10)) - Low-level AD editor

#### **Advanced Level**: Complex GPO troubleshooting, replication issues, security hardening
- **Skills**: Advanced troubleshooting, replication management, security implementation, performance optimization
- **Time to Develop**: 3-6 months with complex enterprise scenarios

**Essential Commands with Examples:**
```powershell
# Advanced GPO Troubleshooting
# GPO processing analysis
gpresult /h "C:\temp\gpresult.html" /f
Get-GPResultantSetOfPolicy -Computer $env:COMPUTERNAME -ReportType Html -Path "C:\temp\rsop.html"

# GPO replication status
Get-ADReplicationPartnerMetadata -Target "DC01.contoso.com" | Where-Object {$_.Partition -like "*CN=Policies*"}

# GPO version checking
$gpos = Get-GPO -All
foreach ($gpo in $gpos) {
    $gpoData = Get-GPO -Guid $gpo.Id
    [PSCustomObject]@{
        Name = $gpo.DisplayName
        UserVersion = $gpoData.User.DSVersion
        ComputerVersion = $gpoData.Computer.DSVersion
        UserSysvolVersion = $gpoData.User.SysvolVersion
        ComputerSysvolVersion = $gpoData.Computer.SysvolVersion
        VersionMismatch = ($gpoData.User.DSVersion -ne $gpoData.User.SysvolVersion) -or ($gpoData.Computer.DSVersion -ne $gpoData.Computer.SysvolVersion)
    }
}

# Replication Troubleshooting
# Check replication health
repadmin /replsummary
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object {$_."Number of Failures" -gt 0}

# Force replication
repadmin /syncall /AdeP

# Check replication partners
Get-ADReplicationConnection -Filter *
Get-ADReplicationSite -Filter *

# Detailed replication analysis
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    Write-Host "Checking replication for $($dc.Name)" -ForegroundColor Yellow
    $replData = Get-ADReplicationPartnerMetadata -Target $dc.Name
    $replData | Select-Object Partner, LastReplicationSuccess, LastReplicationResult | Format-Table
}

# Security Hardening
# Audit policy configuration
auditpol /get /category:*

# Set advanced audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Password policy analysis
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *

# Security group analysis
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($group in $privilegedGroups) {
    Write-Host "Members of $group:" -ForegroundColor Yellow
    Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName, ObjectClass
}

# Kerberos ticket analysis
klist tickets
klist tgt

# Advanced Security Monitoring
function Get-ADSecurityReport {
    $report = @()
    
    # Check for accounts with non-expiring passwords
    $nonExpiringPasswords = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires
    $report += [PSCustomObject]@{
        Category = "Password Security"
        Issue = "Non-expiring passwords"
        Count = $nonExpiringPasswords.Count
        Details = $nonExpiringPasswords.SamAccountName -join ", "
    }
    
    # Check for old passwords
    $oldPasswords = Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet | 
        Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-90)}
    $report += [PSCustomObject]@{
        Category = "Password Security"
        Issue = "Passwords older than 90 days"
        Count = $oldPasswords.Count
        Details = ($oldPasswords | Select-Object -First 5).SamAccountName -join ", "
    }
    
    # Check for inactive accounts
    $inactiveAccounts = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | 
        Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90) -or $_.LastLogonDate -eq $null}
    $report += [PSCustomObject]@{
        Category = "Account Management"
        Issue = "Inactive accounts (90+ days)"
        Count = $inactiveAccounts.Count
        Details = ($inactiveAccounts | Select-Object -First 5).SamAccountName -join ", "
    }
    
    # Check for privileged account usage
    $privilegedUsers = Get-ADGroupMember -Identity "Domain Admins" -Recursive
    foreach ($user in $privilegedUsers) {
        $userInfo = Get-ADUser -Identity $user.SamAccountName -Properties LastLogonDate
        $report += [PSCustomObject]@{
            Category = "Privileged Access"
            Issue = "Domain Admin last logon"
            Count = 1
            Details = "$($userInfo.SamAccountName): $($userInfo.LastLogonDate)"
        }
    }
    
    return $report
}

# Performance Optimization
# LDAP query performance
Measure-Command {
    Get-ADUser -Filter * -Properties *
}

# Optimized query
Measure-Command {
    Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate
}

# Index analysis (requires Schema Admin rights)
# Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=contoso,DC=com" -Filter {searchFlags -band 1} -Properties lDAPDisplayName, searchFlags

# Database maintenance
# ntdsutil "activate instance ntds" "files" "info" quit quit
```

**Expert Learning Resources:**
- [Active Directory Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/) - Replication architecture and troubleshooting
- [Group Policy Troubleshooting](https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/) - Advanced GPO troubleshooting
- [Active Directory Security](https://adsecurity.org/) - Security research and best practices
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) - Security baselines
- [Active Directory Forest Recovery](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-guide) - Disaster recovery procedures

**Advanced Tools & Repositories:**
- [Repadmin](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc770963(v=ws.11)) - Replication diagnostic tool
- [DCDiag](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc731968(v=ws.11)) - Domain controller diagnostic tool
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD attack path analysis
- [PingCastle](https://www.pingcastle.com/) - AD security assessment tool

#### **SME Level**: Forest/domain design, advanced security, disaster recovery
- **Skills**: Enterprise architecture, strategic planning, advanced security, disaster recovery planning
- **Time to Develop**: 6+ months to years of enterprise experience

**Essential Commands with Examples:**
```powershell
# Enterprise Forest Design Analysis
function Get-ADForestHealth {
    param(
        [switch]$Detailed
    )
    
    $forest = Get-ADForest
    $domains = Get-ADDomain -Filter *
    $report = @()
    
    # Forest-level analysis
    $forestInfo = [PSCustomObject]@{
        Component = "Forest"
        Name = $forest.Name
        ForestMode = $forest.ForestMode
        DomainNamingMaster = $forest.DomainNamingMaster
        SchemaMaster = $forest.SchemaMaster
        Domains = $forest.Domains.Count
        Sites = (Get-ADReplicationSite -Filter *).Count
        GlobalCatalogs = $forest.GlobalCatalogs.Count
    }
    $report += $forestInfo
    
    # Domain-level analysis
    foreach ($domain in $domains) {
        $domainInfo = [PSCustomObject]@{
            Component = "Domain"
            Name = $domain.DNSRoot
            DomainMode = $domain.DomainMode
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainControllers = (Get-ADDomainController -Filter * -Server $domain.DNSRoot).Count
            Users = (Get-ADUser -Filter * -Server $domain.DNSRoot).Count
            Computers = (Get-ADComputer -Filter * -Server $domain.DNSRoot).Count
        }
        $report += $domainInfo
        
        if ($Detailed) {
            # Site and replication analysis
            $sites = Get-ADReplicationSite -Filter * -Server $domain.DNSRoot
            foreach ($site in $sites) {
                $siteInfo = [PSCustomObject]@{
                    Component = "Site"
                    Name = $site.Name
                    Domain = $domain.DNSRoot
                    Subnets = (Get-ADReplicationSubnet -Filter {Site -eq $site.Name} -Server $domain.DNSRoot).Count
                    DomainControllers = (Get-ADDomainController -Filter {Site -eq $site.Name} -Server $domain.DNSRoot).Count
                }
                $report += $siteInfo
            }
        }
    }
    
    return $report
}

# Advanced Security Implementation
class ADSecurityManager {
    [string]$Domain
    [System.Collections.ArrayList]$SecurityPolicies
    [hashtable]$AuditSettings
    
    ADSecurityManager([string]$Domain) {
        $this.Domain = $Domain
        $this.SecurityPolicies = @()
        $this.AuditSettings = @{}
        $this.InitializeSecurityBaseline()
    }
    
    [void]InitializeSecurityBaseline() {
        # Define security baseline policies
        $this.SecurityPolicies.Add(@{
            Name = "Password Policy"
            Settings = @{
                MinPasswordLength = 14
                PasswordComplexity = $true
                MaxPasswordAge = 60
                MinPasswordAge = 1
                PasswordHistoryCount = 24
            }
        })
        
        $this.SecurityPolicies.Add(@{
            Name = "Account Lockout Policy"
            Settings = @{
                LockoutThreshold = 5
                LockoutDuration = 30
                ResetLockoutCounterAfter = 30
            }
        })
        
        $this.SecurityPolicies.Add(@{
            Name = "Kerberos Policy"
            Settings = @{
                MaxTicketAge = 10
                MaxRenewAge = 7
                MaxServiceAge = 600
                MaxClockSkew = 5
            }
        })
    }
    
    [void]ApplySecurityBaseline() {
        foreach ($policy in $this.SecurityPolicies) {
            Write-Host "Applying $($policy.Name)..." -ForegroundColor Yellow
            
            switch ($policy.Name) {
                "Password Policy" {
                    $this.ConfigurePasswordPolicy($policy.Settings)
                }
                "Account Lockout Policy" {
                    $this.ConfigureAccountLockoutPolicy($policy.Settings)
                }
                "Kerberos Policy" {
                    $this.ConfigureKerberosPolicy($policy.Settings)
                }
            }
        }
    }
    
    [void]ConfigurePasswordPolicy([hashtable]$Settings) {
        # Implementation would use Group Policy or direct domain policy modification
        # This is a simplified example
        Write-Host "  - Minimum password length: $($Settings.MinPasswordLength)" -ForegroundColor Green
        Write-Host "  - Password complexity: $($Settings.PasswordComplexity)" -ForegroundColor Green
        Write-Host "  - Maximum password age: $($Settings.MaxPasswordAge) days" -ForegroundColor Green
    }
    
    [void]ConfigureAccountLockoutPolicy([hashtable]$Settings) {
        Write-Host "  - Lockout threshold: $($Settings.LockoutThreshold) attempts" -ForegroundColor Green
        Write-Host "  - Lockout duration: $($Settings.LockoutDuration) minutes" -ForegroundColor Green
    }
    
    [void]ConfigureKerberosPolicy([hashtable]$Settings) {
        Write-Host "  - Maximum ticket age: $($Settings.MaxTicketAge) hours" -ForegroundColor Green
        Write-Host "  - Maximum service ticket age: $($Settings.MaxServiceAge) minutes" -ForegroundColor Green
    }
    
    [object]GenerateSecurityReport() {
        $report = @()
        
        # Analyze current security posture
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        foreach ($group in $privilegedGroups) {
            $members = Get-ADGroupMember -Identity $group -Server $this.Domain
            $report += [PSCustomObject]@{
                Category = "Privileged Access"
                Group = $group
                MemberCount = $members.Count
                Members = ($members.SamAccountName -join ", ")
                Recommendation = if ($members.Count -gt 5) { "Review membership - too many privileged users" } else { "Acceptable" }
            }
        }
        
        # Check for service accounts
        $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Server $this.Domain -Properties ServicePrincipalName
        $report += [PSCustomObject]@{
            Category = "Service Accounts"
            Group = "Service Accounts"
            MemberCount = $serviceAccounts.Count
            Members = ($serviceAccounts.SamAccountName -join ", ")
            Recommendation = "Review service account security and delegation"
        }
        
        return $report
    }
}

# Disaster Recovery Implementation
function New-ADDisasterRecoveryPlan {
    param(
        [string]$BackupLocation = "\\backup-server\ADBackup",
        [int]$RetentionDays = 30
    )
    
    $plan = @{
        BackupSchedule = @{
            SystemState = "Daily at 2:00 AM"
            ADDatabase = "Daily at 3:00 AM"
            SYSVOL = "Daily at 4:00 AM"
            GPOBackup = "Weekly on Sunday at 1:00 AM"
        }
        
        RecoveryProcedures = @{
            AuthoritativeRestore = @"
1. Boot DC into Directory Services Restore Mode
2. Restore system state from backup
3. Mark objects as authoritative: ntdsutil "authoritative restore" "restore subtree OU=DeletedOU,DC=contoso,DC=com"
4. Restart in normal mode
5. Force replication: repadmin /syncall /AdeP
"@
            
            NonAuthoritativeRestore = @"
6. Boot DC into Directory Services Restore Mode
7. Restore system state from backup
8. Restart in normal mode
9. Allow normal replication to occur
"@
            
            ForestRecovery = @"
10. Identify forest root domain PDC
11. Disconnect all DCs from network
12. Restore forest root PDC from backup
13. Seize all FSMO roles on restored PDC
14. Clean metadata for failed DCs
15. Gradually bring additional DCs online
16. Restore remaining domains
"@
        }
        
        TestingSchedule = @{
            BackupVerification = "Monthly"
            RestoreTesting = "Quarterly"
            FullDRTest = "Annually"
        }
    }
    
    # Create backup scripts
    $backupScript = @"
# AD Backup Script
`$backupPath = "$BackupLocation\`$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path `$backupPath -ItemType Directory -Force

# System State Backup
wbadmin start systemstatebackup -backupTarget:`$backupPath -quiet

# GPO Backup
Backup-GPO -All -Path "`$backupPath\GPO"

# Export AD Objects
Get-ADUser -Filter * -Properties * | Export-Csv "`$backupPath\Users.csv" -NoTypeInformation
Get-ADGroup -Filter * -Properties * | Export-Csv "`$backupPath\Groups.csv" -NoTypeInformation
Get-ADComputer -Filter * -Properties * | Export-Csv "`$backupPath\Computers.csv" -NoTypeInformation

# Cleanup old backups
Get-ChildItem "$BackupLocation" | Where-Object {`$_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays)} | Remove-Item -Recurse -Force

Write-EventLog -LogName Application -Source "AD Backup" -EventId 1000 -EntryType Information -Message "AD backup completed successfully to `$backupPath"
"@
    
    $backupScript | Out-File -FilePath "C:\Scripts\ADBackup.ps1" -Encoding UTF8
    
    return $plan
}

# Enterprise Monitoring and Alerting
function Start-ADMonitoring {
    param(
        [string[]]$DomainControllers = (Get-ADDomainController -Filter *).Name,
        [int]$CheckIntervalMinutes = 15
    )
    
    while ($true) {
        foreach ($dc in $DomainControllers) {
            try {
                # Check DC health
                $dcHealth = Test-ComputerSecureChannel -Server $dc
                
                # Check critical services
                $services = @("NTDS", "DNS", "Netlogon", "KDC")
                $serviceStatus = Invoke-Command -ComputerName $dc -ScriptBlock {
                    param($ServiceList)
                    foreach ($service in $ServiceList) {
                        Get-Service -Name $service | Select-Object Name, Status
                    }
                } -ArgumentList $services
                
                # Check replication
                $replStatus = Get-ADReplicationPartnerMetadata -Target $dc
                $replErrors = $replStatus | Where-Object {$_.LastReplicationResult -ne 0}
                
                # Generate alerts if needed
                if (-not $dcHealth) {
                    Send-ADAlert -Type "Critical" -Message "Domain controller $dc failed secure channel test"
                }
                
                $failedServices = $serviceStatus | Where-Object {$_.Status -ne "Running"}
                if ($failedServices) {
                    Send-ADAlert -Type "Warning" -Message "Services not running on $dc`: $($failedServices.Name -join ', ')"
                }
                
                if ($replErrors) {
                    Send-ADAlert -Type "Warning" -Message "Replication errors on $dc`: $($replErrors.Count) partners with errors"
                }
                
            }
            catch {
                Send-ADAlert -Type "Critical" -Message "Failed to monitor DC $dc`: $($_.Exception.Message)"
            }
        }
        
        Start-Sleep -Seconds ($CheckIntervalMinutes * 60)
    }
}

function Send-ADAlert {
    param(
        [ValidateSet("Info", "Warning", "Critical")]
        [string]$Type,
        [string]$Message
    )
    
    $eventId = switch ($Type) {
        "Info" { 1001 }
        "Warning" { 2001 }
        "Critical" { 3001 }
    }
    
    Write-EventLog -LogName Application -Source "AD Monitoring" -EventId $eventId -EntryType Warning -Message $Message
    
    # Send email alert for critical issues
    if ($Type -eq "Critical") {
        # Email implementation would go here
        Write-Host "CRITICAL ALERT: $Message" -ForegroundColor Red
    }
}
```

**Strategic Learning Resources:**
- [Active Directory Forest Design](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models) - Enterprise forest planning
- [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/) - Microsoft security guidance
- [Active Directory Disaster Recovery](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-guide) - Comprehensive recovery procedures
- [Enterprise Identity Architecture](https://docs.microsoft.com/en-us/security/compass/compass) - Microsoft security architecture
- [Active Directory Research](https://adsecurity.org/) - Advanced security research and techniques

**Enterprise Tools & Frameworks:**
- [Microsoft Identity Manager](https://docs.microsoft.com/en-us/microsoft-identity-manager/) - Enterprise identity management
- [Azure AD Connect](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/) - Hybrid identity integration
- [Active Directory Federation Services](https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services) - Claims-based authentication
- [Privileged Access Management](https://docs.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services) - Just-in-time access

---

## **Essential Books & References**

### **Foundational Reading**
1. **"Windows Server 2022 Administration Fundamentals" by Bekim Dauti**
   - Comprehensive server administration guide
   - Covers all core Windows Server roles and features
   - Practical examples and real-world scenarios
   - Essential for all skill levels

2. **"Learn PowerShell in a Month of Lunches" by Don Jones and Jeffrey Hicks**
   - Structured approach to PowerShell learning
   - Daily lessons with practical exercises
   - Perfect for beginners to intermediate users
   - Community-recommended starting point

### **Advanced Technical References**
3. **"PowerShell in Depth" by Don Jones, Jeffrey Hicks, and Richard Siddaway**
   - Comprehensive PowerShell technical reference
   - Advanced scripting techniques and best practices
   - Enterprise automation strategies
   - Essential for advanced users and SMEs

4. **"Active Directory" by Brian Desmond, Joe Richards, Robbie Allen, and Alistair Lowe-Norris**
   - Definitive Active Directory reference
   - Covers design, implementation, and troubleshooting
   - Advanced topics including security and performance
   - Industry standard reference

### **Security-Focused Reading**
5. **"Windows Security Internals" by James Forshaw**
   - Deep dive into Windows security architecture
   - Advanced security concepts and implementation
   - Threat analysis and mitigation strategies
   - Essential for security-focused roles

6. **"Active Directory Security Risk Assessment" by Ping Castle Team**
   - Security assessment methodologies
   - Risk identification and mitigation
   - Compliance and audit procedures
   - Practical security implementation

### **Practical Implementation**
7. **"Windows Server Cookbook" by Robbie Allen**
   - Solutions-oriented approach
   - Practical recipes for common tasks
   - Troubleshooting guides and best practices
   - Quick reference for daily operations

8. **"IIS 10.0 Administration" by Jason Helmick**
   - Comprehensive IIS administration guide
   - Web server configuration and optimization
   - Security hardening and troubleshooting
   - Essential for web services management

---

## **Key Repositories & Open Source Projects**

### **Official Microsoft Resources**
- **[PowerShell GitHub](https://github.com/PowerShell/PowerShell)** - Official PowerShell source code and development
- **[Windows Admin Center](https://github.com/Microsoft/windows-admin-center-sdk)** - Modern server management platform
- **[PowerShell Gallery](https://www.powershellgallery.com/)** - Official PowerShell module repository
- **[Microsoft Documentation](https://github.com/MicrosoftDocs)** - Official documentation source code

### **PowerShell Tools & Modules**
- **[Pester](https://github.com/pester/Pester)** - PowerShell testing framework
- **[PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)** - PowerShell code quality analysis
- **[ImportExcel](https://github.com/dfinke/ImportExcel)** - Excel manipulation without Excel installed
- **[PoshBot](https://github.com/poshbotio/PoshBot)** - PowerShell-based chatbot framework

### **Active Directory Tools**
- **[BloodHound](https://github.com/BloodHoundAD/BloodHound)** - Active Directory attack path analysis
- **[ADACLScanner](https://github.com/canix1/ADACLScanner)** - Active Directory ACL scanner
- **[Ping Castle](https://github.com/vletoux/pingcastle)** - Active Directory security assessment
- **[ADRecon](https://github.com/adrecon/ADRecon)** - Active Directory reconnaissance tool

### **IIS & Web Server Tools**
- **[IIS Administration API](https://github.com/Microsoft/IIS.Administration)** - REST API for IIS management
- **[IIS Configuration Editor](https://github.com/Microsoft/IISConfigurationEditor)** - IIS configuration management
- **[Web Deploy](https://github.com/Microsoft/webdeploy)** - Web application deployment tool
- **[Application Request Routing](https://github.com/Microsoft/ApplicationRequestRouting)** - Load balancing and routing

### **Security & Monitoring Tools**
- **[Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)** - System monitoring for security
- **[Windows Event Forwarding](https://github.com/palantir/windows-event-forwarding)** - Centralized log collection
- **[WEFFLES](https://github.com/jepayneMSFT/WEFFLES)** - Windows Event Forwarding configuration
- **[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)** - PowerShell-based log analysis

### **Automation & Configuration Management**
- **[PowerShell DSC](https://github.com/PowerShell/PowerShellDSC)** - Desired State Configuration
- **[Ansible Windows Modules](https://github.com/ansible-collections/ansible.windows)** - Windows automation with Ansible
- **[Terraform Azure Provider](https://github.com/hashicorp/terraform-provider-azurerm)** - Infrastructure as code
- **[Chocolatey](https://github.com/chocolatey/choco)** - Windows package manager

---

## **Professional Development & Certification Paths**

### **Microsoft Certification Tracks**
- **Microsoft 365 Certified: Fundamentals** - Entry-level cloud and productivity certification
- **Windows Server Hybrid Administrator Associate** - Core server administration skills
- **Azure Administrator Associate** - Cloud infrastructure management
- **Azure Security Engineer Associate** - Cloud security implementation
- **Microsoft 365 Security Administrator** - Enterprise security management

### **PowerShell Specialization**
- **PowerShell.org Certification** - Community-recognized PowerShell expertise
- **Microsoft Certified: Azure PowerShell Specialty** - Cloud automation focus
- **Red Hat Certified Specialist in Ansible Automation** - Cross-platform automation
- **Puppet Certified Professional** - Configuration management

### **Security Certifications**
- **CompTIA Security+** - Foundational security concepts
- **CISSP (Certified Information Systems Security Professional)** - Advanced security management
- **GCIH (GIAC Certified Incident Handler)** - Incident response specialization
- **GCFA (GIAC Certified Forensic Analyst)** - Digital forensics expertise

### **Continuous Learning Resources**
- **Microsoft Learn** - Free, official Microsoft training paths
- **Pluralsight** - Comprehensive technical training library
- **CBT Nuggets** - Interactive IT training with labs
- **Linux Academy/A Cloud Guru** - Cloud and infrastructure training
- **SANS Training** - Security-focused professional development

### **Community Engagement**
- **PowerShell.org** - PowerShell community and resources
- **TechNet Forums** - Microsoft technical community
- **Reddit /r/PowerShell** - Active PowerShell community
- **Stack Overflow** - Technical Q&A platform
- **Microsoft Tech Community** - Official Microsoft community platform

This expanded guide provides comprehensive resources for Windows team members to develop from basic competency to expert-level administration skills, with practical commands, real-world examples, and extensive learning resources tailored for PvJ competition success and career development.

