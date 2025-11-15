# 🔴 PvJ Red Team TTPs Briefing Document

**Classification**: SECRET  
**Distribution**: Blue Team Training Use Only  
**Date**: January 2025  
**Prepared by**: Cybersecurity Research Team  

---

## 📋 Executive Summary

This briefing document compiles known Red Team Tactics, Techniques, and Procedures (TTPs) observed in past Pros vs. Joes (PvJ) competitions at BSides conferences. The information is derived from official sources, participant write-ups, open-source intelligence, and post-game analysis documents released by the PvJ organization.

**Key Findings:**
- Red teams have **advanced access** to environments weeks before the competition
- **Pre-planted persistence mechanisms** are deployed across all systems
- **Psychological warfare** and constant pressure are core tactics
- **Multi-stage attack progression** from reconnaissance to "scorched earth"
- **Professional-grade tooling**, including custom C2 frameworks

---

## 🎯 Red Team Structure & Capabilities

### **Red Cell Composition**
- **Professional penetration testers** and security researchers
- **Industry experts** from major cybersecurity companies
- **Experienced CTF players** with advanced technical skills
- **Coordinated team** with specialized roles and responsibilities

### **Pre-Competition Advantages**
- **Weeks of advance access** to target environment
- **Complete network reconnaissance** and vulnerability assessment
- **Pre-positioned persistence mechanisms** across all systems
- **Tested exploit chains** and attack paths
- **Custom tooling development** for a specific environment

### **Operational Objectives**
1. **Maintain persistent access** to all blue team networks
2. **Apply constant pressure** to test blue team resilience
3. **Escalate attack intensity** throughout the competition
4. **Demonstrate real-world attack scenarios**
5. **Provide educational value** through post-game analysis

---

## ⚔️ Attack Methodology & Phases

### **Phase 1: Pre-Competition Setup (Weeks Before)**
**Objective**: Establish a comprehensive foothold and prepare attack infrastructure

**Activities:**
- **Network reconnaissance** and service enumeration
- **Vulnerability assessment** of all systems and services
- **Persistence mechanism deployment** across Windows and Linux systems
- **Custom implant development** and testing
- **Attack path validation** and exploit chain preparation
- **C2 infrastructure setup** and communication channel establishment

### **Phase 2: Initial Contact (Competition Start)**
**Objective**: Activate pre-positioned assets and begin active operations

**Activities:**
- **Beacon activation** from pre-planted implants
- **Credential harvesting** from compromised systems
- **Lateral movement** across network segments
- **Service disruption** to impact scoring
- **Intelligence gathering** on blue team defensive measures

### **Phase 3: Sustained Operations (Throughout Competition)**
**Objective**: Maintain pressure while adapting to blue team countermeasures

**Activities:**
- **Continuous re-compromise** of cleaned systems
- **Escalation of privileges** on newly accessed systems
- **Data exfiltration** and flag collection
- **Psychological pressure** through constant presence
- **Adaptive tactics** based on blue team responses

### **Phase 4: Scorched Earth (Final Hours)**
**Objective**: Maximum disruption and demonstration of complete compromise

**Activities:**
- **Mass service disruption** across all networks
- **Widespread system compromise** and control
- **Maximum beacon deployment** for scoring impact
- **Demonstration of total network ownership**
- **Final psychological pressure** on blue teams

---

## 🛠️ Technical Arsenal & Tools

### **Command & Control (C2) Frameworks**

#### **ThunderStorm C2 (Primary Framework)**
- **Custom-developed** C2 framework specifically for PvJ
- **Modular architecture** with multiple implant types
- **Encrypted communications** to evade detection
- **Multi-protocol support** for resilient connectivity

**Components:**
- **ThunderStorm Bolts**: Primary implants for persistent access
- **ThunderStorm Flurries**: Lightweight launchers and droppers
- **JetStream**: User account manipulation tools
- **UserAdd Service**: Automated user creation and privilege escalation

#### **Empire C2 (Historical)**
- **PowerShell-based** post-exploitation framework
- **Multiple beacon types** including C/GO implementations
- **Userland hooking** capabilities for stealth
- **Privexec service** for privilege escalation

### **Implant Categories**

#### **Persistence Mechanisms**
**File System Implants** (Sample locations from BSidesLV 2024):
```
C:\Windows\vpnplugins\juniper\JunosPulseVрn.exe
C:\Windows\System32\iphlpaрi.exe
C:\Windows\SysWOW64\en\AuthFWSnapIn.Resourceh.dll
C:\Windows\System32\SystemResetPlatform\SysResetLayoui.exe
C:\Windows\System32\rfxvmh.exe
C:\Program Files (x86)\Windows Multimedia Platform\desk.dll
C:\Windows\System32\migwiz\sfcm.dll
C:\Windows\System32\kbdazе.exe
```

**Characteristics:**
- **Unicode character substitution** to evade detection
- **Legitimate-looking paths** and filenames
- **DLL hijacking** and side-loading techniques
- **System directory placement** for persistence
- **Multiple backup implants** per system

#### **Launchers and Droppers**
**Flurry Implants** (Lightweight activation tools):
```
C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Formq.dll
C:\Windows\diagnostics\system\UsbCore\VF_ResetOnResսme.dll
C:\Windows\System32\wbem\schaոnel.dll
C:\Windows\System32\mfsrcsnx.exe
```

**Capabilities:**
- **Staged payload delivery** for larger implants
- **Environment validation** before deployment
- **Anti-analysis techniques** to evade sandboxes
- **Multiple execution methods** (services, scheduled tasks, etc.)

### **Web Shells & Remote Access**

#### **ASP Web Shells**
```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<!-- Custom web shell implementations -->
```

**Features:**
- **File system access** and manipulation
- **Command execution** capabilities
- **Upload/download** functionality
- **Steganographic hiding** in legitimate files

#### **PowerShell Inline Beacons**
- **Memory-resident** execution to avoid disk artifacts
- **Encrypted communication** with C2 infrastructure
- **Reflective loading** of additional modules
- **WMI and CIM** integration for system manipulation

---

## 🎯 Attack Vectors & Techniques

### **Initial Access Methods**

#### **Misconfigured Services**
- **IIS misconfigurations** allowing file upload and execution
- **Weak authentication** on web applications
- **Default credentials** on administrative interfaces
- **Unpatched vulnerabilities** in web services

#### **Active Directory Certificate Services (AD CS) Exploitation**
- **Certificate template abuse** for privilege escalation
- **ESC1-ESC8 attack techniques** against certificate authorities
- **Certificate-based authentication bypass**
- **Golden certificate attacks** for persistence

#### **Credential-Based Attacks**
- **Weak/unchanged passwords** from default installations
- **Password spraying** against user accounts
- **Credential stuffing** with common password lists
- **Pass-the-hash** and pass-the-ticket attacks

#### **Scheduled Tasks & Cron Jobs**
- **Writable task directories** for privilege escalation
- **Weak permissions** on scheduled executables
- **Task hijacking** for persistence
- **Cron job manipulation** on Linux systems

### **Persistence Techniques**

#### **Windows Persistence**
- **Service installation** with legitimate-sounding names
- **Registry modification** for autostart persistence
- **WMI event subscriptions** for stealth persistence
- **DLL hijacking** in system directories
- **Scheduled task creation** with system privileges

#### **Linux Persistence**
- **Cron job installation** for regular execution
- **Systemd service creation** for boot persistence
- **SSH key injection** for backdoor access
- **Library preloading** (LD_PRELOAD) for stealth
- **Init script modification** for startup persistence

### **Lateral Movement**

#### **Windows Lateral Movement**
- **PsExec and variants** for remote execution
- **WMI remote execution** for stealth movement
- **PowerShell remoting** for administrative access
- **SMB relay attacks** for credential theft
- **Kerberos ticket manipulation** (Golden/Silver tickets)

#### **Linux Lateral Movement**
- **SSH key propagation** for passwordless access
- **Sudo privilege abuse** for escalation
- **NFS share exploitation** for file system access
- **Docker container escape** techniques
- **Kernel exploit chaining** for root access

### **Defense Evasion**

#### **Anti-Detection Techniques**
- **Unicode character substitution** in filenames
- **Process hollowing** and injection techniques
- **Reflective DLL loading** to avoid disk artifacts
- **Timestomping** to hide file modification times
- **Log evasion** through selective deletion

#### **Anti-Analysis Measures**
- **Sandbox detection** and evasion
- **Virtual machine detection** techniques
- **Debugger detection** and anti-debugging
- **Code obfuscation** and packing
- **Environment-specific execution** requirements

---

## 🧠 Psychological Warfare Tactics

### **Constant Pressure Application**
- **24/7 attack operations** throughout competition
- **Immediate re-compromise** of cleaned systems
- **Visible presence** through obvious indicators
- **Taunting messages** and psychological manipulation
- **Escalating intensity** as competition progresses

### **Targeted Harassment**
- **Focus on leading teams** to level playing field
- **Increased attention** on well-performing blue teams
- **Strategic timing** of major attacks during critical moments
- **Coordination with scoring events** for maximum impact

### **Demoralization Techniques**
- **Rapid re-infection** after cleanup efforts
- **Multiple simultaneous compromises** to overwhelm defenders
- **Demonstration of total control** over systems
- **Mocking of defensive efforts** through visible artifacts

---

## 📊 Scoring & Economic Warfare

### **Beacon Deployment Strategy**
- **Strategic beacon placement** for maximum scoring impact
- **Redundant beacon deployment** to ensure persistence
- **Timing coordination** with scoring rounds (5-minute intervals)
- **Economic impact** through point deduction

### **Service Disruption Tactics**
- **Critical service targeting** (DNS, AD, Web, Mail)
- **Cascading failure induction** through dependency exploitation
- **Intermittent disruption** to avoid easy detection
- **Coordinated multi-service attacks** for maximum impact

### **Marketplace Manipulation**
- **Economic warfare** through point system abuse
- **Strategic timing** of major attacks to force marketplace spending
- **Resource depletion** forcing blue teams to spend points on resets
- **Psychological pressure** through economic disadvantage

---

## 🔍 Intelligence Gathering & Reconnaissance

### **Pre-Competition Intelligence**
- **Complete network mapping** and service enumeration
- **Vulnerability assessment** of all systems and applications
- **Credential harvesting** from default installations
- **Attack path analysis** and exploitation planning
- **Blue team capability assessment** through historical data

### **Real-Time Intelligence**
- **Blue team monitoring** through compromised systems
- **Communication interception** where possible
- **Defensive measure assessment** and countermeasure development
- **Team performance analysis** for targeted attacks
- **Adaptive strategy development** based on blue team responses

### **Post-Compromise Intelligence**
- **Network topology mapping** from internal perspective
- **Additional credential harvesting** from compromised systems
- **Privilege escalation path identification**
- **High-value target identification** for focused attacks
- **Persistence opportunity assessment** for long-term access

---

## 🛡️ Blue Team Implications & Countermeasures

### **Critical Understanding Points**

#### **Pre-Positioned Threats**
- **Assume compromise** from competition start
- **Immediate threat hunting** required upon network access
- **Comprehensive system reimaging** may be necessary
- **Baseline establishment** critical for anomaly detection

#### **Persistent Adversary**
- **Continuous monitoring** required throughout competition
- **Rapid response capabilities** essential for containment
- **Multiple backup plans** needed for service restoration
- **Team coordination** critical under constant pressure

#### **Professional Opposition**
- **Advanced techniques** requiring sophisticated countermeasures
- **Adaptive adversary** that responds to defensive actions
- **Resource advantage** through pre-competition preparation
- **Psychological pressure** requiring mental resilience

### **Recommended Defensive Strategies**

#### **Immediate Actions (First Hour)**
1. **Password changes** across all systems and accounts
2. **Service hardening** and unnecessary service removal
3. **Firewall configuration** to limit attack surface
4. **Baseline network scanning** for anomaly detection
5. **Threat hunting** for pre-positioned implants

#### **Ongoing Operations**
1. **Continuous monitoring** of all systems and services
2. **Regular threat hunting** sweeps for new compromises
3. **Incident response** procedures for rapid containment
4. **Service restoration** protocols for scoring maintenance
5. **Team coordination** under pressure situations

#### **Advanced Countermeasures**
1. **Behavioral analysis** for anomaly detection
2. **Memory forensics** for fileless malware detection
3. **Network segmentation** for lateral movement prevention
4. **Deception technologies** for early warning
5. **Threat intelligence** sharing between team members

---

## 📚 Historical Evolution & Trends

### **Tool Evolution**
- **2020**: Empire C2 with multiple beacon types
- **2021**: ThunderStorm introduction with userland hooking
- **2022**: Enhanced ThunderStorm with improved stealth
- **2024**: Advanced ThunderStorm with JetStream integration

### **Technique Advancement**
- **Increasing sophistication** in evasion techniques
- **Greater use of living-off-the-land** techniques
- **Enhanced persistence mechanisms** with redundancy
- **Improved psychological warfare** tactics
- **Advanced anti-analysis** measures

### **Defensive Response Evolution**
- **Improved blue team preparation** and training
- **Better understanding** of red team capabilities
- **Enhanced detection** and response procedures
- **Stronger team coordination** under pressure
- **More effective threat hunting** techniques

---

## 🎓 Educational Value & Post-Game Analysis

### **Red Team Transparency**
- **Post-game exploit presentations** by red team members
- **Detailed breakdown** of all techniques used
- **Tool sharing** for blue team education
- **Open discussion** of attack methodologies
- **Lessons learned** sharing for improvement

### **Community Learning**
- **Public documentation** of techniques and tools
- **Open-source tool release** for educational purposes
- **Conference presentations** on attack methodologies
- **Blog posts and writeups** from participants
- **Continuous improvement** of defensive capabilities

### **Professional Development**
- **Real-world experience** with advanced persistent threats
- **Pressure testing** of incident response capabilities
- **Team building** under adversarial conditions
- **Skill development** in threat hunting and analysis
- **Career advancement** through demonstrated capabilities

---

## 🚨 Key Takeaways for Blue Teams

### **Critical Success Factors**
1. **Assume breach** from the moment competition begins
2. **Prioritize service availability** over perfect security
3. **Maintain team coordination** under constant pressure
4. **Implement rapid response** procedures for re-compromise
5. **Focus on learning** rather than winning at all costs

### **Common Failure Points**
1. **Underestimating red team capabilities** and preparation
2. **Inadequate initial hardening** allowing easy re-compromise
3. **Poor team coordination** leading to duplicated efforts
4. **Panic responses** to psychological pressure
5. **Neglecting service availability** for security measures

### **Preparation Recommendations**
1. **Study historical TTPs** and attack patterns
2. **Practice incident response** under pressure
3. **Develop team communication** protocols
4. **Prepare hardening scripts** and procedures
5. **Build mental resilience** for psychological warfare

---

## 📖 Sources & References

### **Primary Sources**
- **PvJ-CTF-RedTools GitHub Repository** (iDigitalFlame/PvJ-CTF-RedTools)
- **Official PvJ Website** (prosversusjoes.net)
- **BSides Las Vegas Official Pages** (bsideslv.org)
- **Red Team Hotwash Documents** (BSidesLV 2024)

### **Participant Writeups**
- **System Overlord Blog** - Blue Team Player's Guide series
- **LockBoxx Blog** - BSidesLV 2016 Blue Team Experience
- **ip3c4c Blog** - Multiple PvJ participation reports
- **Maven Security** - PvJ CTF analysis and lessons learned

### **Technical Documentation**
- **Scorebot Engine (SBE)** - Open source scoring system
- **ThunderStorm C2 Framework** - Custom red team tooling
- **CTF Factory Documentation** - Official game infrastructure

---

**Document Classification**: UNCLASSIFIED  
**Last Updated**: January 2025  
**Next Review**: Pre-Competition 2025  

*This document is intended for educational and training purposes only. All information is derived from publicly available sources and post-competition analysis shared by the PvJ organization for educational benefit.*

