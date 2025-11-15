# 🛠️ PvJ Role-Specific Checklists & Hourly Guides V2

*Updated for 2024 Ruleset Compliance and Safety-Critical Operations*

**Version 2.0 - Safety-First Approach**

---

## 🧱 TEAM NAME: NETWORK / FIREWALL

---

### 🔧 Pre-Game Setup Checklist

*Before the clock starts. Focus on visibility, monitoring, and compliance.*

- [ ] **Inventory & Mapping:**
  - [ ] Identify and document all network endpoints.
  - [ ] Map all known hosts, ports, services, and their intended purposes.
  - [ ] Create a network diagram (even a simple one) for quick reference.

- [ ] **Logging & Monitoring:**
  - [ ] Configure all network devices to send logs (syslog, NetFlow, sFlow) to a central SIEM or syslog server.
  - [ ] Verify log ingestion and parsing in the SIEM.
  - [ ] Set up alerts for high-priority events: port scans, DHCP anomalies, rogue DNS servers, new devices on the network.

- [ ] **Monitoring Setup (CRITICAL - NO BLOCKING):**
  - [ ] Configure comprehensive logging at all network points
  - [ ] Set up traffic monitoring and alerting systems
  - [ ] **VERIFY all scored services are accessible (DO NOT BLOCK)**
  - [ ] Implement monitoring-only firewall rules
  - [ ] Test that scorebot can reach all services

- [ ] **Access & Control:**
  - [ ] Confirm backup access to all management consoles (serial, out-of-band).
  - [ ] Establish a secure, out-of-band communication path for the team.
  - [ ] Prepare monitoring rules for common threat scenarios (logging, not blocking).

### 🚨 Change Management Protocol

**Before Making ANY Network Change:**
- [ ] Document current configuration state
- [ ] Test change on least critical system first
- [ ] Verify team member can troubleshoot if deployer unavailable
- [ ] Have manual rollback procedure documented
- [ ] Get network lead + captain approval for firewall changes
- [ ] Communicate change to team before implementation

### 🕐 Hour-by-Hour Operations Timeline

*Adjust to event schedule (e.g., 9 AM–5 PM PvJ)*

**Hour 1: Monitoring Setup & Baseline**
- [ ] **DNS Health Verification (Every 30 minutes):**
  - [ ] Verify DNS server is responding: `nslookup [hostname] [dns-server]`
  - [ ] Check DNS service status: `systemctl status named/bind9`
  - [ ] Confirm DNS logs show no errors: `tail /var/log/named/named.log`
  - [ ] Test resolution of all critical hostnames
  - [ ] Report DNS issues to team immediately if found

- [ ] **Threat Hunting:**
  - [ ] Monitor for unusual traffic patterns (e.g., large outbound transfers, connections to known bad IPs).
  - [ ] Check for unknown devices on the network using ARP and DHCP logs.
  - [ ] Analyze DNS queries for suspicious domains or patterns.

- [ ] **Monitoring (NOT BLOCKING):**
  - [ ] Log outbound traffic to known C2 destinations (using threat intelligence feeds).
  - [ ] Implement rate-limiting alerts on noisy or suspicious services.

- [ ] **Verification:**
  - [ ] Verify that all alerts and logs are being ingested correctly.
  - [ ] Confirm that all team members have access to necessary tools and consoles.
  - [ ] **CRITICAL**: Verify scorebot can reach all services

**Hour 2–3: Enhanced Monitoring & Analysis**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Traffic Analysis:**
  - [ ] Mirror suspicious traffic to an analysis interface for deeper inspection (e.g., with Wireshark or Zeek).
  - [ ] Correlate network events with host-based alerts from the Linux and Windows teams.

- [ ] **Monitoring Enhancement:**
  - [ ] Implement detailed logging for egress traffic.
  - [ ] Review and enhance monitoring rules based on observed traffic.
  - [ ] **DO NOT BLOCK** - focus on detection and alerting

**Hour 4–6: Threat Hunting & Coordination**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Threat Hunting:**
  - [ ] Trace internal lateral movement by analyzing east-west traffic.
  - [ ] Identify the source of internal attacks and work with the appropriate team to contain them.

- [ ] **Monitoring & Alerting:**
  - [ ] Alert on traffic associated with privilege escalation techniques (e.g., WinRM, SMB relay, PsExec).
  - [ ] Implement monitoring for micro-segmentation violations.

- [ ] **Collaboration:**
  - [ ] Notify the Linux and Windows teams of affected hosts and provide them with relevant network logs.
  - [ ] Work with the other teams to coordinate containment and recovery efforts.

**Final Hour: Documentation & Log Preservation**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Preservation:**
  - [ ] Document current firewall configuration (reverts cost points and take time).
  - [ ] Export all relevant logs for scoring and post-game analysis.

- [ ] **Documentation:**
  - [ ] Document all changes made to the network configuration and the impact of those changes.
  - [ ] Create a timeline of network-related events for the final report.

- [ ] **Preparation:**
  - [ ] Evaluate revert cost vs. manual fix for any temporary changes.

### 🛡️ Triage Actions

- [ ] **Identify Abnormal Traffic:**
  - [ ] Look for changes in flow behavior (e.g., a host that normally only communicates on port 80 suddenly starts sending traffic on a high-numbered port).
  - [ ] Use protocol analysis to identify suspicious or malformed packets.

- [ ] **Dynamic Monitoring (NOT BLOCKING):**
  - [ ] Log and alert on known red team IPs and domains
  - [ ] Monitor traffic patterns for threat hunting
  - [ ] Coordinate with other teams for host-based blocking
  - [ ] Use threat intelligence for detection, not blocking

- [ ] **Packet Capture:**
  - [ ] Use packet captures (PCAPs) to confirm or disprove suspected compromises.
  - [ ] Analyze PCAPs to identify the specific exploits and techniques being used by the red team.

### 📘 Documentation Support

- [ ] **Timestamp Everything:**
  - [ ] Log all changes to the network configuration with a timestamp and the name of the person who made the change.
- [ ] **Justify Your Actions:**
  - [ ] Note the rationale for all monitoring rules and alerts.
  - [ ] Document the expected impact of each change.
- [ ] **Communicate Effectively:**
  - [ ] Share a real-time status update with the command lead every 60 minutes.
  - [ ] Use a shared document or wiki to track all network-related information.

---

## 🐧 TEAM NAME: LINUX

---

### 🔧 Pre-Game Setup Checklist

*Before the clock starts. Focus on account security, logging, and baseline hardening.*

- [ ] **Account Security:**
  - [ ] Audit all user accounts: `cat /etc/passwd | grep -E "sh$|bash$"`
  - [ ] Remove or disable default and unknown user accounts: `userdel -r [username]`
  - [ ] Check for accounts with UID 0: `grep ':0:' /etc/passwd`
  - [ ] Review sudo privileges: `cat /etc/sudoers` and `ls -la /etc/sudoers.d/`

- [ ] **SSH Hardening:**
  - [ ] Enforce SSH key authentication only: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
  - [ ] Disable root login: `PermitRootLogin no`
  - [ ] Change default SSH port if possible: `Port 2222`
  - [ ] Restart SSH service: `systemctl restart ssh`

- [ ] **Logging & Monitoring:**
  - [ ] Install and configure auditd: `systemctl enable auditd && systemctl start auditd`
  - [ ] Configure rsyslog to forward logs to central server: Edit `/etc/rsyslog.conf`
  - [ ] Enable journald forwarding: `systemctl restart systemd-journald`
  - [ ] Verify log forwarding: `logger "Test message" && tail /var/log/syslog`

- [ ] **Persistence Check:**
  - [ ] Review all crontabs: `crontab -l` (for all users), `cat /etc/crontab`, `ls -la /etc/cron.*`
  - [ ] Check startup scripts: `cat /etc/rc.local`, `ls -la /etc/init.d/`
  - [ ] Examine user profiles: `cat ~/.bashrc ~/.profile ~/.bash_profile` (for all users)
  - [ ] Check systemd services: `systemctl list-unit-files --type=service --state=enabled`

- [ ] **System Hardening (Simple Only):**
  - [ ] Harden sudoers file: Remove unnecessary NOPASSWD entries
  - [ ] Enable AppArmor or SELinux if already configured: `aa-status` or `sestatus`
  - [ ] Update package lists: `apt update` (but avoid full upgrades during competition)

### 🚨 Change Management Protocol

**Before Making ANY System Change:**
- [ ] Document current configuration state
- [ ] Test change on least critical system first
- [ ] Verify team member can troubleshoot if deployer unavailable
- [ ] Have manual rollback procedure documented
- [ ] Get service owner approval for service configuration changes
- [ ] Communicate change to team before implementation

### 🛠️ Tool Deployment Safety

**Before Deploying ANY Tool or Automation:**
- [ ] Verify all dependencies are available on target system
- [ ] Test deployment on least critical system first
- [ ] Confirm multiple team members can operate tool
- [ ] Document manual procedures if tool fails
- [ ] Have rollback plan ready before deployment
- [ ] Ensure tool expert will be available throughout event

### 🕐 Hour-by-Hour Operations Timeline

**Hour 1: Account Lockdown & Baseline**
- [ ] **DNS Health Verification (Every 30 minutes):**
  - [ ] Verify DNS server is responding: `nslookup [hostname] [dns-server]`
  - [ ] Check DNS service status: `systemctl status named/bind9`
  - [ ] Confirm DNS logs show no errors: `tail /var/log/named/named.log`
  - [ ] Test resolution of all critical hostnames
  - [ ] Report DNS issues to team immediately if found

- [ ] **System Snapshot:**
  - [ ] Document running processes: `ps aux > /tmp/baseline_processes.txt`
  - [ ] Document open ports: `netstat -tulpn > /tmp/baseline_ports.txt`
  - [ ] Document logged-in users: `who > /tmp/baseline_users.txt`
  - [ ] Document network connections: `ss -tulpn > /tmp/baseline_connections.txt`

- [ ] **Immediate Threats (15 minutes maximum):**
  - [ ] Kill obvious reverse shells: `pkill -f "nc.*-e" && pkill -f "bash.*-i"`
  - [ ] Check for suspicious processes: `ps aux | grep -E "(nc|netcat|python|perl|ruby)" | grep -v grep`
  - [ ] Terminate crypto miners: `pkill -f "xmrig" && pkill -f "minerd"`
  - [ ] **STOP** - Focus on service restoration unless critical finding

- [ ] **Account Security:**
  - [ ] Lock suspicious accounts: `usermod -L [username]`
  - [ ] Check recent logins: `last | head -20`
  - [ ] Review failed login attempts: `grep "Failed password" /var/log/auth.log | tail -20`

**Hour 2–3: Service Focus & Rapid Triage**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Rapid Assessment (15 minutes maximum):**
  - [ ] Quick process check: `ps aux | head -20`
  - [ ] Active connections: `netstat -tulpn | grep ESTABLISHED`
  - [ ] Recent files: `find /tmp -mtime -1 | head -10`
  - [ ] Authentication events: `grep "Failed password" /var/log/auth.log | tail -5`
  - [ ] **STOP** - Focus on service restoration unless critical finding

- [ ] **Service Restoration Priority:**
  - [ ] Check critical service status: `systemctl status apache2 nginx mysql ssh`
  - [ ] Restart failed services: `systemctl restart [service]`
  - [ ] Verify services are accessible to scorebot
  - [ ] Document service restoration actions

- [ ] **SIEM Correlation:**
  - [ ] Share suspicious IPs with Network team
  - [ ] Report compromised accounts to team lead
  - [ ] Focus on service impact, not attack sophistication

**Hour 4–6: Service Maintenance & Minimal Investigation**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Service-First Approach:**
  - [ ] Monitor service availability continuously
  - [ ] Quick restart of any failing services
  - [ ] Coordinate with network team for traffic analysis
  - [ ] Focus 80% effort on service restoration

- [ ] **Minimal Investigation (Only if services are stable):**
  - [ ] Check for new SUID/SGID files: `find / -perm /6000 -type f 2>/dev/null | head -10`
  - [ ] Look for hidden files: `find /home -name ".*" -type f 2>/dev/null | head -10`
  - [ ] Check /tmp and /var/tmp: `ls -la /tmp /var/tmp`
  - [ ] **Time limit**: Maximum 15 minutes total

**Final Hour: Service Stability & Documentation**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Service Verification:**
  - [ ] Verify all critical services are running and accessible
  - [ ] Check service logs for errors: `journalctl -u [service] --since "1 hour ago"`
  - [ ] Test service functionality manually

- [ ] **Evidence Collection (Minimal):**
  - [ ] Archive critical logs: `tar -czf /tmp/linux_logs_$(date +%Y%m%d_%H%M).tar.gz /var/log/auth.log /var/log/syslog`
  - [ ] Document timeline of major events
  - [ ] Save service restoration procedures used

- [ ] **System Status:**
  - [ ] Document final system state
  - [ ] Update team on service status
  - [ ] Prepare for potential scorched earth phase

### 🛡️ Triage Actions

- [ ] **Process Analysis (Quick Only):**
  - [ ] Identify suspicious processes by parent-child relationships: `pstree -p | head -20`
  - [ ] Check process command lines: `ps auxww | grep -E "(bash|sh|python|perl)" | head -10`
  - [ ] **Time limit**: 5 minutes maximum

- [ ] **Network Connections (Quick Only):**
  - [ ] Monitor active connections: `netstat -tulpn | grep ESTABLISHED | head -10`
  - [ ] Check for reverse shells: `netstat -an | grep ESTABLISHED | grep -E ":443|:80|:53" | head -5`
  - [ ] **Time limit**: 5 minutes maximum

- [ ] **Service Impact Assessment:**
  - [ ] Identify which services are affected by suspicious activity
  - [ ] Prioritize service restoration over investigation
  - [ ] Coordinate with team for service-specific fixes

### 📘 Documentation Support

- [ ] **Change Tracking:**
  - [ ] Log all configuration changes with timestamps: `echo "$(date): Changed X to Y" >> /tmp/changes.log`
  - [ ] Document rationale for each change
  - [ ] Keep backup copies of original configurations

- [ ] **Service Focus:**
  - [ ] Maintain service availability log
  - [ ] Document service restoration procedures
  - [ ] Track service uptime and downtime

- [ ] **Team Communication:**
  - [ ] Report status to team lead every 60 minutes
  - [ ] Share service-impacting IOCs with other teams immediately
  - [ ] Maintain shared documentation of service status

---

## 🪟 TEAM NAME: WINDOWS

---

### 🔧 Pre-Game Setup Checklist

*Before the clock starts. Focus on logging, hardening, and baseline security.*

- [ ] **Logging & Monitoring:**
  - [ ] Install and configure Sysmon: `sysmon -accepteula -i sysmonconfig.xml`
  - [ ] Configure Windows Event Forwarding (WEF) to central log server
  - [ ] Enable PowerShell logging: Set `EnableScriptBlockLogging` and `EnableModuleLogging` in Group Policy
  - [ ] Verify Event Log service is running: `Get-Service EventLog`

- [ ] **Remote Access Hardening:**
  - [ ] Secure RDP settings: Disable RDP if not needed, or restrict to specific IPs
  - [ ] Configure Network Level Authentication for RDP
  - [ ] Change default RDP port if keeping enabled: `Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -Value 3390`
  - [ ] Harden SMB: Disable SMBv1, enable SMB signing

- [ ] **Legacy Protocol Hardening:**
  - [ ] Disable NetBIOS over TCP/IP: Network adapter properties
  - [ ] Disable LLMNR: Group Policy or registry: `HKLM\Software\policies\Microsoft\Windows NT\DNSClient`
  - [ ] Disable WPAD: Registry setting `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad`

- [ ] **System Audit:**
  - [ ] Review startup items: `Get-CimInstance Win32_StartupCommand`
  - [ ] Audit scheduled tasks: `Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}`
  - [ ] Check running services: `Get-Service | Where-Object {$_.Status -eq "Running"}`
  - [ ] Review local users and groups: `Get-LocalUser` and `Get-LocalGroup`

- [ ] **Security Tools:**
  - [ ] Confirm Windows Defender or EDR agent is running: `Get-MpComputerStatus`
  - [ ] Update Windows Defender signatures: `Update-MpSignature`
  - [ ] Enable Windows Firewall: `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`

### 🚨 Change Management Protocol

**Before Making ANY System Change:**
- [ ] Document current configuration state
- [ ] Test change on least critical system first
- [ ] Verify team member can troubleshoot if deployer unavailable
- [ ] Have manual rollback procedure documented
- [ ] Get service owner approval for service configuration changes
- [ ] Communicate change to team before implementation

### 🛠️ Tool Deployment Safety

**Before Deploying ANY Tool or Automation:**
- [ ] Verify all dependencies are available on target system
- [ ] Test deployment on least critical system first
- [ ] Confirm multiple team members can operate tool
- [ ] Document manual procedures if tool fails
- [ ] Have rollback plan ready before deployment
- [ ] Ensure tool expert will be available throughout event

### 🕐 Hour-by-Hour Operations Timeline

**Hour 1: User & Service Audit**
- [ ] **DNS Health Verification (Every 30 minutes):**
  - [ ] Verify DNS server is responding: `nslookup [hostname] [dns-server]`
  - [ ] Check DNS service status: `Get-Service DNS`
  - [ ] Confirm DNS logs show no errors: `Get-WinEvent -LogName "DNS Server"`
  - [ ] Test resolution of all critical hostnames
  - [ ] Report DNS issues to team immediately if found

- [ ] **Account Security:**
  - [ ] Review local administrator accounts: `Get-LocalGroupMember Administrators`
  - [ ] Check for new user accounts: `Get-LocalUser | Where-Object {$_.LastLogon -gt (Get-Date).AddDays(-1)}`
  - [ ] Audit recent logons: `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)}`
  - [ ] Check for failed logon attempts: `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)}`

- [ ] **Network Security:**
  - [ ] Close RDP to Internet: Configure firewall rules to restrict RDP access
  - [ ] Review active network connections: `Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}`
  - [ ] Check for suspicious listening ports: `Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}`

- [ ] **Process Analysis:**
  - [ ] Document running processes: `Get-Process | Export-Csv C:\temp\baseline_processes.csv`
  - [ ] Check for suspicious processes: `Get-Process | Where-Object {$_.ProcessName -match "powershell|cmd|wmic|net"}`

**Hour 2–3: Service Focus & Rapid Assessment**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Rapid Assessment (15 minutes maximum):**
  - [ ] Running processes: `Get-Process | Select Name,Id,CPU | Sort CPU -Desc | Select -First 10`
  - [ ] Network connections: `Get-NetTCPConnection | Where State -eq "Established" | Select -First 10`
  - [ ] Recent logons: `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} | Select -First 5`
  - [ ] **STOP** - Focus on service restoration unless critical finding

- [ ] **Service Restoration Priority:**
  - [ ] Check critical service status: `Get-Service | Where-Object {$_.Name -match "DNS|IIS|MSSQL|Exchange"}`
  - [ ] Restart failed services: `Restart-Service [ServiceName]`
  - [ ] Verify services are accessible to scorebot
  - [ ] Document service restoration actions

**Hour 4–6: Service Maintenance & Minimal Investigation**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Service-First Approach:**
  - [ ] Monitor service availability continuously
  - [ ] Quick restart of any failing services
  - [ ] Focus 80% effort on service restoration
  - [ ] Coordinate with network team for traffic analysis

- [ ] **Minimal Investigation (Only if services are stable):**
  - [ ] Check for mimikatz usage: Search for LSASS access events in Sysmon (Event ID 10) - limit to 5 minutes
  - [ ] Look for credential dumping: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Message -match "lsass"} | Select -First 5`
  - [ ] **Time limit**: Maximum 15 minutes total

**Final Hour: Service Stability & Evidence Collection**
- [ ] **DNS Health Verification (Every 30 minutes)**

- [ ] **Service Verification:**
  - [ ] Verify all critical services are running and accessible
  - [ ] Test service functionality manually
  - [ ] Check service logs for errors

- [ ] **Minimal Evidence Collection:**
  - [ ] Export Security event logs: `wevtutil epl Security C:\temp\Security.evtx`
  - [ ] Export System event logs: `wevtutil epl System C:\temp\System.evtx`
  - [ ] Document timeline of major service events

- [ ] **System Status:**
  - [ ] Document final system state
  - [ ] Update team on service status
  - [ ] Prepare for potential scorched earth phase

### 🛡️ Triage Actions

- [ ] **Service Impact Assessment:**
  - [ ] Identify which services are affected by suspicious activity
  - [ ] Prioritize service restoration over investigation
  - [ ] Coordinate with team for service-specific fixes

- [ ] **Quick Process Check (5 minutes max):**
  - [ ] Monitor for process injection: Check Sysmon Event ID 8 (CreateRemoteThread) - first 5 events only
  - [ ] Detect hollow process creation: Look for unusual parent-child relationships - quick scan only
  - [ ] **Time limit**: 5 minutes maximum

- [ ] **Network Behavior (Quick Only):**
  - [ ] Identify beaconing behavior: Look for regular outbound connections - top 5 only
  - [ ] Check for DNS tunneling: Analyze DNS queries for unusual patterns - quick scan only
  - [ ] **Time limit**: 5 minutes maximum

### 📘 Documentation Support

- [ ] **Change Tracking:**
  - [ ] Log all system changes: `Add-Content -Path C:\temp\changes.log -Value "$(Get-Date): Made change X"`
  - [ ] Document rationale for each security action
  - [ ] Maintain backup of original configurations

- [ ] **Service Focus:**
  - [ ] Maintain service availability log
  - [ ] Document service restoration procedures
  - [ ] Track service uptime and downtime

- [ ] **Team Coordination:**
  - [ ] Report service-impacting issues to Network team for monitoring
  - [ ] Share service-affecting IOCs with Linux team and central command
  - [ ] Provide hourly status updates to team lead
  - [ ] Maintain shared documentation of Windows service status

---

## 📣 SHARED COMMS & COORDINATION CHECKLIST V2

---

### 🔄 Cross-Team Communication Protocols

- [ ] **Hourly Sync Requirements:**
  - [ ] Each team lead reports to PvJ command channel every 60 minutes
  - [ ] Status format: `[TEAM] - [TIME] - [STATUS] - [ACTIVE_INCIDENTS] - [SUPPORT_NEEDED]`
  - [ ] Example: `NETWORK - 10:00 - GREEN - 2 monitored IPs, 1 isolated subnet - Need Windows team to check DC01`

- [ ] **Cross-Team Alerting:**
  - [ ] **IMMEDIATE** notification when compromise is suspected on any system
  - [ ] Use `@channel` or equivalent for urgent alerts
  - [ ] Include: Affected system, suspected compromise type, immediate actions taken
  - [ ] Example: `@channel URGENT: WEB01 showing beacon activity, isolated from network, Windows team please investigate`

- [ ] **Information Sharing:**
  - [ ] Share IOCs (IPs, domains, file hashes) immediately across all teams
  - [ ] Use shared document/channel for real-time IOC updates
  - [ ] Tag IOCs with confidence level: HIGH/MEDIUM/LOW

### 📊 Logging & Documentation Standards

- [ ] **System Change Documentation:**
  - [ ] **Format**: `[TIMESTAMP] [TEAM] [SYSTEM] [ACTION] [RATIONALE] [RESULT]`
  - [ ] **Example**: `14:23 NETWORK FW01 ENABLED_LOGGING Suspicious_traffic_detected Successfully_configured`
  - [ ] Log ALL configuration changes, no matter how small

- [ ] **Service Status Tracking:**
  - [ ] Document service availability and restoration actions
  - [ ] Track service uptime/downtime with timestamps
  - [ ] Note service restoration procedures that worked
  - [ ] Focus on scoring impact of service changes

- [ ] **Artifact Tagging:**
  - [ ] Tag all evidence with: `[TEAM]_[SYSTEM]_[TYPE]_[TIMESTAMP]`
  - [ ] Example: `WINDOWS_DC01_EVENTLOG_20240815_1430`
  - [ ] Maintain chain of custody documentation

### 🚨 Escalation Procedures

- [ ] **Level 1 - Team Internal:**
  - [ ] Single system compromise or service degradation
  - [ ] Handle within team, notify team lead
  - [ ] Document in team channel

- [ ] **Level 2 - Cross-Team Coordination:**
  - [ ] Multiple systems affected or lateral movement detected
  - [ ] Notify all relevant teams immediately
  - [ ] Coordinate response through team leads

- [ ] **Level 3 - Command Escalation:**
  - [ ] Critical infrastructure compromise (DC, DNS, core network)
  - [ ] Multiple teams overwhelmed
  - [ ] Escalate to PvJ command for guidance/resources

### 🎯 Scoring Support Activities

- [ ] **Service Uptime Monitoring:**
  - [ ] Each team monitors their critical services every 5 minutes
  - [ ] Report service status changes immediately
  - [ ] Coordinate service restoration efforts
  - [ ] **Priority**: Service restoration over investigation

- [ ] **Beacon Response:**
  - [ ] When beacon detected: Immediate containment, then investigation
  - [ ] Document beacon duration and containment method
  - [ ] Share beacon IOCs with all teams
  - [ ] Focus on stopping point bleeding, not understanding attack

- [ ] **Grey Team Support:**
  - [ ] Assign dedicated person for Grey Team ticket monitoring
  - [ ] Respond to tickets within 15 minutes
  - [ ] Coordinate with appropriate technical team for resolution
  - [ ] Consider marketplace outsourcing for risky tasks

### 📋 Shared Tools & Resources

- [ ] **Communication Channels:**
  - [ ] Primary: [Discord/Slack/Teams channel]
  - [ ] Backup: [Alternative communication method]
  - [ ] Emergency: [Phone/SMS for critical issues]

- [ ] **Shared Documentation:**
  - [ ] Real-time status board: [HackMD/Google Docs/Notion]
  - [ ] IOC tracking sheet: [Shared spreadsheet/database]
  - [ ] Network diagram: [Shared diagram tool]
  - [ ] Service status dashboard: [Shared monitoring view]

- [ ] **File Sharing:**
  - [ ] Evidence repository: [Shared drive/folder]
  - [ ] Log aggregation: [Central SIEM/log server]
  - [ ] Configuration documentation: [Version control/shared storage]

### ⏰ Timeline Coordination

- [ ] **Event Milestones:**
  - [ ] **T+0**: Game start, initial baseline, DNS verification
  - [ ] **T+1hr**: First status report, service restoration focus
  - [ ] **T+3hr**: Mid-game assessment, marketplace strategy
  - [ ] **T+6hr**: Final push, service stability verification
  - [ ] **T+8hr**: Game end, final documentation

- [ ] **Break Coordination:**
  - [ ] Stagger team member breaks to maintain coverage
  - [ ] Minimum 2 people per team active at all times
  - [ ] Coordinate high-stress role rotations
  - [ ] Ensure DNS guardian always covered

### 🔍 Shared Threat Hunting (Service-First Approach)

- [ ] **Coordinated Service Monitoring:**
  - [ ] Share service status across teams every 30 minutes
  - [ ] Coordinate service restoration efforts
  - [ ] Focus on service impact over attack attribution

- [ ] **Intelligence Sharing:**
  - [ ] Share service-affecting threats immediately
  - [ ] Correlate service outages across different system types
  - [ ] Build service restoration timeline

### 📈 Performance Metrics

- [ ] **Team KPIs:**
  - [ ] Service uptime percentage (primary metric)
  - [ ] Mean Time to Service Restoration (MTSR)
  - [ ] Number of successful service restorations
  - [ ] Beacon containment speed

- [ ] **Shared Metrics:**
  - [ ] Overall team score and ranking
  - [ ] Cross-team collaboration effectiveness
  - [ ] Communication response times
  - [ ] Service restoration documentation completeness

---

## 🎯 FINAL REMINDERS V2

### Before Game Start:
- [ ] Test all communication channels
- [ ] Verify access to all shared resources
- [ ] Confirm role assignments and backup coverage
- [ ] Review escalation procedures with entire team
- [ ] **CRITICAL**: Verify scorebot can reach all services

### During Game:
- [ ] Maintain situational awareness across all teams
- [ ] Communicate early and often
- [ ] Document everything in real-time
- [ ] **PRIORITY**: Service restoration over investigation
- [ ] Support teammates under pressure
- [ ] **REMEMBER**: DNS failure = zero points for dependent assets

### After Game:
- [ ] Preserve all evidence and documentation
- [ ] Conduct immediate hot-wash debrief
- [ ] Share lessons learned with community
- [ ] Plan improvements for next event

### V2 Safety Checklist:
- [ ] **Never block scored services** - monitor and log only
- [ ] **Test changes on non-critical systems first** - no snapshots available
- [ ] **Focus 80% effort on service restoration** - investigation is secondary
- [ ] **Verify DNS health every 30 minutes** - cascade failure prevention
- [ ] **Choose simple tools over complex ones** - team supportability matters

---

*Remember: PvJ V2 is about learning, community, and service availability. Help your teammates, share knowledge, focus on keeping services running, and remember that simple solutions often beat complex ones. The real victory is the skills and relationships you build along the way.*

**Version 2.0 - Safety-First, Service-Focused Approach**

