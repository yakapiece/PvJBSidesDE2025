# 🎯 BSides Pros vs. Joes (PvJ) Training & Preparation Guide V2

*The Ultimate Survival Manual for Cyber Defense Simulation - Updated for 2024 Ruleset*

**Version 2.0 - Safety-Critical Updates Included**

---

## 📍 1. Overview of PvJ Dynamics

### Event Structure & Timeline

**Pre-Event (Weeks Before)**
- Red Team gets **advance access** to your infrastructure
- Multiple persistence mechanisms pre-planted across all systems
- Deep reconnaissance and exploit chain preparation
- Blue Teams conduct 6-week preparation cycle with weekly meetings

**Day 1: Incident Response Simulation**
- **Duration**: Full day (8+ hours)
- **Scenario**: You're called in to respond to a "horribly configured IT infrastructure"
- **Reality Check**: You **cannot** eradicate the APT - focus on service maintenance
- **Environment**: Mixed Windows/Linux servers, DNS, firewall, file servers, PBX, mail servers
- **Constant Pressure**: Red Team harassment and trolling throughout
- **Dynamic Scaling**: Additional servers added during the day

**Day 2: Purple Team Operations**
- **Continuation**: Pick up where Day 1 left off
- **New Element**: Attack other Blue Teams while defending your own
- **Beacon Planting**: Score points by compromising competitor systems
- **Escalation**: Additional servers go live
- **Finale**: "Scorched Earth" - final hour where Red Team destroys everything

### 🔗 DNS Scoring Dependency Chain

**Understanding the Scoring Cascade:**
1. **DNS Resolution**: Scorebot queries your team's DNS server for asset hostname
2. **If DNS Fails**: NO further checks proceed - asset scores ZERO points
3. **If DNS Succeeds**: Scorebot pings the resolved IP address
4. **If Ping Succeeds**: Scorebot performs TCP health checks on scored services
5. **Points Awarded**: Based on successful service responses

**Critical Implications:**
- DNS server failure = **instant zero points** for all dependent assets
- DNS misconfiguration = **cascade failure** across infrastructure
- DNS response time affects scoring efficiency
- Backup DNS servers are **essential**, not optional

**DNS Monitoring Commands:**
```bash
# Continuous DNS health monitoring
while true; do
    echo "$(date): DNS Check"
    nslookup web01.team1.local 192.168.1.10
    dig @192.168.1.10 web01.team1.local
    sleep 30
done

# DNS server status verification
systemctl status named
systemctl status bind9
tail -f /var/log/named/named.log
```

### Scoring Mechanics

**Four Primary Components:**
1. **Host Uptime**: Points for maintaining service availability (updated every 3 minutes)
2. **Beacon Penalties**: Score deducted when Red Team signals compromise
3. **Flag Breaches**: Score lost when Red Team accesses specific files
4. **Grey Team Tickets**: Penalties for not supporting user requests

**Economic Model:**
- Score is **transferred**, not just lost
- Dichotomy's Marketplace: Spend points for strategic advantages
- Service resets, Grey Team task outsourcing, additional resources
- Red Team can also participate in economic system

> **💡 Pro Tip**: The marketplace is your strategic weapon. Don't hoard points - spend them tactically for service resets and competitive advantages.

### Win Conditions & Reality Check

**Official Goal**: Maintain maximum service uptime while minimizing compromises
**Actual Reality**: Survive the chaos, learn from professionals, contribute to team success

**Key Mindset Shifts:**
- This is **education**, not pure competition
- Red Team **will** own your systems - accept it
- Team chemistry > individual technical skills
- Communication under pressure is the real skill being tested

---

## 🧠 2. Mindset & Mental Models

### Core Mental Models for Success

#### "Chaos is Normal" Framework
```
Expected State: Everything is on fire
Your Job: Keep the most critical services running
Success Metric: Relative performance, not perfection
```

#### "Communication Beats Tools" Principle
- **Tool mastery** without **team coordination** = failure
- **Clear communication** with **basic tools** = success
- Document everything in real-time for scoring and handoffs

#### "Service Restoration Over Investigation" (80/15/5 Rule)
- **80% of effort**: Service restoration and availability
- **15% of effort**: Understanding what happened
- **5% of effort**: Evidence collection and attribution

### Situational Awareness Framework

#### OODA Loop Application for PvJ
```
OBSERVE:
- Scorebot status every 3 minutes
- Team member status and workload
- Red Team activity patterns
- Service degradation trends

ORIENT:
- Current team position vs competitors
- Resource allocation effectiveness
- Marketplace spending opportunities
- Time remaining in current phase

DECIDE:
- Service restoration priorities
- Marketplace purchases
- Team member task assignments
- Communication escalations

ACT:
- Execute decisions quickly
- Document actions for team awareness
- Monitor results for next OODA cycle
```

#### Triage Heuristics Under Pressure

**Priority Matrix:**
```
HIGH IMPACT + HIGH SCORING = DO NOW
HIGH IMPACT + LOW SCORING = DO NEXT
LOW IMPACT + HIGH SCORING = DELEGATE
LOW IMPACT + LOW SCORING = IGNORE
```

**Service Restoration Order:**
1. **DNS** - Everything depends on it (cascade failure prevention)
2. **Domain Controller** - Authentication foundation
3. **File Shares** - User productivity and Grey Team tickets
4. **Web Services** - High visibility, often high scoring
5. **Mail Services** - Communication and business function
6. **Specialty Services** - PBX, custom applications

### Stress Management Techniques

#### "Impostor Syndrome is Universal"
- **Everyone** feels unprepared - this is normal
- Focus on **contribution** rather than **perfection**
- Your fresh perspective has value to experienced teammates

#### Pressure Response Protocols
```
When Overwhelmed:
1. STOP - Take 30 seconds to breathe
2. COMMUNICATE - Tell your captain your status
3. PRIORITIZE - Focus on one high-impact task
4. EXECUTE - Complete that task before moving on
5. REPEAT - Return to OODA loop
```

#### Energy Management
- **Hydration**: Constant water intake (not just caffeine)
- **Nutrition**: Protein-rich snacks, avoid sugar crashes
- **Movement**: Stand and stretch every hour
- **Mental Breaks**: 5-minute team check-ins for morale

---

## 🧰 3. Tool & Tech Prep

### 🛠️ Tool Selection Guidelines

**The "One Person Rule"**
- Never deploy tools that only one team member understands
- If the tool expert leaves for lunch, the tool becomes useless
- Choose tools that multiple team members can troubleshoot

**Environment Constraints**
- Expect EOL systems with broken package managers
- Python may not be available or may be wrong version
- Required libraries may be missing and uninstallable
- Plan for "bare minimum" tool availability

**Tool Complexity Assessment:**
```markdown
Before choosing any tool, ask:
1. Can 3+ team members install and configure this?
2. Can 2+ team members troubleshoot when it breaks?
3. Do we have manual alternatives if this fails?
4. Are all dependencies guaranteed to be available?
5. Can we test this safely on a non-critical system?

If any answer is "no" - choose a simpler alternative.
```

**Deployment Testing Protocol:**
1. Test on least critical system first
2. Verify all dependencies are available
3. Ensure multiple team members can operate tool
4. Have manual fallback procedures ready
5. Document rollback procedures before deployment

### 🚨 Critical Firewall Limitations

**MUST ALLOW ALL SCORED SERVICE TRAFFIC**
- Teams are **required** to allow all traffic to scored services
- **Cannot block by source IP** - this is explicitly prohibited
- Overly-restrictive firewall rules are **actively penalized** by Red/Gold teams
- Focus on **monitoring and detection**, not blocking

**Monitoring-First Firewall Strategy:**
```bash
# Focus on logging and alerting, not blocking
# pfSense/OPNsense configuration examples
# Enable detailed logging for all traffic
# Set up alerts for suspicious patterns
# Use traffic analysis for threat hunting

# Example: Monitor but don't block
iptables -A INPUT -p tcp --dport 80 -j LOG --log-prefix "HTTP_TRAFFIC: "
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# NEVER do this (will break scoring):
# iptables -A INPUT -s 192.168.1.100 -j DROP
```

**Firewall Best Practices for PvJ:**
- **Log everything** - use firewall logs for threat hunting
- **Alert on anomalies** - unusual traffic patterns, port scans
- **Monitor bandwidth** - detect data exfiltration attempts
- **Track connections** - identify lateral movement patterns
- **Never block scored services** - when in doubt, allow and log

### 🛡️ Blue Team Focus

#### Log Analysis & SIEM (Simple Deployments Only)

**Graylog Quick Setup (If Team Has Expertise)**
```yaml
# Only deploy if 3+ team members understand Graylog
# Docker compose for rapid deployment
version: '3'
services:
  graylog:
    image: graylog/graylog:4.3
    # Minimal configuration for PvJ environment
```

**Simple Log Analysis (Recommended)**
```bash
# Basic log analysis that works everywhere
# Linux authentication monitoring
tail -f /var/log/auth.log | grep -E "(Failed|Accepted)"

# Windows event monitoring (PowerShell)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625,4624} -MaxEvents 10

# Simple network monitoring
netstat -tulpn | grep ESTABLISHED
ss -tulpn | grep LISTEN
```

#### Endpoint Visibility (Simple Tools First)

**Basic Process Monitoring**
```bash
# Linux process monitoring
ps aux | grep -E "(nc|netcat|python|perl)" | grep -v grep
lsof -i | grep ESTABLISHED

# Windows process monitoring
Get-Process | Where-Object {$_.ProcessName -match "powershell|cmd"}
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
```

**File System Monitoring (Manual)**
```bash
# Recent file changes (Linux)
find /tmp -type f -mtime -1 2>/dev/null
find /home -name ".*" -type f -mtime -1 2>/dev/null

# Recent file changes (Windows)
Get-ChildItem C:\temp -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-1)}
```

#### Network Monitoring (Keep It Simple)

**Basic Network Analysis**
```bash
# Traffic monitoring without complex tools
tcpdump -i any -n | grep -E "(SYN|FIN|RST)"
netstat -i  # Interface statistics
iftop       # If available, simple bandwidth monitoring
```

### 💔 System Recovery Realities

**No Safety Net Available:**
- **Snapshots**: Typically NOT available in PvJ environment
- **Reverts**: Cost points and performed by Gold Team at their convenience
- **Timing**: Reverts may take minutes to hours to complete
- **Dependencies**: You may be stuck with changes until revert completes

**Change Management Protocol:**
```markdown
Before making ANY system change:
1. Document current state
2. Test change on least critical system first
3. Have manual rollback procedure ready
4. Ensure team member can troubleshoot if you're unavailable
5. Communicate change to team before implementation

Change Approval Matrix:
- DNS changes: Requires team captain approval
- Firewall changes: Requires network lead + captain approval
- Service configuration: Requires service owner approval
- Automation deployment: Requires automation expert + captain approval
```

**Recovery Cost Analysis:**
- System revert: 500-1000 points (varies by event)
- Service downtime during revert: Additional point loss
- Time cost: Team resources diverted to manage revert
- Opportunity cost: Missing other critical tasks

---

## 🧪 4. Pre-Event Practice Scenarios

### Home Lab Setup (Simple Configurations)

**Proxmox/VMware Setup (If Available)**
```bash
# Basic multi-VM environment
- 1 Windows Server (DNS, AD, File Share)
- 1 Linux Server (Web, SSH, Database)
- 1 Firewall VM (pfSense/OPNsense)
- 1 Attacker VM (Kali Linux)

# Focus on service restoration, not complex attacks
```

**Docker Lab (Simpler Alternative)**
```yaml
# Basic service simulation
version: '3'
services:
  web:
    image: nginx
    ports: ["80:80"]
  db:
    image: mysql
    environment:
      MYSQL_ROOT_PASSWORD: password
```

### Team Training Exercises

**Communication Drills**
- Practice structured status reports
- Role-play high-pressure scenarios
- Test backup communication methods
- Practice escalation procedures

**Service Restoration Drills**
```bash
# Practice common restoration tasks
# DNS service restart
systemctl restart named
systemctl restart bind9

# Web service restoration
systemctl restart apache2
systemctl restart nginx
systemctl restart httpd

# Database recovery
systemctl restart mysql
systemctl restart postgresql
```

---

## 🤝 5. Team Dynamics & Communication

### Role Assignments & Responsibilities

**Essential Roles:**
- **Team Captain**: Decision making, marketplace, communication with Gold Team
- **DNS Guardian**: Dedicated DNS monitoring and maintenance
- **Network Lead**: Firewall monitoring (not blocking), traffic analysis
- **Windows Lead**: Windows systems, Active Directory
- **Linux Lead**: Linux systems, web services
- **Communication Lead**: Documentation, status updates, team coordination

### Communication Protocols

**Structured Status Reports (Every 60 minutes):**
```
[TEAM] - [TIME] - [STATUS] - [ACTIVE_INCIDENTS] - [SUPPORT_NEEDED]
Example: "NETWORK - 10:00 - GREEN - 2 suspicious IPs monitored, 1 isolated subnet - Need Windows team to check DC01"
```

**Escalation Matrix:**
- **Level 1**: Single system issue - handle within team
- **Level 2**: Multiple systems or lateral movement - cross-team coordination
- **Level 3**: Critical infrastructure or team overwhelmed - captain escalation

### Documentation Standards

**Real-Time Change Log:**
```
[TIMESTAMP] [TEAM] [SYSTEM] [ACTION] [RATIONALE] [RESULT]
Example: "14:23 NETWORK FW01 ENABLED_LOGGING Suspicious_traffic_detected Successfully_configured"
```

---

## 📓 6. Learning Resources

### PvJ-Specific Materials
- **Official PvJ recordings** and debriefs from prosversusjoes.net
- **Participant blog series** and lessons learned
- **PvJ GitHub repositories** (Scorebot engine analysis)
- **Community Discord/Slack** channels for preparation

### Technical Frameworks
- **MITRE ATT&CK** - Understanding adversary techniques
- **MITRE D3FEND** - Defensive countermeasures
- **NIST Cybersecurity Framework** - Incident response structure

### Quick Reference Materials
- **"Blue Team Field Manual"** - Command reference
- **CyberChef** - Data analysis and decoding
- **Sigma rules** - Detection rule formats
- **YARA rules** - Malware detection patterns

### 🔍 Investigation Priorities

**Service First, Forensics Second**
- Primary goal: Maintain service availability
- Secondary goal: Understand what happened
- Tertiary goal: Collect evidence

**Rapid Triage Techniques**
- Focus on "good enough" information for decisions
- Avoid time-consuming comprehensive analysis
- Use quick wins: process lists, network connections, recent files
- Save detailed forensics for post-game analysis

**Investigation Time Limits**
- Maximum 15 minutes for initial threat assessment
- Focus on service impact, not attack sophistication
- Document findings quickly, investigate deeply later
- Prioritize restoration over attribution

**Quick Triage Commands:**
```bash
# Linux rapid assessment (5 minutes max)
ps aux | grep -E "(nc|netcat|python|perl)" | grep -v grep
netstat -tulpn | grep ESTABLISHED
find /tmp -type f -mtime -1
last | head -10

# Windows rapid assessment (5 minutes max)
Get-Process | Where-Object {$_.ProcessName -match "powershell|cmd"}
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-1)} | Select -First 10
```

---

## 🪖 7. Day-Of Survival Tactics

### Pressure Management

**The 5-Minute Rule:**
When overwhelmed:
1. **STOP** - Take 30 seconds to breathe
2. **LIST** - Write down all current issues
3. **RANK** - Order by scoring impact
4. **ASSIGN** - Pick the top priority
5. **EXECUTE** - Work on that one thing only

### Top 5 Early-Win Actions

**For All Teams:**
1. **Verify DNS is working** - Test resolution of all critical hostnames
2. **Check scorebot status** - Identify what's broken vs. working
3. **Document baseline** - Current processes, connections, users
4. **Establish communication** - Test all team communication channels
5. **Identify critical services** - Know what scores the most points

### Energy and Nutrition Hacks

**Long Session Survival:**
- **Hydration**: Water bottle always within reach
- **Protein snacks**: Nuts, jerky, protein bars
- **Avoid sugar crashes**: No candy, limit soda
- **Movement**: Stand and stretch every hour
- **Eye breaks**: Look away from screen every 20 minutes

### When to Pivot

**Recognize When You're Stuck:**
- Spending more than 30 minutes on one issue
- Trying the same solution repeatedly
- Feeling frustrated or panicked
- Team communication breaking down

**Pivot Strategies:**
- **Ask for help** - Don't suffer in silence
- **Use marketplace** - Service reset might be faster
- **Switch tasks** - Let someone else try
- **Take a break** - 5 minutes can provide clarity

---

## 🧾 8. Post-Game Review Checklist

### Immediate Hot-Wash (Within 30 minutes)

**Team Debrief Questions:**
- What worked well for our team?
- What would we do differently?
- Which tools/techniques were most effective?
- Where did communication break down?
- What should we practice more before next time?

### Individual Self-Assessment

**Personal Reflection:**
- What new skills did I develop?
- Where did I contribute most effectively?
- What technical areas need improvement?
- How did I handle pressure and stress?
- What would I focus on for next event?

### Documentation for Portfolio

**Resume/Portfolio Items:**
- "Participated in 8-hour cyber defense simulation"
- "Maintained critical service availability under APT attack"
- "Collaborated with cross-functional team under pressure"
- "Implemented incident response procedures in real-time"

**Specific Accomplishments:**
- Services restored and time to restoration
- Threats detected and containment methods
- Team coordination and communication successes
- Technical skills demonstrated under pressure

### Knowledge Transfer

**Share with Community:**
- Write blog post about experience
- Contribute lessons learned to team wiki
- Mentor new participants in preparation
- Provide feedback to PvJ organizers

---

## 🎯 V2 Safety Reminders

### Before Any Action:
- Check if it affects scored services (firewall restrictions)
- Verify DNS won't be impacted (cascade failure prevention)
- Test on non-critical system first (no snapshots available)
- Ensure team can troubleshoot if you're unavailable (one person rule)
- Document the change and rationale (real-time logging)

### When Things Go Wrong:
- Communicate immediately (transparency saves teams)
- Prioritize by scoring impact (triage ruthlessly)
- Consider marketplace solutions (spend to win)
- Focus on service restoration over investigation (80/15/5 rule)
- Remember: everyone feels lost - this is normal

### Tool Selection Checklist:
- Can 3+ team members install and configure this?
- Can 2+ team members troubleshoot when it breaks?
- Do we have manual alternatives if this fails?
- Are all dependencies guaranteed to be available?
- Can we test this safely on a non-critical system?

---

*This guide represents the collective wisdom of the PvJ community, updated for 2024 ruleset compliance and enhanced with safety-critical improvements. Focus on learning, support your teammates, and remember that simple solutions often beat complex ones.*

**Version 2.0 - Updated for Safety and Effectiveness**

