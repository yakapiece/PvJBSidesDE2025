# 🎯 PvJ Team Ramp-Up Plan: 8 Meetings to Vegas

*Comprehensive preparation plan for 10-person team (Captain + 9 members)*  
*Target: BSides Las Vegas August 4-6, 2024*

## 📋 Plan Overview

### Team Profile
- **Size**: 10 people (Captain + 9 members)
- **Experience**: Mixed (3 PvJ veterans, some 20+ years experience, some college level)
- **Subteams**: Windows, *nix, Firewall, BIND (2-3 people each)
- **Meeting Format**: Virtual, 1 hour + optional 1 hour extension
- **Expected Attendance**: 75% per meeting
- **Practice Time**: 2-3 hours between meetings

### Training Philosophy
- **Progressive complexity** - Build from basics to advanced coordination
- **Balanced approach** - Equal focus on individual skills and team coordination
- **Practical focus** - Hands-on practice with real scenarios
- **Veteran mentorship** - Leverage experienced members to teach others
- **Safety first** - Emphasize V2 protocols and avoid common pitfalls

---

## 📅 Meeting Schedule & Progression

### Phase 1: Foundation (Meetings 1-2)
**Focus**: Team formation, role assignment, basic knowledge transfer

### Phase 2: Skill Building (Meetings 3-4)  
**Focus**: Subteam specialization, technical skill development

### Phase 3: Integration (Meetings 5-6)
**Focus**: Cross-team coordination, scenario practice

### Phase 4: Competition Prep (Meetings 7-8)
**Focus**: Final preparation, logistics, confidence building

---

## 🚀 Meeting 1: Team Formation & PvJ Fundamentals
**Timeline**: 4 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Opening (10 minutes)
- **Introductions**: Name, background, cybersecurity experience
  
Have fun, win if you can. - Techtonic

Pick something you’re interested in, always wanted to learn, and use it for the game. - StraySheep

- **PvJ experience sharing**: Veterans share a 2-minute overview
- **Team goals**: Establish a learning-focused mindset
- **Meeting structure**: Explain format and expectations

#### PvJ Overview (25 minutes)
- **Competition structure**: 2.5 days, scoring system, environment
- **Rex's Rules presentation**: Cover all 14 rules with emphasis on:
  - DNS dependency (Rule #2)
  - Firewall monitoring-only (Rule #11)
  - Simple tools over complex (Rule #13)
- **Scoring reality**: Service uptime > security hardening
- **Common failure modes**: What kills teams (DNS, firewall blocking, automation)

#### Subteam Formation (20 minutes)
- **Subteam assignments**: Windows, *nix, Firewall, BIND (2-3 each)
- **Role definitions**: Primary/secondary responsibilities
- **Veteran distribution**: Ensure each subteam has experience
- **Communication structure**: Team leads, escalation paths

#### Wrap-up (5 minutes)
- **Homework assignment**: Read the comprehensive training guide
- **Next meeting preview**: Subteam deep dives
- **Lab status update**: Timeline for practice environment

### Hour 2: Extended Session (Optional)

#### Deep Dive Q&A (30 minutes)
- **Veterans share war stories**: Specific examples from past competitions
- **Detailed rule discussion**: Edge cases and interpretations
- **Environment walkthrough**: Typical network topology and services

#### Initial Subteam Meetings (30 minutes)
- **Breakout rooms**: Each subteam meets separately
- **Skill assessment**: What does each person know?
- **Learning goals**: What does each person need to learn?
- **Mentorship pairing**: Veterans with newer members

### Homework (2-3 hours)
- **Read**: PvJ Training Guide V2 (focus on your subteam section)
- **Study**: Rex's Rules V2 - memorize all 14 rules
- **Research**: Review the scored services guide for your subteam
- **Prepare**: Questions for next meeting's technical deep dive

---

## 🔧 Meeting 2: Subteam Deep Dives & Technical Foundations
**Timeline**: 3.5 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Subteam Presentations (40 minutes - 10 min each)
Each subteam presents to the full team:

**Windows Team Presentation**:
- **Key services**: AD, IIS, Exchange/hMail, SQL Server, SMB
- **Common issues**: Service failures, account lockouts, permissions
- **Critical commands**: PowerShell basics, service management
- **Monitoring focus**: Event logs, service status, user accounts

**\*nix Team Presentation**:
- **Key services**: SSH, Apache/Nginx, Postfix, MySQL, NFS
- **Common issues**: Process failures, permission problems, config errors
- **Critical commands**: systemctl, ps, netstat, log analysis
- **Monitoring focus**: Process lists, cron jobs, network connections

**Firewall Team Presentation**:
- **Key constraint**: Monitor only - cannot block scored services
- **Traffic analysis**: Connection patterns, bandwidth, protocols
- **Tools**: pfSense/ASA interfaces, packet capture, flow analysis
- **Coordination**: Supporting other teams with network intelligence

**BIND Team Presentation**:
- **Critical role**: ALL scoring depends on DNS resolution
- **DNS services**: Forward/reverse zones, zone transfers, RNDC
- **Failure impact**: DNS down = all services show red
- **Monitoring**: Query patterns, zone integrity, performance

#### Cross-Team Dependencies (15 minutes)
- **DNS health checks**: Every team checks DNS every 30 minutes
- **Communication protocols**: When to alert, escalation procedures
- **Shared procedures**: Change management, documentation standards

#### Q&A and Clarifications (5 minutes)

### Hour 2: Extended Session (Optional)

#### Hands-On Command Practice (45 minutes)
**Breakout by subteam** - Veterans teach newer members:

**Windows Team**:
```powershell
# Service management
Get-Service | Where-Object {$_.Status -eq "Stopped"}
Restart-Service -Name "W3SVC"
Get-EventLog -LogName System -Newest 50

# User account management  
Get-LocalUser
Get-ADUser -Filter *
```

**\*nix Team**:
```bash
# Service management
systemctl status apache2
systemctl restart mysql
journalctl -u ssh -f

# Process and network monitoring
ps aux | grep apache
netstat -tulpn | grep :80
```

**Firewall Team**:
- pfSense interface navigation
- Log analysis techniques
- Traffic monitoring setup

**BIND Team**:
```bash
# DNS testing and management
nslookup domain.com
dig @dns-server domain.com
rndc reload
named-checkconf
```

#### Team Coordination Practice (15 minutes)
- **Communication drill**: Practice escalation scenarios
- **Documentation standards**: Shared note-taking format
- **Tool familiarization**: Discord/Slack, shared documents

### Homework (2-3 hours)
- **Practice**: Commands from your subteam session
- **Study**: Checklists V2 for your subteam (both initial and ongoing)
- **Prepare**: Specific questions about your subteam's responsibilities
- **Lab prep**: Review practice lab documentation (once available)

---

## 🛠️ Meeting 3: Hands-On Lab Introduction & Basic Scenarios
**Timeline**: 3 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Lab Environment Walkthrough (20 minutes)
- **Network topology**: Understanding the practice environment
- **VM assignments**: Which systems each subteam manages
- **Scorebot dashboard**: How to read the scoreboard
- **Access methods**: VPN, SSH keys, RDP connections

#### Basic Scenario: Service Restoration (25 minutes)
**Live demonstration with full team participation**:

**Scenario Setup**:
- Apache service stopped on Linux web server
- IIS service stopped on Windows web server
- DNS server responding slowly
- One database connection failing

**Team Response**:
- **Captain**: Coordinates overall response
- **Subteams**: Each handles their assigned services
- **Communication**: Practice real-time coordination
- **Documentation**: Everyone takes notes

**Learning Objectives**:
- Basic troubleshooting workflow
- Team communication under pressure
- Scorebot monitoring and interpretation
- Change documentation procedures

#### Debrief and Lessons Learned (10 minutes)
- **What worked well**: Positive observations
- **What needs improvement**: Areas for development
- **Process refinements**: Adjustments for next time

#### Next Steps (5 minutes)
- **Individual lab access**: How to practice between meetings
- **Homework scenarios**: Specific tasks for each subteam

### Hour 2: Extended Session (Optional)

#### Subteam Lab Practice (45 minutes)
**Breakout sessions** - Each subteam practices in their area:

**Windows Team**:
- Service start/stop/restart procedures
- Event log analysis for common issues
- Basic PowerShell troubleshooting
- User account and permission checks

**\*nix Team**:
- systemctl service management
- Log file analysis (/var/log/*)
- Process monitoring and management
- Network connectivity testing

**Firewall Team**:
- pfSense interface navigation
- Traffic monitoring and analysis
- Log review and pattern recognition
- Performance monitoring setup

**BIND Team**:
- DNS query testing and validation
- Zone file syntax checking
- Service restart procedures
- Performance monitoring setup

#### Team Coordination Drill (15 minutes)
- **Communication practice**: Using team channels effectively
- **Escalation procedures**: When and how to ask for help
- **Documentation standards**: Consistent change logging

### Homework (2-3 hours)
- **Individual lab practice**: 1-2 hours in your subteam area
- **Scenario completion**: Complete assigned basic scenarios
- **Command mastery**: Practice essential commands until fluent
- **Documentation**: Create personal reference sheets

---

## 🎯 Meeting 4: Advanced Scenarios & DNS Deep Dive
**Timeline**: 2.5 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### DNS Cascade Failure Scenario (30 minutes)
**Critical learning scenario** - Most important lesson for PvJ success:

**Scenario Setup**:
- BIND DNS server becomes unresponsive
- All services start showing RED on scorebot
- Team must diagnose and resolve DNS issues
- Other services are actually running fine

**Team Response Process**:
1. **Recognition** (5 min): Identify DNS as root cause
2. **Coordination** (5 min): BIND team takes lead, others support
3. **Diagnosis** (10 min): BIND team troubleshoots DNS issues
4. **Resolution** (5 min): Restore DNS service
5. **Verification** (5 min): Confirm all services return to GREEN

**Key Learning Points**:
- DNS failure cascades to ALL services
- Scorebot shows RED even if services are running
- BIND team has most critical role
- Other teams must support DNS troubleshooting
- Quick DNS fixes can restore entire scoreboard

#### Advanced Service Issues (20 minutes)
**Multiple simultaneous problems**:
- Database connectivity issues (affects web applications)
- Mail server configuration problems
- File sharing permission errors
- Network connectivity intermittent issues

**Team Coordination Focus**:
- **Triage**: Which issues to tackle first
- **Resource allocation**: Who works on what
- **Communication**: Keeping everyone informed
- **Documentation**: Tracking changes and results

#### Lessons Learned Discussion (10 minutes)
- **DNS dependency**: Reinforcing the critical importance
- **Triage strategies**: How to prioritize multiple issues
- **Team coordination**: What communication worked best

### Hour 2: Extended Session (Optional)

#### Subteam Advanced Practice (30 minutes)
**Complex scenarios for each subteam**:

**Windows Team**:
- Active Directory authentication failures
- IIS application pool crashes
- SQL Server connection issues
- Exchange/hMail configuration problems

**\*nix Team**:
- Apache virtual host configuration errors
- MySQL/PostgreSQL performance issues
- SSH key authentication problems
- Postfix mail relay configuration

**Firewall Team**:
- Traffic analysis for performance issues
- Identifying unusual connection patterns
- Supporting other teams with network data
- Performance monitoring and alerting

**BIND Team**:
- Zone file corruption recovery
- Secondary DNS server synchronization
- Query performance optimization
- Security monitoring and alerting

#### Cross-Team Coordination Practice (30 minutes)
- **Multi-team scenarios**: Issues requiring coordination
- **Communication protocols**: Structured information sharing
- **Escalation procedures**: When to involve captain/other teams
- **Documentation standards**: Shared change tracking

### Homework (2-3 hours)
- **Advanced scenario practice**: Complete complex scenarios for your subteam
- **Cross-training**: Learn basics of one other subteam's area
- **Command fluency**: Master advanced commands for your area
- **Procedure documentation**: Create step-by-step guides for common issues

---

## 🔄 Meeting 5: Team Coordination & Communication Mastery
**Timeline**: 2 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Communication Protocol Training (25 minutes)
**Structured communication for high-pressure situations**:

**Incident Reporting Format**:
```
ALERT: [SUBTEAM] - [SERVICE] - [SEVERITY]
STATUS: [Brief description]
IMPACT: [What's affected]
ETA: [Expected resolution time]
SUPPORT NEEDED: [What help is needed]
```

**Example Communications**:
- "ALERT: BIND - DNS - CRITICAL / STATUS: DNS server unresponsive / IMPACT: All services showing RED / ETA: 10 minutes / SUPPORT NEEDED: None"
- "ALERT: Windows - IIS - HIGH / STATUS: Web server down / IMPACT: HTTP/HTTPS services RED / ETA: 5 minutes / SUPPORT NEEDED: Firewall team check traffic"

**Practice Scenarios**:
- Multiple teams practice structured communication
- Captain coordinates overall response
- Focus on clear, concise, actionable information

#### Multi-Team Coordination Scenario (25 minutes)
**Complex scenario requiring all teams**:

**Scenario**: Network performance degradation affecting multiple services
- **Symptoms**: Slow response times across all services
- **Root cause**: Network congestion from unknown source
- **Required coordination**: All teams must work together

**Team Roles**:
- **Firewall Team**: Identify traffic patterns and sources
- **BIND Team**: Check DNS query performance and load
- **Windows Team**: Monitor server performance and connections
- **\*nix Team**: Check system load and network utilization
- **Captain**: Coordinate investigation and response

**Learning Objectives**:
- Information sharing between teams
- Coordinated troubleshooting approach
- Resource allocation and task assignment
- Maintaining service availability during investigation

#### Communication Debrief (10 minutes)
- **What worked**: Effective communication patterns
- **What didn't**: Communication breakdowns and fixes
- **Process improvements**: Refinements for better coordination

### Hour 2: Extended Session (Optional)

#### Advanced Coordination Scenarios (45 minutes)
**Three rapid-fire scenarios** (15 minutes each):

**Scenario 1: Cascade Failure**
- DNS issues trigger multiple service failures
- Teams must coordinate rapid response
- Practice structured escalation and resolution

**Scenario 2: Security Incident**
- Suspicious activity detected by firewall team
- Requires investigation by all teams
- Practice incident response coordination

**Scenario 3: Performance Crisis**
- Multiple services experiencing performance issues
- Teams must coordinate optimization efforts
- Practice resource allocation and prioritization

#### Team Building & Stress Management (15 minutes)
- **Stress response techniques**: Staying calm under pressure
- **Team support strategies**: How to help struggling teammates
- **Energy management**: Maintaining performance over long competition
- **Positive communication**: Encouraging and constructive feedback

### Homework (2-3 hours)
- **Communication practice**: Use structured format in all lab practice
- **Cross-team scenarios**: Practice scenarios requiring coordination
- **Stress testing**: Practice under time pressure
- **Team support**: Help teammates with their weak areas

---

## 🛡️ Meeting 6: Security & Incident Response
**Timeline**: 1.5 weeks before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Red Team Attack Simulation (35 minutes)
**Realistic attack scenario with active red team simulation**:

**Attack Progression**:
1. **Initial compromise** (5 min): Web shell planted on Linux server
2. **Persistence establishment** (10 min): Cron jobs, scheduled tasks created
3. **Lateral movement** (10 min): Additional systems compromised
4. **Beacon generation** (5 min): Regular callbacks to external systems
5. **Service disruption** (5 min): Some services begin failing

**Team Response**:
- **Detection**: Firewall team identifies suspicious traffic
- **Investigation**: Service teams check their systems
- **Containment**: Remove persistence mechanisms
- **Recovery**: Restore affected services
- **Documentation**: Track all changes and findings

**Key Learning Points**:
- Balancing security response with service availability
- Coordinated incident response procedures
- Maintaining scorebot performance during incidents
- Documentation for post-incident analysis

#### Incident Response Procedures (15 minutes)
**Structured approach to security incidents**:

**Response Framework**:
1. **Detect**: Identify suspicious activity
2. **Assess**: Determine scope and impact
3. **Contain**: Limit further damage
4. **Eradicate**: Remove threats and persistence
5. **Recover**: Restore normal operations
6. **Document**: Record actions and lessons learned

**Team Coordination**:
- **Incident commander**: Captain or designated lead
- **Communication**: Structured updates every 10 minutes
- **Resource allocation**: Who works on what aspects
- **Service priority**: Maintain scoring while responding

#### Security vs. Availability Balance (10 minutes)
- **PvJ reality**: Service uptime more important than perfect security
- **Risk assessment**: When to take services down for cleaning
- **Quick fixes**: Temporary solutions to maintain availability
- **Documentation**: Tracking security issues for post-competition analysis

### Hour 2: Extended Session (Optional)

#### Advanced Threat Hunting (30 minutes)
**Subteam-specific security focus**:

**Windows Team**:
- Event log analysis for compromise indicators
- Scheduled task and service enumeration
- User account and permission auditing
- PowerShell script analysis

**\*nix Team**:
- Process and network connection analysis
- Cron job and startup script review
- File permission and ownership checks
- Log analysis for suspicious activity

**Firewall Team**:
- Traffic pattern analysis for beacons
- Connection frequency and timing analysis
- Geolocation and reputation checking
- Performance impact assessment

**BIND Team**:
- DNS query pattern analysis
- Zone file integrity checking
- Unusual query type detection
- Performance monitoring during attacks

#### Rapid Response Drills (30 minutes)
**Quick succession scenarios** (10 minutes each):
- **Persistence removal**: Find and eliminate backdoors
- **Service restoration**: Quickly restore compromised services
- **Communication coordination**: Practice incident communication

### Homework (2-3 hours)
- **Security scenario practice**: Complete incident response scenarios
- **Tool familiarization**: Practice with security analysis tools
- **Response procedures**: Memorize incident response steps
- **Team coordination**: Practice security communication protocols

---

## 🏁 Meeting 7: Competition Simulation & Final Preparation
**Timeline**: 1 week before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Full Competition Simulation (45 minutes)
**Complete PvJ simulation with realistic timeline**:

**Simulation Structure**:
- **Initial assessment** (10 min): Team gets access to environment
- **Service baseline** (10 min): Establish initial service status
- **Attack phase** (15 min): Red team activities begin
- **Defense phase** (10 min): Team responds to attacks and maintains services

**Realistic Constraints**:
- **Time pressure**: Compressed timeline mimics competition stress
- **Multiple issues**: Several problems occur simultaneously
- **Communication challenges**: Practice under pressure
- **Scoring focus**: Maintain green services on scorebot

**Team Performance Metrics**:
- **Service uptime**: Percentage of services maintained
- **Response time**: How quickly issues are resolved
- **Communication quality**: Effectiveness of team coordination
- **Stress management**: How well team handles pressure

#### Performance Review & Feedback (15 minutes)
- **Strengths identified**: What the team does well
- **Improvement areas**: Specific skills to focus on
- **Individual feedback**: Personal development areas
- **Team dynamics**: Coordination effectiveness

### Hour 2: Extended Session (Optional)

#### Competition Logistics & Final Prep (30 minutes)
**Practical preparation for Vegas**:

**Travel and Logistics**:
- **Event schedule**: Detailed timeline for August 4-6
- **Team coordination**: Meeting points and communication
- **Equipment checklist**: What to bring and what's provided
- **Accommodation**: Team coordination for lodging

**Competition Day Procedures**:
- **Morning routine**: How to start each day
- **Break management**: Maintaining energy and focus
- **Meal coordination**: Team eating schedule
- **End-of-day procedures**: Wrap-up and preparation for next day

**Emergency Procedures**:
- **Team member absence**: Backup plans and role coverage
- **Technical issues**: Equipment failure contingencies
- **Communication backup**: Alternative contact methods
- **Stress management**: Techniques for high-pressure situations

#### Final Q&A and Confidence Building (30 minutes)
- **Open questions**: Any remaining concerns or questions
- **Success stories**: Veterans share positive experiences
- **Team strengths**: Reinforcing what the team does well
- **Confidence building**: Positive mindset for competition

### Homework (2-3 hours)
- **Final practice**: Individual skill refinement
- **Equipment preparation**: Gather and test all equipment
- **Mental preparation**: Review materials and build confidence
- **Team support**: Help teammates with final preparations

---

## 🎯 Meeting 8: Final Briefing & Team Confidence
**Timeline**: 3-4 days before Vegas  
**Duration**: 1 hour + 1 hour optional

### Hour 1: Core Session (Required - All Attend)

#### Final Knowledge Check (20 minutes)
**Quick review of critical concepts**:

**Rex's Rules Quiz** (5 minutes):
- Quick verbal quiz on all 14 rules
- Focus on most critical: DNS dependency, firewall constraints
- Ensure everyone can recite key rules from memory

**Service Priority Review** (5 minutes):
- Each subteam states their top 3 service priorities
- Cross-team dependencies and coordination points
- Emergency escalation procedures

**Communication Protocol Check** (5 minutes):
- Practice structured incident reporting
- Verify team communication channels and backups
- Confirm captain and team lead contact information

**Competition Schedule Review** (5 minutes):
- Detailed timeline for August 4-6
- Meeting points and team coordination
- Break schedules and meal planning

#### Team Strengths & Strategy (20 minutes)
**Positive reinforcement and strategic focus**:

**Team Strengths Assessment**:
- **Technical skills**: What each subteam does well
- **Coordination**: How well the team works together
- **Experience leverage**: How veterans support newer members
- **Adaptability**: Team's ability to handle unexpected situations

**Competition Strategy**:
- **Service-first approach**: Prioritize uptime over perfect security
- **DNS protection**: Extra attention to most critical dependency
- **Communication excellence**: Leverage team's coordination skills
- **Stress management**: Techniques for maintaining performance

**Success Metrics**:
- **Learning goals**: What each person wants to learn
- **Team goals**: Collective objectives for the competition
- **Fun factor**: Maintaining positive attitude and enjoyment

#### Final Motivation & Team Building (20 minutes)
- **Individual strengths**: Recognition of each team member's contributions
- **Team unity**: Reinforcing collective identity and support
- **Competition mindset**: Positive, learning-focused approach
- **Confidence building**: Affirmation of team readiness

### Hour 2: Extended Session (Optional)

#### Last-Minute Practice & Troubleshooting (30 minutes)
**Final hands-on practice**:
- **Quick scenarios**: Rapid-fire problem solving
- **Command review**: Final check of essential commands
- **Tool verification**: Ensure everyone can access necessary tools
- **Backup procedures**: Practice contingency plans

#### Equipment and Logistics Final Check (15 minutes)
- **Packing list review**: Verify everyone has necessary equipment
- **Travel coordination**: Final confirmation of travel plans
- **Communication setup**: Test all team communication channels
- **Emergency contacts**: Ensure everyone has backup contact methods

#### Team Celebration & Positive Send-Off (15 minutes)
- **Achievement recognition**: Celebrate the preparation journey
- **Team bonding**: Positive team building activity
- **Confidence affirmation**: Final confidence building
- **Vegas excitement**: Build anticipation for the competition

### Final Preparation (Individual)
- **Equipment packing**: Use provided packing list
- **Mental preparation**: Review key materials one final time
- **Rest and recovery**: Ensure adequate sleep before travel
- **Positive mindset**: Focus on learning and team success

---

## 📊 Success Metrics & Tracking

### Meeting Attendance Tracking
- **Target**: 75% attendance per meeting
- **Tracking**: Attendance log with makeup sessions for critical content
- **Accountability**: Buddy system for sharing missed content

### Skill Development Progression
- **Week 1-2**: Basic knowledge and team formation
- **Week 3-4**: Technical skill development and practice
- **Week 5-6**: Advanced coordination and scenario practice
- **Week 7-8**: Competition readiness and confidence building

### Team Readiness Indicators
- **Technical competency**: Each subteam can handle their core responsibilities
- **Communication effectiveness**: Structured, clear communication under pressure
- **Coordination ability**: Multi-team scenarios executed smoothly
- **Confidence level**: Team feels prepared and excited for competition

### Individual Development Goals
- **New members**: Basic competency in assigned subteam area
- **Experienced members**: Advanced skills and mentorship capability
- **Veterans**: Leadership and knowledge transfer effectiveness
- **Captain**: Team coordination and strategic oversight

---

## 🎉 Competition Week Schedule

### August 4 (Day 1): Competition Start
- **Morning**: Team arrival and setup
- **Afternoon**: Competition begins
- **Evening**: Team debrief and Day 2 preparation

### August 5 (Day 2): Full Competition Day
- **Morning**: Continued competition
- **Afternoon**: Continued competition
- **Evening**: Team debrief and Day 3 preparation

### August 6 (Day 3): Final Day
- **Morning**: Final competition activities (half day)
- **Afternoon**: Competition wrap-up and awards
- **Evening**: Team celebration and lessons learned

---

## 📚 Supporting Materials

### Required Reading
- **PvJ Training Guide V2**: Comprehensive preparation guide
- **Rex's Rules V2**: 14 critical rules for success
- **Checklists V2**: Subteam-specific operational guides
- **Scored Services Guide**: Services and ports reference

### Practice Resources
- **Proxmox Practice Lab**: Hands-on training environment
- **Local LLM Guide**: AI assistance for troubleshooting
- **Content Resources**: Blog posts, videos, and community content

### Competition Materials
- **Packing List**: Essential items for competition
- **Laptop Specifications**: Hardware requirements
- **Team Coordination Tools**: Communication and documentation platforms

This comprehensive 8-meeting plan will prepare your team for success at BSides Las Vegas while building both individual skills and team coordination. The progressive structure ensures steady development while the focus on practical scenarios and team building will create a cohesive, effective team ready for the competition challenges.

