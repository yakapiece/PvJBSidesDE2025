# 🔥 Firewall Team: Ongoing Operations

*Time-based operational guide for Firewall subteam - Continuous monitoring and analysis*

---

## 🚨 V2 Safety Protocols - Always Remember

### Ongoing Operations Rules
- **MONITOR ONLY**: Never block traffic to scored services
- **DNS Check Every 30 Minutes**: DNS failure = zero points for all services
- **Logging First**: Maintain comprehensive traffic logging
- **15-Minute Investigation Limit**: Don't get lost in analysis rabbit holes
- **Communicate Findings**: Share traffic anomalies immediately with relevant teams

### **🚨 CRITICAL REMINDER**: Your Role is Detection, Not Blocking
- **Analyze traffic patterns and report findings**
- **Coordinate with other teams for response actions**
- **Maintain visibility into network activity**
- **NEVER block scored service traffic**

---

## ⏰ Hour 1-2: Monitoring Establishment Phase

### Every 30 Minutes: Scored Service Connectivity Check
```bash
# Verify scored services are reachable (2 minutes max)
SCORED_PORTS="22 53 80 443 3306 5432 139 445"
for port in $SCORED_PORTS; do
    if nc -zv localhost $port 2>/dev/null; then
        echo "Port $port: ACCESSIBLE"
    else
        echo "ALERT: Port $port NOT ACCESSIBLE"
    fi
done
```
**🤝 Coordinate with All Teams**: Report any connectivity issues immediately

### Every 15 Minutes: Traffic Pattern Analysis
```bash
# Quick traffic analysis (3 minutes max)
echo "=== Traffic Summary - $(date) ==="

# Active connections by port
for port in 22 53 80 443 3306 5432; do
    count=$(netstat -an | grep ":$port" | grep ESTABLISHED | wc -l)
    echo "Port $port: $count active connections"
done

# Top external connections
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -v -E "127\.0\.0\.1|192\.168|10\.|172\." | sort | uniq -c | sort -nr | head -5

# Check for new suspicious connections
netstat -an | grep -E ":4444|:8080|:1234|:31337|:6666" | head -5
```

### Continuous Log Monitoring Setup
```bash
# Set up real-time log analysis
cat > /tmp/log_monitor.sh << 'EOF'
#!/bin/bash
while true; do
    # Monitor firewall logs for patterns
    tail -50 /var/log/firewall.log 2>/dev/null | grep "$(date '+%b %d %H:%M')" | while read line; do
        # Check for high-volume sources
        echo "$line" | grep -E "SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $1, $2, $3}' >> /tmp/traffic_sources.log
        
        # Check for scored service traffic
        echo "$line" | grep -E "DPT=(22|53|80|443|3306|5432|139|445)" >> /tmp/scored_service_traffic.log
    done
    
    sleep 300  # Check every 5 minutes
done
EOF

chmod +x /tmp/log_monitor.sh
# nohup /tmp/log_monitor.sh &
```

---

## ⏰ Hour 2-4: Active Analysis Phase

### Every 30 Minutes: Threat Pattern Detection
```bash
# Advanced traffic analysis (5 minutes max)
echo "=== Threat Analysis - $(date) ==="

# Port scan detection
netstat -an | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | awk '$1 > 10 {print "Potential scanner: " $2 " (" $1 " connections)"}' | head -5

# Brute force detection (SSH)
grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d %H:')" | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 5 {print "SSH brute force from: " $2 " (" $1 " attempts)"}'

# DNS query analysis
tail -100 /var/log/firewall.log 2>/dev/null | grep "DPT=53" | awk '{print $1, $2, $3, "DNS query"}' | tail -10

# Web attack patterns
tail -100 /var/log/firewall.log 2>/dev/null | grep -E "DPT=(80|443)" | grep -E "union|select|script|alert" | wc -l | awk '{if($1>0) print "Potential web attacks detected: " $1}'
```

### **🤝 Coordinate with Specific Teams**:
```bash
# Generate team-specific reports
echo "=== Windows Team Report ==="
# SMB/RDP traffic
netstat -an | grep -E ":139|:445|:3389" | wc -l | awk '{print "SMB/RDP connections: " $1}'
grep "DPT=445" /var/log/firewall.log 2>/dev/null | tail -5

echo "=== Linux Team Report ==="
# SSH/Web traffic
netstat -an | grep -E ":22|:80|:443" | wc -l | awk '{print "SSH/Web connections: " $1}'
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5

echo "=== BIND Team Report ==="
# DNS traffic analysis
netstat -an | grep ":53" | wc -l | awk '{print "DNS connections: " $1}'
grep "DPT=53" /var/log/firewall.log 2>/dev/null | tail -5
```

### Traffic Volume Analysis
```bash
# Monitor traffic volume trends (3 minutes max)
# Create hourly traffic summaries
current_hour=$(date +%H)
grep "$(date '+%b %d %H:')" /var/log/firewall.log 2>/dev/null | wc -l > /tmp/traffic_hour_$current_hour.txt

# Compare with previous hour
if [ -f /tmp/traffic_hour_$((current_hour-1)).txt ]; then
    prev_count=$(cat /tmp/traffic_hour_$((current_hour-1)).txt)
    curr_count=$(cat /tmp/traffic_hour_$current_hour.txt)
    echo "Traffic trend: Previous hour: $prev_count, Current hour: $curr_count"
fi

# Top talkers analysis
awk '/FW-/ {print $8}' /var/log/firewall.log 2>/dev/null | grep "SRC=" | cut -d= -f2 | cut -d' ' -f1 | sort | uniq -c | sort -nr | head -10 > /tmp/top_talkers.txt
```

---

## ⏰ Hour 4-6: Deep Analysis Phase

### Every 45 Minutes: Advanced Pattern Recognition
```bash
# Sophisticated traffic analysis (5 minutes max)
echo "=== Advanced Analysis - $(date) ==="

# Connection duration analysis
ss -tuln | awk 'NR>1 {print $1, $4, $5}' | sort | uniq -c | sort -nr | head -10

# Protocol distribution
netstat -an | awk '{print $1}' | sort | uniq -c | sort -nr

# Time-based attack pattern detection
for hour in $(seq 0 23); do
    count=$(grep "$(date '+%b %d') $(printf '%02d' $hour):" /var/log/firewall.log 2>/dev/null | wc -l)
    if [ $count -gt 1000 ]; then
        echo "High traffic at hour $hour: $count events"
    fi
done

# Geographic analysis (if GeoIP available)
# geoiplookup $(netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -v -E "127\.0\.0\.1|192\.168|10\.|172\." | head -5)
```

### Service-Specific Deep Dive
```bash
# Detailed service analysis (10 minutes max)
echo "=== Service-Specific Analysis ==="

# SSH analysis
echo "SSH Analysis:"
ss -t state established '( dport = :22 or sport = :22 )' | wc -l | awk '{print "Active SSH sessions: " $1}'
grep "Accepted password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d %H:')" | wc -l | awk '{print "Successful SSH logins this hour: " $1}'

# Web service analysis
echo "Web Service Analysis:"
netstat -an | grep -E ":80|:443" | grep ESTABLISHED | wc -l | awk '{print "Active web connections: " $1}'
tail -100 /var/log/firewall.log 2>/dev/null | grep -E "DPT=(80|443)" | awk '{print $8}' | grep "SRC=" | cut -d= -f2 | cut -d' ' -f1 | sort | uniq | wc -l | awk '{print "Unique web clients: " $1}'

# Database analysis
echo "Database Analysis:"
netstat -an | grep -E ":3306|:5432" | grep ESTABLISHED | wc -l | awk '{print "Active database connections: " $1}'

# DNS analysis
echo "DNS Analysis:"
netstat -an | grep ":53" | wc -l | awk '{print "DNS connections: " $1}'
tail -100 /var/log/firewall.log 2>/dev/null | grep "DPT=53" | wc -l | awk '{print "Recent DNS queries: " $1}'
```

### **🤝 Coordinate with All Teams**: Share detailed analysis findings

---

## ⏰ Hour 6-8: Final Monitoring Phase

### Every 20 Minutes: Critical Service Verification
```bash
# Intensive service monitoring (2 minutes max)
echo "=== Critical Service Check - $(date) ==="

CRITICAL_PORTS="22 53 80 443 3306 5432 139 445"
for port in $CRITICAL_PORTS; do
    # Check local accessibility
    if nc -zv localhost $port 2>/dev/null; then
        # Check external accessibility (if possible)
        connections=$(netstat -an | grep ":$port" | grep ESTABLISHED | wc -l)
        echo "Port $port: ACCESSIBLE ($connections active connections)"
    else
        echo "CRITICAL ALERT: Port $port NOT ACCESSIBLE"
        # Immediate escalation
        echo "$(date): Port $port inaccessible" >> /tmp/critical_alerts.log
    fi
done
```

### Final Threat Assessment
```bash
# Comprehensive threat summary (5 minutes max)
echo "=== Final Threat Assessment ==="

# Total unique external IPs
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -v -E "127\.0\.0\.1|192\.168|10\.|172\." | sort | uniq | wc -l | awk '{print "Unique external IPs: " $1}'

# Top threat indicators
echo "Top external connections:"
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -v -E "127\.0\.0\.1|192\.168|10\." | sort | uniq -c | sort -nr | head -5

# Attack summary
echo "Attack pattern summary:"
grep -c "Failed password" /var/log/auth.log 2>/dev/null | awk '{print "SSH brute force attempts: " $1}'
tail -1000 /var/log/firewall.log 2>/dev/null | grep -c -E "union|select|script" | awk '{print "Web attack attempts: " $1}'
netstat -an | grep -c -E ":4444|:8080|:1234|:31337" | awk '{print "Suspicious port connections: " $1}'
```

### **🤝 Final Coordination with All Teams**
- Share comprehensive threat assessment
- Confirm all scored services remain accessible
- Provide final traffic analysis summary

---

## 🔄 Continuous Tasks (Throughout Competition)

### Real-Time Monitoring Dashboards
```bash
# Keep these running in separate terminals

# Terminal 1: Service Connectivity Monitor
while true; do
    clear
    echo "=== Service Connectivity Dashboard - $(date) ==="
    ports="22 53 80 443 3306 5432 139 445"
    for port in $ports; do
        if nc -zv localhost $port 2>/dev/null; then
            echo -e "Port $port : \033[32mACCESSIBLE\033[0m"
        else
            echo -e "Port $port : \033[31mNOT ACCESSIBLE\033[0m"
        fi
    done
    sleep 30
done

# Terminal 2: Traffic Volume Monitor
while true; do
    clear
    echo "=== Traffic Volume Dashboard - $(date) ==="
    echo "Active connections by service:"
    for port in 22 53 80 443 3306 5432; do
        count=$(netstat -an | grep ":$port" | grep ESTABLISHED | wc -l)
        echo "Port $port: $count connections"
    done
    echo ""
    echo "Top external IPs:"
    netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -v -E "127\.0\.0\.1|192\.168|10\." | sort | uniq -c | sort -nr | head -5
    sleep 60
done

# Terminal 3: Security Event Monitor
while true; do
    clear
    echo "=== Security Events Dashboard - $(date) ==="
    echo "Recent failed SSH attempts:"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | awk '{print $1, $2, $3, $(NF-3)}'
    echo ""
    echo "Recent firewall events:"
    tail -10 /var/log/firewall.log 2>/dev/null | awk '{print $1, $2, $3, "Event"}'
    sleep 120
done
```

---

## 🚨 Incident Response Procedures

### Scored Service Inaccessible (CRITICAL - 2-minute max)
1. **Immediate Check**:
   ```bash
   nc -zv localhost [port]
   telnet localhost [port]
   ```

2. **Verify No Blocking Rules**:
   ```bash
   iptables -L | grep -E "DROP|REJECT" | grep [port]
   iptables -L INPUT | grep [port]
   ```

3. **Check Service Status** (coordinate with relevant team):
   ```bash
   # Report to Windows/Linux team immediately
   echo "CRITICAL: Port [port] inaccessible - checking with [team]"
   ```

4. **Document and Escalate**:
   ```bash
   echo "$(date): Port [port] inaccessible" >> /tmp/critical_incidents.log
   ```

### Suspected Attack Detection (5-minute max)
1. **Document Evidence**:
   ```bash
   netstat -an > /tmp/attack_netstat_$(date +%H%M).txt
   tail -100 /var/log/firewall.log > /tmp/attack_logs_$(date +%H%M).txt
   ```

2. **Analyze Pattern**:
   ```bash
   # Identify attack source
   netstat -an | grep [suspicious_ip] | wc -l
   grep [suspicious_ip] /var/log/firewall.log | tail -20
   ```

3. **Coordinate Response** (DO NOT BLOCK):
   ```bash
   # Inform relevant teams for response
   echo "Suspected attack from [IP] targeting [service] - coordinating with [team]"
   ```

4. **Continue Monitoring**:
   ```bash
   # Enhanced monitoring of attack source
   tcpdump -i any host [suspicious_ip] -w /tmp/attack_capture_$(date +%H%M).pcap -c 1000 &
   ```

### Network Connectivity Issues (3-minute max)
1. **Basic Connectivity Test**:
   ```bash
   ping -c 3 8.8.8.8
   traceroute 8.8.8.8 | head -5
   ```

2. **DNS Resolution Test**:
   ```bash
   nslookup google.com
   dig @8.8.8.8 google.com
   ```

3. **Route Table Check**:
   ```bash
   ip route show
   arp -a | head -10
   ```

4. **Coordinate with BIND Team** if DNS issues

---

## 📊 Status Reporting Templates

### Hourly Status Report
```
FIREWALL TEAM - HOUR [X] STATUS
===============================
Time: [HH:MM]
Scored Services: [X/Y] Accessible
Traffic Volume: [HIGH/MEDIUM/LOW]
Security Events: [COUNT] this hour
Top Threats: [LIST TOP 3 IPs]
Team Coordination: [ACTIVE ISSUES]
Current Focus: [MONITORING ACTIVITY]
Next Hour Priority: [PRIORITY]
Critical Alerts: [ANY CRITICAL ISSUES]
```

### Security Incident Report Template
```
SECURITY INCIDENT - [TIME]
=========================
Incident Type: [ATTACK TYPE]
Source IP(s): [IP ADDRESSES]
Target Service(s): [AFFECTED SERVICES]
Attack Pattern: [DESCRIPTION]
Impact Assessment: [NONE/LOW/MEDIUM/HIGH]
Response Actions: [COORDINATION WITH TEAMS]
Monitoring Status: [ONGOING/RESOLVED]
Recommendations: [NEXT STEPS]
```

### End-of-Competition Summary
```
FIREWALL TEAM - FINAL REPORT
============================
Total Traffic Monitored: [VOLUME]
Security Incidents: [COUNT]
Scored Service Uptime: [PERCENTAGE]
Top Threat Sources: [LIST]
Team Coordination Events: [COUNT]
Critical Alerts: [COUNT]
Lessons Learned: [KEY POINTS]
Recommendations: [FOR NEXT TIME]
```

---

## 🎯 Optimization Tips for Long Competition

### Monitoring Efficiency
- **Automate repetitive checks** with scripts
- **Use multiple terminals** for different monitoring tasks
- **Set up alerts** for critical thresholds
- **Rotate monitoring focus** every 2 hours

### Team Coordination
- **Regular status updates** every 30 minutes
- **Immediate escalation** for scored service issues
- **Share traffic intelligence** with relevant teams
- **Document all findings** for pattern analysis

### Technical Efficiency
- **Use screen/tmux** for persistent monitoring sessions
- **Prepare common commands** as aliases
- **Keep log analysis scripts** ready
- **Maintain traffic baselines** for comparison

---

## 🔧 Emergency Command Reference

### Quick Connectivity Tests
```bash
# Service accessibility
nc -zv [host] [port]
telnet [host] [port]
curl -I http://[host]:[port]

# Network connectivity
ping -c 3 [host]
traceroute [host]
mtr -c 10 [host]

# DNS resolution
nslookup [host]
dig [host]
host [host]
```

### Traffic Analysis Commands
```bash
# Connection analysis
netstat -an | grep [port]
ss -tuln | grep [port]
lsof -i :[port]

# Traffic capture
tcpdump -i any port [port] -c 100
tcpdump -i any host [ip] -w capture.pcap

# Log analysis
tail -f /var/log/firewall.log
grep [pattern] /var/log/firewall.log | tail -20
awk '/[pattern]/ {print $1, $2, $3}' /var/log/firewall.log
```

### Emergency Recovery
```bash
# Firewall rule management
iptables -L -n --line-numbers
iptables -F  # EMERGENCY ONLY - flushes all rules
iptables -P INPUT ACCEPT  # EMERGENCY ONLY

# Service verification
systemctl status [service]
systemctl restart [service]
journalctl -u [service] -f
```

---

*Remember: Your primary mission is maintaining visibility into network traffic and coordinating with other teams. Never compromise scored service accessibility for security measures.*

**Stay vigilant, stay coordinated, and keep the network transparent to your team.**

