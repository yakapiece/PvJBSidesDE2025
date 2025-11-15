# 🔥 Firewall Team: Initial Inventory & Triage → Remediation

*Task-based guide for Firewall subteam - Complete these tasks before moving to ongoing operations*

---

## 🚨 V2 Safety Protocols - READ FIRST

### Critical Rules for Firewall Team
- **MONITOR ONLY**: DO NOT BLOCK any traffic to scored services - this will zero your points
- **DNS Dependency**: If DNS fails, ALL services score ZERO points
- **Logging First**: Enable comprehensive logging before any other changes
- **Service Priority**: 80% effort on traffic analysis, 15% understanding, 5% evidence
- **Team Coordination**: Share traffic patterns affecting other teams immediately

### **🚨 CRITICAL**: Firewall Rules and Scoring
- **Scored services MUST receive all traffic** - blocking = zero points
- **Your role is DETECTION and ANALYSIS, not blocking**
- **Focus on logging, monitoring, and alerting**
- **Coordinate with other teams for response actions**

---

## 📋 Task 1: Network Infrastructure Assessment (15 minutes max)

### Network Topology Discovery
```bash
# Document current network state
ip route show > /tmp/baseline_routes.txt
ip addr show > /tmp/baseline_interfaces.txt
arp -a > /tmp/baseline_arp.txt

# Identify network segments
ip route | grep -E "192.168|10\.|172\."
ip addr | grep -E "inet.*192\.168|inet.*10\.|inet.*172\."

# Check for VLANs or additional interfaces
ip link show | grep -E "vlan|bond|bridge"
```

### Firewall Platform Identification
```bash
# Identify firewall type and version
# pfSense/OPNsense
uname -a 2>/dev/null | grep -i freebsd
cat /etc/version 2>/dev/null

# Linux-based (iptables/netfilter)
iptables --version 2>/dev/null
ufw --version 2>/dev/null
firewall-cmd --version 2>/dev/null

# Check for commercial firewalls
# Look for management interfaces, vendor-specific commands
ps aux | grep -E "pf|ipfw|checkpoint|fortinet|palo|cisco"
```

### Current Rule Assessment
```bash
# Document existing rules (DO NOT MODIFY YET)
# iptables-based
iptables -L -n --line-numbers > /tmp/baseline_iptables.txt
iptables -t nat -L -n > /tmp/baseline_nat.txt
iptables -t mangle -L -n > /tmp/baseline_mangle.txt

# pfSense/OPNsense (if applicable)
# pfctl -sr > /tmp/baseline_pf_rules.txt 2>/dev/null
# pfctl -sn > /tmp/baseline_pf_nat.txt 2>/dev/null

# Check for existing logging
iptables -L | grep LOG
tail -20 /var/log/kern.log 2>/dev/null | grep -i firewall
```

**⏰ Time Limit**: 15 minutes maximum - focus on understanding current state

---

## 📋 Task 2: Enable Comprehensive Logging (Critical First Step)

### **🚨 V2 Safety**: Logging Before Any Changes
```bash
# Enable iptables logging for monitoring (DO NOT BLOCK)
# Log all traffic to scored services for analysis
iptables -I INPUT -j LOG --log-prefix "FW-INPUT: " --log-level 4
iptables -I OUTPUT -j LOG --log-prefix "FW-OUTPUT: " --log-level 4
iptables -I FORWARD -j LOG --log-prefix "FW-FORWARD: " --log-level 4

# Configure rsyslog for firewall logs
cat >> /etc/rsyslog.conf << EOF
# Firewall logging
kern.info                       /var/log/firewall.log
EOF

systemctl restart rsyslog
```

### Enhanced Network Monitoring
```bash
# Enable packet capture for analysis
tcpdump -i any -w /tmp/initial_traffic.pcap -c 1000 &
TCPDUMP_PID=$!

# Monitor specific scored service ports
# (Coordinate with other teams for port list)
SCORED_PORTS="22 53 80 443 3306 5432 139 445"
for port in $SCORED_PORTS; do
    echo "Monitoring port $port"
    ss -tulpn | grep ":$port"
done

# Stop initial packet capture after 5 minutes
sleep 300
kill $TCPDUMP_PID 2>/dev/null
```

### **🤝 Coordinate with All Teams**: Get list of scored services and ports

---

## 📋 Task 3: Traffic Pattern Analysis

### Baseline Traffic Assessment
```bash
# Analyze current connections
netstat -an | grep ESTABLISHED > /tmp/baseline_connections.txt
ss -tuln > /tmp/baseline_listening.txt

# Check for suspicious traffic patterns
netstat -an | grep -E ":4444|:8080|:1234|:31337|:6666"
ss -an | grep -E "UNCONN.*:53"  # Check for DNS traffic

# Monitor traffic volume by port
for port in 22 53 80 443; do
    echo "Port $port connections:"
    netstat -an | grep ":$port" | wc -l
done
```

### **🚨 V2 Safety**: Identify Scored Service Traffic
```bash
# Document traffic to scored services (DO NOT BLOCK)
# Get scored service list from other teams
SCORED_SERVICES="ssh http https dns mysql postgresql smb"

# Monitor traffic to these services
for service in $SCORED_SERVICES; do
    case $service in
        ssh) port=22 ;;
        http) port=80 ;;
        https) port=443 ;;
        dns) port=53 ;;
        mysql) port=3306 ;;
        postgresql) port=5432 ;;
        smb) port=445 ;;
    esac
    
    echo "=== $service (port $port) traffic ==="
    netstat -an | grep ":$port"
done
```

### Threat Traffic Identification
```bash
# Look for suspicious patterns (5 minutes max)
# High-volume connections
netstat -an | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10

# Unusual ports
netstat -an | grep ESTABLISHED | awk '{print $4}' | cut -d: -f2 | sort | uniq -c | sort -nr | head -20

# External connections
netstat -an | grep ESTABLISHED | grep -v -E "127\.0\.0\.1|192\.168|10\.|172\."
```

**⏰ Time Limit**: 10 minutes maximum for threat analysis - focus on obvious patterns

---

## 📋 Task 4: Network Segmentation Analysis

### VLAN and Subnet Discovery
```bash
# Identify network segments
ip route show table all
ip rule show

# Check for VLANs
cat /proc/net/vlan/config 2>/dev/null
ip link show | grep vlan

# Analyze routing between segments
traceroute -n 8.8.8.8 2>/dev/null | head -10
```

### **🤝 Coordinate with Windows/Linux Teams**: Share network topology findings

### Inter-VLAN Traffic Analysis
```bash
# Monitor traffic between network segments
# Set up monitoring for cross-segment traffic
iptables -I FORWARD -j LOG --log-prefix "INTER-VLAN: " --log-level 4

# Check for lateral movement patterns
netstat -rn | grep -E "192\.168|10\.|172\."
arp -a | grep -E "192\.168|10\.|172\."
```

---

## 📋 Task 5: DNS Traffic Monitoring (Work with BIND Team)

### DNS Query Analysis
```bash
# Monitor DNS traffic (CRITICAL for scoring)
tcpdump -i any port 53 -w /tmp/dns_traffic.pcap -c 500 &
DNS_TCPDUMP_PID=$!

# Check DNS resolution paths
dig @localhost google.com
nslookup localhost
cat /etc/resolv.conf

# Monitor DNS query patterns
iptables -I INPUT -p udp --dport 53 -j LOG --log-prefix "DNS-IN: "
iptables -I OUTPUT -p udp --sport 53 -j LOG --log-prefix "DNS-OUT: "
```

### **🤝 Coordinate with BIND Team**: 
- Share DNS server IPs and query patterns
- Report any DNS traffic anomalies immediately
- Ensure DNS traffic is NEVER blocked

### DNS Security Monitoring
```bash
# Check for DNS tunneling or exfiltration
# Large DNS queries
tcpdump -i any port 53 -s 0 | grep -E "length [5-9][0-9][0-9]"

# Unusual DNS query types
dig @localhost google.com TXT
dig @localhost google.com MX

# Stop DNS capture after 5 minutes
sleep 300
kill $DNS_TCPDUMP_PID 2>/dev/null
```

**🚨 Critical**: DNS issues affect ALL team scoring - escalate immediately

---

## 📋 Task 6: Web Traffic Analysis (Work with Windows/Linux Teams)

### HTTP/HTTPS Traffic Monitoring
```bash
# Monitor web traffic patterns
iptables -I INPUT -p tcp --dport 80 -j LOG --log-prefix "HTTP-IN: "
iptables -I INPUT -p tcp --dport 443 -j LOG --log-prefix "HTTPS-IN: "

# Check for web service availability
curl -I http://localhost 2>/dev/null | head -1
curl -I https://localhost 2>/dev/null | head -1

# Monitor for web attacks
tcpdump -i any port 80 -A -s 0 | grep -E "GET|POST|PUT|DELETE" | head -20
```

### **🤝 Coordinate with Windows/Linux Teams**: 
- Share web server status and traffic patterns
- Report suspicious web traffic immediately
- Ensure web traffic is NEVER blocked

### Web Security Monitoring
```bash
# Look for common attack patterns (5 minutes max)
# SQL injection attempts
tail -100 /var/log/firewall.log 2>/dev/null | grep -i -E "union|select|insert|drop|delete"

# Directory traversal attempts
tail -100 /var/log/firewall.log 2>/dev/null | grep -E "\.\./|\.\.\\|%2e%2e"

# Brute force attempts
tail -100 /var/log/firewall.log 2>/dev/null | grep -E "admin|login|wp-admin"
```

---

## 📋 Task 7: Database Traffic Monitoring

### Database Connection Analysis
```bash
# Monitor database traffic
iptables -I INPUT -p tcp --dport 3306 -j LOG --log-prefix "MYSQL-IN: "
iptables -I INPUT -p tcp --dport 5432 -j LOG --log-prefix "PGSQL-IN: "

# Check database connectivity
nc -zv localhost 3306 2>/dev/null && echo "MySQL accessible"
nc -zv localhost 5432 2>/dev/null && echo "PostgreSQL accessible"

# Monitor for database attacks
tcpdump -i any port 3306 -A -s 0 | head -20
tcpdump -i any port 5432 -A -s 0 | head -20
```

### **🤝 Coordinate with Windows/Linux Teams**: 
- Share database server status and connection patterns
- Report database traffic anomalies
- Ensure database traffic is NEVER blocked

---

## 📋 Task 8: File Sharing Traffic Analysis

### SMB/CIFS Traffic Monitoring
```bash
# Monitor SMB traffic
iptables -I INPUT -p tcp --dport 139 -j LOG --log-prefix "SMB-139: "
iptables -I INPUT -p tcp --dport 445 -j LOG --log-prefix "SMB-445: "

# Check SMB service availability
nc -zv localhost 139 2>/dev/null && echo "SMB port 139 accessible"
nc -zv localhost 445 2>/dev/null && echo "SMB port 445 accessible"

# Monitor for SMB attacks
tcpdump -i any port 445 -s 0 | head -20
```

### NFS Traffic Monitoring
```bash
# Monitor NFS traffic
iptables -I INPUT -p tcp --dport 2049 -j LOG --log-prefix "NFS: "
iptables -I INPUT -p udp --dport 2049 -j LOG --log-prefix "NFS-UDP: "

# Check NFS service
showmount -e localhost 2>/dev/null
```

---

## 📋 Task 9: SSH Traffic Analysis

### SSH Connection Monitoring
```bash
# Monitor SSH traffic (CRITICAL service)
iptables -I INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH-IN: "

# Check SSH service availability
nc -zv localhost 22 && echo "SSH accessible"

# Monitor SSH connection patterns
ss -t state established '( dport = :22 or sport = :22 )'
who | grep pts

# Check for SSH brute force
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20
```

### **🤝 Coordinate with Windows/Linux Teams**: 
- Share SSH access patterns and failed attempts
- Report SSH brute force attempts
- Ensure SSH traffic is NEVER blocked

---

## 📋 Task 10: Documentation & Monitoring Setup

### Traffic Analysis Documentation
```bash
# Document traffic patterns
cat > /tmp/firewall_analysis.txt << EOF
Firewall Team Analysis - $(date)
===============================
Network Topology: [Document segments]
Scored Services Identified: [List services and ports]
Suspicious Traffic: [List patterns]
Logging Configuration: [List log locations]
Monitoring Setup: [List monitoring tools]
Team Coordination: [List shared information]
EOF
```

### **🤝 Cross-Team Coordination Summary**
- **BIND Team**: DNS traffic patterns, query analysis
- **Windows Team**: Windows service ports, SMB traffic, RDP patterns
- **Linux Team**: SSH traffic, web service patterns, database connections
- **All Teams**: Scored service ports and traffic requirements

### Continuous Monitoring Setup
```bash
# Set up real-time monitoring
cat > /tmp/traffic_monitor.sh << 'EOF'
#!/bin/bash
while true; do
    echo "=== Traffic Monitor - $(date) ==="
    
    # Check scored service connectivity
    for port in 22 53 80 443 3306 5432; do
        connections=$(netstat -an | grep ":$port" | grep ESTABLISHED | wc -l)
        echo "Port $port: $connections active connections"
    done
    
    # Check for new suspicious connections
    netstat -an | grep ESTABLISHED | grep -v -E "127\.0\.0\.1|192\.168|10\." | head -5
    
    sleep 60
done
EOF

chmod +x /tmp/traffic_monitor.sh
# nohup /tmp/traffic_monitor.sh > /tmp/traffic_monitor.log &
```

---

## 🎯 Transition to Ongoing Ops

### Readiness Checklist
- [ ] Comprehensive logging enabled for all traffic
- [ ] Scored service ports identified and monitored
- [ ] Network topology documented
- [ ] Traffic patterns analyzed and documented
- [ ] Monitoring tools configured
- [ ] Cross-team coordination established
- [ ] **VERIFIED**: No blocking rules affecting scored services

### **When to Transition**
- All monitoring tasks completed OR
- 2 hours elapsed (whichever comes first)
- Move to "Firewall Team: Ongoing Ops" guide

---

## 🚨 Emergency Procedures

### Scored Service Down Emergency
1. **Check firewall rules FIRST**: Ensure no blocking rules
   ```bash
   iptables -L | grep -E "DROP|REJECT"
   iptables -L | grep [service_port]
   ```

2. **Verify connectivity**: Test from external source
   ```bash
   nc -zv [external_ip] [service_port]
   telnet [external_ip] [service_port]
   ```

3. **Coordinate immediately**: Inform relevant team
4. **Document**: Log all findings
5. **Escalate**: If connectivity issues persist

### Firewall Lockout Emergency
1. **Don't panic** - document current rules
2. **Use console access** if available
3. **Flush rules if necessary**: 
   ```bash
   iptables -F
   iptables -X
   iptables -t nat -F
   iptables -t mangle -F
   ```
4. **Re-enable logging only**: No blocking rules
5. **Contact team lead** immediately

### **🚨 NEVER DO THESE THINGS**:
- Block traffic to scored services
- Modify rules without testing connectivity first
- Make changes without coordinating with other teams
- Assume a connection is malicious without investigation

---

*Your role is DETECTION and ANALYSIS, not blocking. Focus on understanding traffic patterns and coordinating with other teams for response actions.*

**Remember: Monitoring and logging are your weapons, not blocking rules.**

