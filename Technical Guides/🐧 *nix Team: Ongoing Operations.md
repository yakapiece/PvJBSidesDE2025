# 🐧 *nix Team: Ongoing Operations

*Time-based operational guide for *nix subteam - Continuous monitoring and maintenance*

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
```bash
# Quick DNS verification (2 minutes max)
nslookup localhost
nslookup $(hostname)
systemctl is-active bind9 || systemctl is-active named || echo "DNS service check needed"
```
**🤝 Coordinate with BIND Team**: Report any DNS issues immediately

### Every 15 Minutes: Critical Service Status
```bash
# Service health check (3 minutes max)
CRITICAL_SERVICES="ssh apache2 nginx mysql postgresql bind9 dhcp-server nfs-server samba"
for service in $CRITICAL_SERVICES; do
    if systemctl is-active $service >/dev/null 2>&1; then
        echo "$service: RUNNING"
    else
        echo "ALERT: $service is NOT RUNNING"
        # Auto-restart if enabled
        if systemctl is-enabled $service >/dev/null 2>&1; then
            echo "Auto-restarting $service"
            systemctl restart $service
            sleep 3
            systemctl is-active $service && echo "$service: RESTARTED" || echo "$service: RESTART FAILED"
        fi
    fi
done
```

### Continuous Monitoring Setup
```bash
# Set up basic monitoring script
cat > /tmp/service_monitor.sh << 'EOF'
#!/bin/bash
while true; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check critical services
    services="ssh apache2 nginx mysql postgresql bind9 dhcp-server"
    for svc in $services; do
        if ! systemctl is-active $svc >/dev/null 2>&1; then
            echo "$timestamp - ALERT: $svc is not running" | tee -a /tmp/service_alerts.log
        fi
    done
    
    sleep 300  # Check every 5 minutes
done
EOF

chmod +x /tmp/service_monitor.sh
# nohup /tmp/service_monitor.sh &
```

---

## ⏰ Hour 2-4: Active Defense Phase

### Every 30 Minutes: Security Monitoring
```bash
# Quick security check (5 minutes max)
# New processes since last check
ps aux --sort=start_time | tail -20

# New network connections
ss -tulpn | grep -E ":22|:80|:443|:53|:3306|:5432"

# Failed login attempts (last 30 minutes)
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d %H:')" | tail -10 2>/dev/null
journalctl -u ssh --since "30 minutes ago" | grep -i failed | tail -5

# Check for new files in suspicious locations
find /tmp /var/tmp -type f -mmin -30 2>/dev/null | head -10
```

### Every Hour: Account Security Review
```bash
# Account activity check (3 minutes max)
# Recent successful logins
last -n 30 | head -15

# Check for new local accounts
current_users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | sort)
echo "$current_users" > /tmp/current_users_$(date +%H%M).txt

# Compare with baseline (if exists)
if [ -f /tmp/baseline_users.txt ]; then
    new_users=$(comm -13 /tmp/baseline_users.txt /tmp/current_users_$(date +%H%M).txt)
    if [ -n "$new_users" ]; then
        echo "NEW USERS DETECTED: $new_users"
    fi
fi

# Check sudo usage
grep sudo /var/log/auth.log | grep "$(date '+%b %d %H:')" | tail -10 2>/dev/null
```

### **🤝 Coordinate with Firewall Team**: Share suspicious network activity patterns

---

## ⏰ Hour 4-6: Optimization Phase

### Every 45 Minutes: Performance Monitoring
```bash
# System performance check (3 minutes max)
# CPU and memory usage
top -bn1 | head -5
free -h
uptime

# Disk space check
df -h | grep -E "/$|/var|/tmp|/home"

# Service response times (if web services)
if systemctl is-active apache2 >/dev/null || systemctl is-active nginx >/dev/null; then
    curl -o /dev/null -s -w "HTTP Response Time: %{time_total}s\n" http://localhost/ 2>/dev/null || echo "Web service check failed"
fi

# Database response times (if applicable)
if systemctl is-active mysql >/dev/null; then
    time mysql -e "SELECT 1;" >/dev/null 2>&1 && echo "MySQL response: OK" || echo "MySQL response: FAILED"
fi

if systemctl is-active postgresql >/dev/null; then
    time sudo -u postgres psql -c "SELECT 1;" >/dev/null 2>&1 && echo "PostgreSQL response: OK" || echo "PostgreSQL response: FAILED"
fi
```

### Service Optimization (if performance issues)
```bash
# Apache optimization (if applicable)
if systemctl is-active apache2 >/dev/null; then
    # Check active connections
    apache2ctl status 2>/dev/null | grep -E "requests|workers" || echo "Apache status not available"
    
    # Check error logs for issues
    tail -20 /var/log/apache2/error.log 2>/dev/null | grep -E "error|warning"
fi

# Nginx optimization (if applicable)
if systemctl is-active nginx >/dev/null; then
    # Check active connections
    curl -s http://localhost/nginx_status 2>/dev/null || echo "Nginx status not configured"
    
    # Check error logs
    tail -20 /var/log/nginx/error.log 2>/dev/null | grep -E "error|warning"
fi

# Database optimization (if applicable)
if systemctl is-active mysql >/dev/null; then
    # Check MySQL connections
    mysql -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null
    mysql -e "SHOW PROCESSLIST;" 2>/dev/null | wc -l
fi
```

---

## ⏰ Hour 6-8: Endgame Phase

### Every 20 Minutes: Critical Service Verification
```bash
# Intensive service monitoring (2 minutes max)
CRITICAL_SERVICES="ssh apache2 nginx mysql postgresql bind9 dhcp-server nfs-server samba"
for service in $CRITICAL_SERVICES; do
    if systemctl is-active $service >/dev/null 2>&1; then
        enabled=$(systemctl is-enabled $service 2>/dev/null)
        echo "$service: RUNNING ($enabled)"
    else
        echo "$service: NOT RUNNING"
        # Auto-restart critical services
        if systemctl is-enabled $service >/dev/null 2>&1; then
            echo "Auto-restarting $service"
            systemctl start $service
            sleep 3
        fi
    fi
done
```

### Final Security Sweep
```bash
# Last-hour security check (5 minutes max)
# Check for any new cron jobs
find /etc/cron* -type f -mmin -60 2>/dev/null
crontab -l 2>/dev/null | grep -v "^#"

# Check for new startup scripts
find /etc/systemd/system /etc/init.d -type f -mmin -60 2>/dev/null

# Final process check
ps aux | grep -E "nc|netcat|ncat|socat|python|perl|ruby" | grep -v grep
ps aux --sort=start_time | tail -10
```

### **🤝 Final Coordination with All Teams**
- Share any last-minute findings
- Confirm all services are stable
- Prepare for final scoring push

---

## 🔄 Continuous Tasks (Throughout Competition)

### Real-Time Monitoring Commands
```bash
# Keep these running in separate terminals

# Terminal 1: Service Monitor
while true; do
    clear
    echo "=== *nix Service Status - $(date) ==="
    services="ssh apache2 nginx mysql postgresql bind9 dhcp-server"
    for svc in $services; do
        if systemctl is-active $svc >/dev/null 2>&1; then
            echo -e "$svc : \033[32mRUNNING\033[0m"
        else
            echo -e "$svc : \033[31mNOT RUNNING\033[0m"
        fi
    done
    sleep 30
done

# Terminal 2: Network Monitor
while true; do
    clear
    echo "=== Network Connections - $(date) ==="
    ss -tulpn | grep -E ":22|:80|:443|:53|:3306|:5432"
    echo ""
    echo "=== Active SSH Sessions ==="
    who | grep pts
    sleep 60
done

# Terminal 3: Log Monitor
while true; do
    clear
    echo "=== Recent Auth Events - $(date) ==="
    tail -10 /var/log/auth.log 2>/dev/null | grep -E "Failed|Accepted"
    echo ""
    echo "=== Recent System Events ==="
    journalctl --since "10 minutes ago" | grep -E "Started|Stopped|Failed" | tail -5
    sleep 120
done
```

---

## 🚨 Incident Response Procedures

### Service Down Response (5-minute max)
1. **Immediate Check**:
   ```bash
   systemctl status [service] --no-pager -l
   journalctl -u [service] --since "10 minutes ago"
   ```

2. **Quick Restart**:
   ```bash
   systemctl restart [service]
   sleep 3
   systemctl status [service]
   ```

3. **If Restart Fails**:
   ```bash
   # Check configuration
   [service] -t  # For nginx, apache2ctl configtest for Apache
   
   # Check dependencies
   systemctl list-dependencies [service]
   
   # Check file permissions
   ls -la /etc/[service]/
   ```

4. **Escalate**: If not resolved in 5 minutes, escalate to team lead

### Security Incident Response (15-minute max)
1. **Document**: Copy evidence immediately
   ```bash
   ps aux > /tmp/incident_processes_$(date +%H%M).txt
   netstat -tulpn > /tmp/incident_network_$(date +%H%M).txt
   ```

2. **Contain**: Isolate affected process/connection
   ```bash
   pkill [suspicious_process]
   iptables -A INPUT -s [suspicious_ip] -j DROP  # Coordinate with Firewall team
   ```

3. **Assess Impact**: Check if scoring services affected
4. **Communicate**: Inform team lead and relevant teams
5. **Remediate**: Focus on service restoration, not perfect forensics

---

## 📊 Status Reporting Templates

### Hourly Status Report
```
*NIX TEAM - HOUR [X] STATUS
===========================
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
*NIX TEAM - FINAL REPORT
========================
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
- **Use screen/tmux** for persistent sessions
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
```bash
# Service management
systemctl status [service]
systemctl start [service]
systemctl stop [service]
systemctl restart [service]
systemctl enable [service]
systemctl disable [service]

# Process management
ps aux | grep [process]
pgrep [process]
pkill [process]
kill -9 [PID]

# Network troubleshooting
ss -tulpn | grep [port]
netstat -tulpn | grep [port]
telnet [host] [port]
nc -zv [host] [port]

# Log analysis
journalctl -u [service] -f
tail -f /var/log/[logfile]
grep -i error /var/log/[logfile]
```

### Emergency Recovery
```bash
# File system check
df -h
mount | column -t
lsof | grep [file]

# Network reset
systemctl restart networking
systemctl restart NetworkManager
ip addr flush dev [interface]
dhclient [interface]

# Service dependency check
systemctl list-dependencies [service]
systemctl show [service] -p Requires
systemctl show [service] -p After
```

### Quick Diagnostics
```bash
# System health
uptime
free -h
df -h
iostat 1 3
vmstat 1 3

# Network connectivity
ping -c 3 8.8.8.8
traceroute 8.8.8.8
dig @8.8.8.8 google.com

# Service ports
ss -tulpn | grep LISTEN
nmap -sT localhost
```

---

*Remember: In the final hours, focus on stability over optimization. Keep services running and communicate with your team. Simple solutions are often the best solutions.*

**Stay calm, stay focused, and prioritize service availability above all else.**

