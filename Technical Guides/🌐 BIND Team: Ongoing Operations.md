# 🌐 BIND Team: Ongoing Operations

*Time-based operational guide for BIND subteam - Continuous DNS monitoring and maintenance*

---

## 🚨 V2 Safety Protocols - Always Remember

### Ongoing Operations Rules
- **DNS Check Every 15 Minutes**: DNS failure = zero points for ALL teams
- **Test Before Change**: ALL DNS changes tested with non-critical queries first
- **Service First**: 80% effort on DNS availability and performance
- **Cascade Awareness**: Your service affects every other team's scoring
- **Immediate Communication**: DNS issues must be reported to ALL teams instantly

### **🚨 CRITICAL REMINDER**: DNS Scoring Dependency
- **You are the single point of failure for the entire team**
- **ALL other services depend on DNS resolution**
- **DNS downtime = zero points for everyone**
- **Your performance directly determines team success**

---

## ⏰ Hour 1-2: DNS Stability Phase

### Every 15 Minutes: Critical DNS Health Check
```bash
# Essential DNS verification (2 minutes max)
echo "=== DNS Health Check - $(date) ==="

# Test local resolution
if nslookup localhost >/dev/null 2>&1; then
    echo "Local resolution: OK"
else
    echo "CRITICAL ALERT: Local resolution FAILED"
    echo "$(date): Local DNS resolution failed" >> /tmp/critical_dns_alerts.log
fi

# Test hostname resolution
if dig @localhost $(hostname) >/dev/null 2>&1; then
    echo "Hostname resolution: OK"
else
    echo "CRITICAL ALERT: Hostname resolution FAILED"
    echo "$(date): Hostname DNS resolution failed" >> /tmp/critical_dns_alerts.log
fi

# Test external resolution
if dig @localhost google.com >/dev/null 2>&1; then
    echo "External resolution: OK"
else
    echo "WARNING: External resolution FAILED"
    echo "$(date): External DNS resolution failed" >> /tmp/dns_warnings.log
fi

# Verify service is running
systemctl is-active bind9 >/dev/null 2>&1 || systemctl is-active named >/dev/null 2>&1 || echo "CRITICAL: DNS service not running"
```

**🤝 Report to ALL Teams**: Any DNS issues must be communicated immediately

### Every 30 Minutes: DNS Performance Monitoring
```bash
# DNS performance check (3 minutes max)
echo "=== DNS Performance Check - $(date) ==="

# Response time testing
echo "Local response times:"
time dig @localhost $(hostname) | grep "Query time"
time dig @localhost localhost | grep "Query time"

# External response time
echo "External response times:"
time dig @localhost google.com | grep "Query time"

# Query load monitoring
if [ -f /var/log/bind/query.log ]; then
    queries_last_30min=$(grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | wc -l)
    echo "Queries in last 30 minutes: $queries_last_30min"
fi

# Check for errors in logs
tail -20 /var/log/syslog | grep -i named | grep -E "error|warning|failed"
```

### Continuous DNS Monitoring Setup
```bash
# Enhanced DNS monitoring script
cat > /tmp/dns_continuous_monitor.sh << 'EOF'
#!/bin/bash
while true; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Critical resolution tests
    if ! nslookup localhost >/dev/null 2>&1; then
        echo "$timestamp - CRITICAL: Local DNS resolution failed" | tee -a /tmp/critical_dns_alerts.log
        # Attempt automatic restart
        systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
        sleep 5
    fi
    
    if ! dig @localhost $(hostname) >/dev/null 2>&1; then
        echo "$timestamp - CRITICAL: Hostname resolution failed" | tee -a /tmp/critical_dns_alerts.log
    fi
    
    # Service status check
    if ! systemctl is-active bind9 >/dev/null 2>&1 && ! systemctl is-active named >/dev/null 2>&1; then
        echo "$timestamp - CRITICAL: DNS service not running" | tee -a /tmp/critical_dns_alerts.log
        # Attempt automatic restart
        systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
    fi
    
    sleep 180  # Check every 3 minutes
done
EOF

chmod +x /tmp/dns_continuous_monitor.sh
# nohup /tmp/dns_continuous_monitor.sh &
```

---

## ⏰ Hour 2-4: DNS Optimization Phase

### Every 30 Minutes: DNS Query Analysis
```bash
# Query pattern analysis (5 minutes max)
echo "=== DNS Query Analysis - $(date) ==="

# Analyze query types
if [ -f /var/log/bind/query.log ]; then
    echo "Query type distribution (last hour):"
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -nr | head -10
    
    echo "Top queried domains (last hour):"
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $7}' | sort | uniq -c | sort -nr | head -10
    
    echo "Query sources (last hour):"
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $4}' | cut -d'#' -f1 | sort | uniq -c | sort -nr | head -10
fi

# Check for unusual query patterns
if [ -f /var/log/bind/query.log ]; then
    # Look for potential DNS tunneling
    long_queries=$(grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk 'length($7) > 50' | wc -l)
    if [ $long_queries -gt 0 ]; then
        echo "WARNING: $long_queries unusually long DNS queries detected"
    fi
    
    # Look for high-frequency queries from single source
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $4}' | cut -d'#' -f1 | sort | uniq -c | awk '$1 > 100 {print "High query volume from: " $2 " (" $1 " queries)"}'
fi
```

### DNS Cache Performance Monitoring
```bash
# Cache performance analysis (3 minutes max)
echo "=== DNS Cache Analysis - $(date) ==="

# Check cache statistics (if available)
if command -v rndc >/dev/null 2>&1; then
    rndc stats 2>/dev/null
    if [ -f /var/cache/bind/named.stats ]; then
        echo "Cache hit ratio:"
        tail -50 /var/cache/bind/named.stats | grep -E "cache|hits|misses" | tail -10
    fi
fi

# Test cache effectiveness
echo "Testing cache effectiveness:"
# First query (should be slow)
time1=$(time dig @localhost google.com 2>&1 | grep "Query time" | awk '{print $4}')
# Second query (should be faster from cache)
time2=$(time dig @localhost google.com 2>&1 | grep "Query time" | awk '{print $4}')
echo "First query: ${time1}ms, Second query: ${time2}ms"

# Check cache size
du -sh /var/cache/bind/ 2>/dev/null | awk '{print "Cache size: " $1}'
```

### **🤝 Coordinate with Firewall Team**: Share DNS query patterns and potential security issues

---

## ⏰ Hour 4-6: DNS Security Monitoring Phase

### Every 45 Minutes: DNS Security Analysis
```bash
# DNS security monitoring (5 minutes max)
echo "=== DNS Security Analysis - $(date) ==="

# Check for DNS amplification attempts
if [ -f /var/log/bind/query.log ]; then
    echo "Checking for potential DNS amplification:"
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | grep -E "ANY|TXT" | wc -l | awk '{if($1>10) print "Potential amplification attempts: " $1}'
fi

# Monitor for suspicious domains
if [ -f /var/log/bind/query.log ]; then
    echo "Checking for suspicious domain patterns:"
    grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | grep -E "\.tk|\.ml|\.ga|\.cf|dga|random" | head -5
fi

# Check for zone transfer attempts
grep "$(date '+%b %d %H:')" /var/log/syslog 2>/dev/null | grep -i "transfer" | grep -i "denied\|refused" | wc -l | awk '{if($1>0) print "Zone transfer attempts blocked: " $1}'

# Monitor for configuration changes
find /etc/bind /etc/named -name "*.conf" -o -name "*.zone" -mmin -45 2>/dev/null | while read file; do
    echo "Recent config change: $file ($(stat -c %y "$file"))"
done
```

### DNS Threat Detection
```bash
# Advanced threat detection (5 minutes max)
echo "=== DNS Threat Detection - $(date) ==="

# Check for DNS tunneling indicators
if [ -f /var/log/bind/query.log ]; then
    # Look for base64-like patterns in queries
    base64_queries=$(grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | grep -E "[A-Za-z0-9+/]{20,}" | wc -l)
    if [ $base64_queries -gt 0 ]; then
        echo "Potential DNS tunneling detected: $base64_queries suspicious queries"
    fi
    
    # Look for subdomain enumeration
    enum_attempts=$(grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $7}' | grep -E "^[a-z0-9-]{1,10}\." | sort | uniq | wc -l)
    if [ $enum_attempts -gt 50 ]; then
        echo "Potential subdomain enumeration: $enum_attempts unique subdomains queried"
    fi
fi

# Check for DGA (Domain Generation Algorithm) patterns
if [ -f /var/log/bind/query.log ]; then
    dga_patterns=$(grep "$(date '+%d-%b-%Y %H:')" /var/log/bind/query.log 2>/dev/null | awk '{print $7}' | grep -E "^[a-z]{8,20}\.[a-z]{2,3}$" | wc -l)
    if [ $dga_patterns -gt 20 ]; then
        echo "Potential DGA activity: $dga_patterns suspicious domain patterns"
    fi
fi
```

### **🤝 Coordinate with All Teams**: Share security findings that may affect other services

---

## ⏰ Hour 6-8: DNS Endgame Phase

### Every 20 Minutes: Critical DNS Verification
```bash
# Intensive DNS monitoring (2 minutes max)
echo "=== Critical DNS Verification - $(date) ==="

# Test all critical resolutions
critical_tests=("localhost" "$(hostname)" "google.com")
for test in "${critical_tests[@]}"; do
    if dig @localhost "$test" >/dev/null 2>&1; then
        echo "$test resolution: OK"
    else
        echo "CRITICAL ALERT: $test resolution FAILED"
        echo "$(date): $test resolution failed" >> /tmp/critical_dns_alerts.log
        
        # Attempt immediate service restart
        echo "Attempting DNS service restart..."
        systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
        sleep 3
        
        # Retest after restart
        if dig @localhost "$test" >/dev/null 2>&1; then
            echo "$test resolution: RECOVERED after restart"
        else
            echo "CRITICAL: $test resolution still FAILED after restart"
        fi
    fi
done

# Verify service is running and listening
if systemctl is-active bind9 >/dev/null 2>&1 || systemctl is-active named >/dev/null 2>&1; then
    if ss -tulpn | grep :53 >/dev/null; then
        echo "DNS service: RUNNING and LISTENING"
    else
        echo "CRITICAL: DNS service running but NOT LISTENING on port 53"
    fi
else
    echo "CRITICAL: DNS service NOT RUNNING"
fi
```

### Final DNS Performance Optimization
```bash
# Final performance check (3 minutes max)
echo "=== Final DNS Performance Check - $(date) ==="

# Response time verification
for query in "localhost" "$(hostname)" "google.com"; do
    response_time=$(dig @localhost "$query" | grep "Query time" | awk '{print $4}')
    echo "$query response time: ${response_time}ms"
    
    # Alert if response time is too high
    if [ "${response_time:-999}" -gt 100 ]; then
        echo "WARNING: Slow response time for $query: ${response_time}ms"
    fi
done

# Check system resources
echo "DNS service resource usage:"
ps aux | grep -E "named|bind" | grep -v grep | awk '{print "CPU: " $3 "%, Memory: " $4 "%"}'

# Final cache statistics
if command -v rndc >/dev/null 2>&1; then
    rndc stats 2>/dev/null
    if [ -f /var/cache/bind/named.stats ]; then
        echo "Final cache statistics:"
        tail -20 /var/cache/bind/named.stats | grep -E "queries|responses" | tail -5
    fi
fi
```

### **🤝 Final Coordination with ALL Teams**
- Confirm DNS is stable and performing well
- Share final performance metrics
- Ensure all teams can resolve critical hostnames

---

## 🔄 Continuous Tasks (Throughout Competition)

### Real-Time DNS Monitoring Dashboards
```bash
# Keep these running in separate terminals

# Terminal 1: DNS Service Status Monitor
while true; do
    clear
    echo "=== DNS Service Dashboard - $(date) ==="
    
    # Service status
    if systemctl is-active bind9 >/dev/null 2>&1 || systemctl is-active named >/dev/null 2>&1; then
        echo -e "DNS Service: \033[32mRUNNING\033[0m"
    else
        echo -e "DNS Service: \033[31mNOT RUNNING\033[0m"
    fi
    
    # Port 53 status
    if ss -tulpn | grep :53 >/dev/null; then
        echo -e "Port 53: \033[32mLISTENING\033[0m"
    else
        echo -e "Port 53: \033[31mNOT LISTENING\033[0m"
    fi
    
    # Critical resolution tests
    tests=("localhost" "$(hostname)" "google.com")
    for test in "${tests[@]}"; do
        if dig @localhost "$test" >/dev/null 2>&1; then
            echo -e "$test: \033[32mOK\033[0m"
        else
            echo -e "$test: \033[31mFAILED\033[0m"
        fi
    done
    
    sleep 30
done

# Terminal 2: DNS Query Monitor
while true; do
    clear
    echo "=== DNS Query Dashboard - $(date) ==="
    
    if [ -f /var/log/bind/query.log ]; then
        echo "Recent queries (last 10):"
        tail -10 /var/log/bind/query.log | awk '{print $1, $2, $3, $7}'
        
        echo ""
        echo "Query volume (last 5 minutes):"
        grep "$(date '+%d-%b-%Y %H:%M')" /var/log/bind/query.log 2>/dev/null | wc -l | awk '{print "Queries: " $1}'
    else
        echo "Query logging not available"
    fi
    
    sleep 60
done

# Terminal 3: DNS Performance Monitor
while true; do
    clear
    echo "=== DNS Performance Dashboard - $(date) ==="
    
    # Response times
    for query in "localhost" "google.com"; do
        response_time=$(dig @localhost "$query" 2>/dev/null | grep "Query time" | awk '{print $4}')
        echo "$query: ${response_time:-N/A}ms"
    done
    
    echo ""
    echo "System resources:"
    ps aux | grep -E "named|bind" | grep -v grep | awk '{print "CPU: " $3 "%, Memory: " $4 "%"}'
    
    echo ""
    echo "Recent errors:"
    tail -5 /var/log/syslog | grep -i named | grep -E "error|warning"
    
    sleep 120
done
```

---

## 🚨 Incident Response Procedures

### DNS Service Down (CRITICAL - 1-minute max)
1. **Immediate Restart**:
   ```bash
   systemctl restart bind9 || systemctl restart named
   sleep 3
   systemctl status bind9 || systemctl status named
   ```

2. **Quick Verification**:
   ```bash
   nslookup localhost
   dig @localhost $(hostname)
   ss -tulpn | grep :53
   ```

3. **If Still Down**:
   ```bash
   named-checkconf
   tail -20 /var/log/syslog | grep named
   ```

4. **Emergency Communication**: Notify ALL teams immediately

### DNS Resolution Failing (CRITICAL - 2-minute max)
1. **Test Service Status**:
   ```bash
   systemctl is-active bind9 || systemctl is-active named
   ss -tulpn | grep :53
   ```

2. **Test External DNS**:
   ```bash
   dig @8.8.8.8 google.com
   ```

3. **Check Configuration**:
   ```bash
   named-checkconf
   grep forwarders /etc/bind/named.conf*
   ```

4. **Emergency Forwarder Fix**:
   ```bash
   # If forwarders are broken, add emergency forwarders
   echo "forwarders { 8.8.8.8; 1.1.1.1; };" >> /etc/bind/named.conf.options
   systemctl restart bind9 || systemctl restart named
   ```

### DNS Performance Degradation (3-minute max)
1. **Check System Resources**:
   ```bash
   top -p $(pgrep named)
   df -h /var/cache/bind
   ```

2. **Clear Cache if Needed**:
   ```bash
   rndc flush
   ```

3. **Check for High Query Volume**:
   ```bash
   tail -100 /var/log/bind/query.log | wc -l
   ```

4. **Restart if Necessary**:
   ```bash
   systemctl restart bind9 || systemctl restart named
   ```

---

## 📊 Status Reporting Templates

### Every 30 Minutes Status Report
```
BIND TEAM - HOUR [X] STATUS
===========================
Time: [HH:MM]
DNS Service: [RUNNING/DOWN]
Local Resolution: [OK/FAILED]
Hostname Resolution: [OK/FAILED]
External Resolution: [OK/FAILED]
Query Volume: [HIGH/MEDIUM/LOW]
Response Times: [GOOD/SLOW/TIMEOUT]
Security Events: [COUNT]
Critical Alerts: [COUNT]
Team Impact: [ALL TEAMS OK/ISSUES]
```

### Critical Incident Report
```
DNS CRITICAL INCIDENT - [TIME]
==============================
Incident: [DESCRIPTION]
Impact: [ALL TEAMS/SPECIFIC TEAMS]
Duration: [START TIME - END TIME]
Root Cause: [CAUSE]
Resolution: [ACTIONS TAKEN]
Prevention: [FUTURE MEASURES]
Team Notification: [COMPLETED/PENDING]
```

### End-of-Competition Summary
```
BIND TEAM - FINAL REPORT
========================
Total Uptime: [PERCENTAGE]
Total Queries Processed: [COUNT]
Average Response Time: [MS]
Critical Incidents: [COUNT]
Security Events: [COUNT]
Team Impact Events: [COUNT]
Performance Optimization: [SUMMARY]
Lessons Learned: [KEY POINTS]
Recommendations: [FOR NEXT TIME]
```

---

## 🎯 Optimization Tips for Long Competition

### DNS Service Reliability
- **Monitor every 15 minutes minimum**
- **Automate service restarts** for common failures
- **Keep configuration backups** ready
- **Test changes on non-critical queries first**

### Performance Management
- **Monitor response times continuously**
- **Clear cache if performance degrades**
- **Watch for resource exhaustion**
- **Optimize forwarder configuration**

### Team Coordination
- **Immediate notification** for any DNS issues
- **Regular status updates** every 30 minutes
- **Share query patterns** with Firewall team
- **Coordinate with all teams** for hostname changes

---

## 🔧 Emergency Command Reference

### Quick DNS Tests
```bash
# Basic resolution tests
nslookup localhost
dig @localhost $(hostname)
dig @localhost google.com
host $(hostname)

# Service status
systemctl status bind9
systemctl status named
ss -tulpn | grep :53
ps aux | grep named

# Configuration validation
named-checkconf
named-checkzone [zone] [file]
```

### Emergency Recovery
```bash
# Service management
systemctl restart bind9
systemctl restart named
systemctl enable bind9
systemctl enable named

# Configuration fixes
named-checkconf
cp /tmp/dns_backup/* /etc/bind/
chown -R bind:bind /var/lib/bind/

# Cache management
rndc flush
rndc reload
rndc stats
```

### Performance Diagnostics
```bash
# Response time testing
time dig @localhost google.com
time nslookup $(hostname)

# Resource monitoring
top -p $(pgrep named)
df -h /var/cache/bind
du -sh /var/cache/bind

# Query analysis
tail -100 /var/log/bind/query.log
grep "$(date '+%H:%M')" /var/log/bind/query.log | wc -l
```

---

*Remember: You are the foundation of the entire team's success. DNS failure means everyone fails. Your vigilance and quick response to issues directly determines the team's final score.*

**Stay alert, stay responsive, and keep DNS running at all costs.**

