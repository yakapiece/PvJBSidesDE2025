# 🌐 BIND Team: Initial Inventory & Triage → Remediation

*Task-based guide for BIND subteam - Complete these tasks before moving to ongoing operations*

---

## 🚨 V2 Safety Protocols - READ FIRST

### Critical Rules for the BIND Team
- **DNS IS EVERYTHING**: If DNS fails, ALL services score ZERO points across all teams
- **Test Before Change**: ALL DNS changes are tested with non-critical queries first
- **Service Priority**: 80% effort on DNS availability, 15% understanding, 5% evidence
- **Cascade Awareness**: DNS failure cascades to every other service
- **Team Coordination**: DNS issues affect ALL teams - communicate immediately

### **🚨 CRITICAL**: DNS Scoring Dependency
- **ALL scoring starts with DNS resolution to your DNS server**
- **If DNS fails, ZERO other checks proceed for any asset**.
- **DNS is the single point of failure for the entire team scoring**
- **Your team's performance directly affects everyone else's score**.

---

## 📋 Task 1: DNS Service Assessment (10 minutes max)

### DNS Service Identification and Status
```bash
# Identify DNS service type and version
systemctl status bind9 2>/dev/null || systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null

# Check BIND version and configuration
named -v 2>/dev/null || /usr/sbin/named -v 2>/dev/null
which named dig nslookup host

# Verify DNS service is running and listening
ss -tulpn | grep :53
netstat -tulpn | grep :53
ps aux | grep -E "named|bind|dnsmasq" | grep -v grep
```

### DNS Configuration Discovery
```bash
# Locate BIND configuration files
find /etc -name "named.conf*" 2>/dev/null
find /etc -name "bind*" -type d 2>/dev/null
ls -la /etc/bind/ 2>/dev/null || ls -la /etc/named/ 2>/dev/null

# Check main configuration
cat /etc/bind/named.conf 2>/dev/null | head -20
cat /etc/named.conf 2>/dev/null | head -20

# Identify zone files location
grep -E "zone|file" /etc/bind/named.conf* 2>/dev/null | head -10
grep -E "zone|file" /etc/named.conf* 2>/dev/null | head -10
```

### DNS Resolution Testing
```bash
# Test basic DNS functionality
nslookup localhost
nslookup $(hostname)
dig @localhost $(hostname)
dig @localhost google.com

# Test from external perspective (if possible)
dig @8.8.8.8 $(hostname)
host $(hostname)
```

**⏰ Time Limit**: 10 minutes maximum - focus on service status first

---

## 📋 Task 2: Zone Configuration Analysis (Critical)

### Zone File Discovery and Validation
```bash
# Find all zone files
find /var/lib/bind /etc/bind /var/named /etc/named -name "*.zone" -o -name "db.*" 2>/dev/null

# Check zone file syntax
named-checkconf 2>/dev/null && echo "Configuration syntax: OK" || echo "Configuration syntax: ERROR"

# Validate individual zone files
for zone_file in $(find /var/lib/bind /etc/bind -name "*.zone" 2>/dev/null | head -5); do
    echo "Checking $zone_file"
    named-checkzone $(basename $zone_file .zone) $zone_file 2>/dev/null
done
```

### Critical Zone Records Verification
```bash
# Check SOA records for all zones
dig @localhost SOA $(hostname | cut -d. -f2-)
dig @localhost SOA localhost

# Check A records for critical hosts
dig @localhost A $(hostname)
dig @localhost A localhost

# Check NS records
dig @localhost NS $(hostname | cut -d. -f2-)

# Check MX records (if applicable)
dig @localhost MX $(hostname | cut -d. -f2-)
```

### **🤝 Coordinate with All Teams**: Share zone information and critical hostnames

---

## 📋 Task 3: DNS Security Assessment

### DNSSEC Configuration Check
```bash
# Check if DNSSEC is enabled
grep -i dnssec /etc/bind/named.conf* 2>/dev/null
dig @localhost DNSKEY $(hostname | cut -d. -f2-)
dig @localhost DS $(hostname | cut -d. -f2-)

# Check DNSSEC validation
dig @localhost +dnssec google.com | grep -E "RRSIG|ad"
```

### DNS Security Features
```bash
# Check for DNS security features
grep -E "allow-query|allow-transfer|allow-update|recursion" /etc/bind/named.conf* 2>/dev/null

# Check for rate limiting
grep -E "rate-limit|response-rate" /etc/bind/named.conf* 2>/dev/null

# Check access controls
grep -E "acl|allow-query" /etc/bind/named.conf* 2>/dev/null
```

### DNS Cache and Forwarders
```bash
# Check forwarder configuration
grep -E "forwarders|forward" /etc/bind/named.conf* 2>/dev/null

# Test forwarder functionality
dig @localhost google.com
dig @8.8.8.8 google.com

# Check cache status (if available)
rndc dumpdb -cache 2>/dev/null
ls -la /var/cache/bind/ 2>/dev/null
```

---

## 📋 Task 4: DNS Service Restoration Priority

### Critical DNS Service Recovery
```bash
# Restart DNS service if not running
if ! systemctl is-active bind9 >/dev/null 2>&1 && ! systemctl is-active named >/dev/null 2>&1; then
    echo "DNS service not running - attempting restart"
    systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
    sleep 5
    systemctl status bind9 2>/dev/null || systemctl status named 2>/dev/null
fi

# Verify DNS is listening on port 53
ss -tulpn | grep :53 || echo "CRITICAL: DNS not listening on port 53"

# Test basic resolution after restart
nslookup localhost
dig @localhost $(hostname)
```

### DNS Configuration Repair
```bash
# Check and fix common configuration issues
# Verify named.conf syntax
named-checkconf 2>/dev/null || echo "CRITICAL: Configuration syntax error"

# Check zone file permissions
ls -la /var/lib/bind/ 2>/dev/null | head -10
ls -la /etc/bind/ 2>/dev/null | head -10

# Ensure proper ownership
chown -R bind:bind /var/lib/bind/ 2>/dev/null
chown -R named:named /var/named/ 2>/dev/null
```

### **🚨 Critical**: Immediate DNS Functionality Test
```bash
# Test resolution for scored services
echo "Testing DNS resolution for critical services:"
nslookup $(hostname)
dig @localhost A $(hostname)
dig @localhost PTR $(hostname -I | awk '{print $1}')

# Test external resolution (forwarders)
dig @localhost google.com
nslookup google.com localhost
```

**🚨 If DNS tests fail**: This is a CRITICAL emergency - escalate immediately

---

## 📋 Task 5: Zone File Security and Integrity

### Zone File Backup and Documentation
```bash
# Create backup of current zone files
mkdir -p /tmp/dns_backup
cp /var/lib/bind/*.zone /tmp/dns_backup/ 2>/dev/null
cp /etc/bind/db.* /tmp/dns_backup/ 2>/dev/null
cp /etc/bind/named.conf* /tmp/dns_backup/ 2>/dev/null

# Document current zone configuration
for zone in $(grep -E "^zone" /etc/bind/named.conf* 2>/dev/null | awk '{print $2}' | tr -d '"'); do
    echo "Zone: $zone"
    dig @localhost SOA $zone
    dig @localhost NS $zone
done > /tmp/zone_documentation.txt
```

### Zone File Integrity Check
```bash
# Check for suspicious entries in zone files
grep -E "\.onion|\.bit|suspicious|hack|pwn" /var/lib/bind/*.zone /etc/bind/db.* 2>/dev/null

# Check for unusual TTL values
grep -E "TTL.*[0-9]{6,}" /var/lib/bind/*.zone /etc/bind/db.* 2>/dev/null

# Check for wildcard records
grep "\*" /var/lib/bind/*.zone /etc/bind/db.* 2>/dev/null

# Verify serial numbers are reasonable
grep -E "serial|Serial" /var/lib/bind/*.zone /etc/bind/db.* 2>/dev/null
```

### **🤝 Coordinate with Firewall Team**: Share DNS server IPs and query patterns

---

## 📋 Task 6: DNS Logging and Monitoring Setup

### Enable DNS Query Logging
```bash
# Enable query logging in BIND
# Add to named.conf if not present:
cat >> /etc/bind/named.conf.local << 'EOF'
logging {
    channel query_log {
        file "/var/log/bind/query.log" versions 3 size 5m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    category queries { query_log; };
};
EOF

# Create log directory
mkdir -p /var/log/bind
chown bind:bind /var/log/bind 2>/dev/null

# Restart to apply logging
systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null
```

### DNS Monitoring Setup
```bash
# Set up basic DNS monitoring
cat > /tmp/dns_monitor.sh << 'EOF'
#!/bin/bash
while true; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Test local resolution
    if nslookup localhost >/dev/null 2>&1; then
        echo "$timestamp - DNS local resolution: OK"
    else
        echo "$timestamp - CRITICAL: DNS local resolution FAILED" | tee -a /tmp/dns_alerts.log
    fi
    
    # Test external resolution
    if dig @localhost google.com >/dev/null 2>&1; then
        echo "$timestamp - DNS external resolution: OK"
    else
        echo "$timestamp - WARNING: DNS external resolution FAILED" | tee -a /tmp/dns_alerts.log
    fi
    
    sleep 300  # Check every 5 minutes
done
EOF

chmod +x /tmp/dns_monitor.sh
# nohup /tmp/dns_monitor.sh &
```

### **🤝 Coordinate with All Teams**: Share DNS monitoring status and any issues

---

## 📋 Task 7: DNS Performance Optimization

### DNS Cache Configuration
```bash
# Check current cache settings
grep -E "max-cache-size|cleaning-interval" /etc/bind/named.conf* 2>/dev/null

# Optimize cache settings (if needed)
# Add to named.conf options section:
# max-cache-size 256M;
# cleaning-interval 60;

# Check current cache statistics
rndc stats 2>/dev/null
cat /var/cache/bind/named.stats 2>/dev/null | tail -20
```

### DNS Response Time Testing
```bash
# Test DNS response times
echo "Testing DNS response times:"
time dig @localhost $(hostname)
time dig @localhost google.com
time nslookup $(hostname) localhost

# Compare with external DNS
echo "Comparing with external DNS:"
time dig @8.8.8.8 google.com
time dig @1.1.1.1 google.com
```

### DNS Load Testing (Brief)
```bash
# Quick load test (30 seconds only)
echo "Brief DNS load test:"
for i in {1..10}; do
    dig @localhost google.com >/dev/null 2>&1 &
    dig @localhost $(hostname) >/dev/null 2>&1 &
done
wait

# Check if service is still responsive
nslookup localhost
```

**⏰ Time Limit**: 5 minutes maximum for performance testing

---

## 📋 Task 8: DNS Security Hardening

### Access Control Configuration
```bash
# Review and secure access controls
grep -A 5 -B 5 "allow-query" /etc/bind/named.conf* 2>/dev/null

# Check recursion settings
grep -E "recursion|allow-recursion" /etc/bind/named.conf* 2>/dev/null

# Verify zone transfer restrictions
grep -E "allow-transfer|also-notify" /etc/bind/named.conf* 2>/dev/null
```

### DNS Security Features
```bash
# Enable response rate limiting (if not enabled)
grep "rate-limit" /etc/bind/named.conf* 2>/dev/null || echo "Consider enabling rate limiting"

# Check for version hiding
grep -E "version|hostname" /etc/bind/named.conf* 2>/dev/null

# Verify empty zones configuration
grep -E "empty-zones-enable|disable-empty-zone" /etc/bind/named.conf* 2>/dev/null
```

### **🚨 V2 Safety**: Secure but Functional
```bash
# Ensure security doesn't break functionality
# Test that all teams can still resolve
nslookup $(hostname)
dig @localhost A $(hostname)

# Test external resolution still works
dig @localhost google.com
nslookup google.com localhost
```

**🚨 Critical**: Any security changes must maintain full DNS functionality

---

## 📋 Task 9: DNS Troubleshooting Preparation

### DNS Diagnostic Tools Setup
```bash
# Verify diagnostic tools are available
which dig nslookup host rndc named-checkconf named-checkzone

# Create diagnostic script
cat > /tmp/dns_diagnostics.sh << 'EOF'
#!/bin/bash
echo "=== DNS Diagnostics - $(date) ==="

echo "1. Service Status:"
systemctl is-active bind9 2>/dev/null || systemctl is-active named 2>/dev/null

echo "2. Port 53 Status:"
ss -tulpn | grep :53

echo "3. Local Resolution Test:"
nslookup localhost

echo "4. External Resolution Test:"
dig @localhost google.com | grep -E "ANSWER|status"

echo "5. Configuration Syntax:"
named-checkconf 2>/dev/null && echo "OK" || echo "ERROR"

echo "6. Recent Errors:"
tail -10 /var/log/syslog | grep -i named
EOF

chmod +x /tmp/dns_diagnostics.sh
```

### Common DNS Issue Preparation
```bash
# Document common fixes
cat > /tmp/dns_common_fixes.txt << 'EOF'
Common DNS Issues and Fixes:

1. Service not running:
   systemctl restart bind9 || systemctl restart named

2. Configuration syntax error:
   named-checkconf
   Check /etc/bind/named.conf for syntax

3. Zone file error:
   named-checkzone [zone] [file]
   Check zone file syntax

4. Permission issues:
   chown -R bind:bind /var/lib/bind/
   chmod 644 /var/lib/bind/*.zone

5. Port 53 not listening:
   Check if another service is using port 53
   netstat -tulpn | grep :53

6. Resolution failing:
   Check forwarders in named.conf
   Test with dig @8.8.8.8 google.com
EOF
```

---

## 📋 Task 10: Documentation & Team Coordination

### DNS Configuration Documentation
```bash
# Document DNS setup for team
cat > /tmp/dns_team_info.txt << EOF
BIND Team Configuration - $(date)
================================
DNS Service: $(systemctl is-active bind9 2>/dev/null || systemctl is-active named 2>/dev/null)
DNS Server IP: $(hostname -I | awk '{print $1}')
Primary Zones: $(grep -c "^zone" /etc/bind/named.conf* 2>/dev/null || echo "Unknown")
Forwarders: $(grep -A 2 "forwarders" /etc/bind/named.conf* 2>/dev/null | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -2)
Query Logging: $(test -f /var/log/bind/query.log && echo "Enabled" || echo "Disabled")
Critical Hostnames: $(hostname), localhost
EOF
```

### **🤝 Cross-Team Coordination Summary**
- **All Teams**: DNS server IP, critical hostnames, resolution status
- **Firewall Team**: DNS traffic patterns, port 53 monitoring
- **Windows Team**: Windows DNS client configuration
- **Linux Team**: Linux DNS client configuration

### Status Report Template
```
BIND TEAM STATUS - [TIME]
========================
DNS Service: [RUNNING/STOPPED]
Local Resolution: [WORKING/FAILED]
External Resolution: [WORKING/FAILED]
Zone Files: [OK/ERRORS]
Query Logging: [ENABLED/DISABLED]
Critical Issues: [LIST]
Team Impact: [ALL TEAMS AFFECTED/SPECIFIC TEAMS]
Next Phase: Ready for Ongoing Ops / Need [X] more time
```

---

## 🎯 Transition to Ongoing Ops

### Readiness Checklist
- [ ] DNS service running and stable
- [ ] Local resolution working (localhost, hostname)
- [ ] External resolution working (google.com)
- [ ] Zone files validated and backed up
- [ ] Query logging enabled
- [ ] Monitoring scripts configured
- [ ] Team coordination established
- [ ] **VERIFIED**: All teams can resolve critical hostnames

### **When to Transition**
- All critical DNS tasks completed OR
- 1.5 hours elapsed (DNS is too critical to delay)
- Move to "BIND Team: Ongoing Ops" guide

---

## 🚨 Emergency Procedures

### DNS Service Down Emergency (CRITICAL - 2-minute max)
1. **Immediate Restart**:
   ```bash
   systemctl restart bind9 || systemctl restart named
   sleep 3
   systemctl status bind9 || systemctl status named
   ```

2. **Quick Test**:
   ```bash
   nslookup localhost
   dig @localhost $(hostname)
   ```

3. **If Still Failing**:
   ```bash
   named-checkconf
   tail -20 /var/log/syslog | grep named
   ```

4. **Emergency Escalation**: Inform ALL teams immediately

### DNS Resolution Failing Emergency
1. **Test External DNS**:
   ```bash
   dig @8.8.8.8 google.com
   ```

2. **Check Forwarders**:
   ```bash
   grep forwarders /etc/bind/named.conf*
   ```

3. **Temporary Fix** (if needed):
   ```bash
   # Add public DNS as forwarder temporarily
   echo "forwarders { 8.8.8.8; 1.1.1.1; };" >> /etc/bind/named.conf.options
   systemctl restart bind9 || systemctl restart named
   ```

### Configuration Corruption Emergency
1. **Restore from Backup**:
   ```bash
   cp /tmp/dns_backup/* /etc/bind/
   systemctl restart bind9 || systemctl restart named
   ```

2. **Minimal Working Config** (last resort):
   ```bash
   # Create a minimal working configuration
   # Only if absolutely necessary and coordinated with the team lead
   ```

---

*DNS is the foundation of all scoring. Your team's success directly impacts everyone else's score. When in doubt, prioritize DNS availability over everything else.*

**Remember: If DNS fails, everything fails. Your role is critical to the entire team's success.**

