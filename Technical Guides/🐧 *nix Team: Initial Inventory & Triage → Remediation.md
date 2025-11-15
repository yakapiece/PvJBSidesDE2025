# 🐧 *nix Team: Initial Inventory & Triage → Remediation

*Task-based guide for *nix subteam - Complete these tasks before moving to ongoing operations*

---

## 🚨 V2 Safety Protocols - READ FIRST

### Critical Rules for *nix Team
- **DNS Dependency**: If DNS fails, ALL *nix services score ZERO points
- **Change Testing**: Test ALL changes on least critical system first
- **Service Priority**: 80% effort on service restoration, 15% understanding, 5% evidence
- **No Snapshots**: Reverts cost points and take time - avoid breaking changes
- **Team Coordination**: Share service-affecting findings immediately

---
## Core Task ##

Baseline
-Pull current processes 
-Pull current services
-Pull current network connections
-ID core scored services
## 📋 Task 1: Immediate System Assessment (15 minutes max)

### Baseline Documentation
```bash
# Document current state
ps aux > /tmp/baseline_processes.txt
systemctl list-units --type=service --state=running > /tmp/baseline_services.txt
netstat -tulpn > /tmp/baseline_connections.txt
cat /etc/passwd > /tmp/baseline_users.txt
who > /tmp/baseline_logged_in.txt
```

### Critical Service Status Check
```bash
# Check scoring-critical services
CRITICAL_SERVICES="ssh apache2 nginx mysql postgresql bind9 dhcp-server nfs-server samba"
for service in $CRITICAL_SERVICES; do
    systemctl is-active $service 2>/dev/null && echo "$service: RUNNING" || echo "$service: NOT RUNNING"
done

# Check listening ports
ss -tulpn | grep -E ":22|:80|:443|:53|:3306|:5432|:139|:445"
```

### Immediate Threat Detection (5 minutes only)
```bash
# Quick process check for obvious threats
ps aux | grep -E "nc|netcat|ncat|socat|python|perl|ruby" | grep -v grep

# Check for suspicious network connections
netstat -an | grep ESTABLISHED | grep -E ":4444|:8080|:1234|:31337"

# Recent login attempts
last -n 20
lastb -n 10  # Failed login attempts

# Check for new files in /tmp and /var/tmp
find /tmp /var/tmp -type f -mtime -1 -ls 2>/dev/null | head -20
```

**⏰ Time Limit**: Stop investigation after 15 minutes total - move to service restoration

---

## 📋 Task 2: DNS Health Verification (Critical - Work with BIND Team)

### DNS Service Status
```bash
# Check DNS service (varies by distribution)
systemctl status bind9 || systemctl status named || systemctl status dnsmasq

# Test DNS resolution
nslookup localhost
nslookup $(hostname)
dig @localhost $(hostname)

# Check DNS configuration
cat /etc/resolv.conf
cat /etc/hosts | head -10
```

### **🤝 Coordinate with BIND Team**: Share DNS server status and any resolution issues

### DNS Client Configuration
```bash
# Check systemd-resolved (if applicable)
systemctl status systemd-resolved
resolvectl status

# Test external DNS resolution
nslookup google.com
dig @8.8.8.8 google.com
```

**🚨 Critical**: If DNS issues found, escalate to BIND team immediately - this affects ALL scoring

---

## 📋 Task 3: Account Security Lockdown

### User Account Audit
```bash
# Check for new/suspicious accounts
awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd
grep -E ":0:|:1000:" /etc/passwd

# Check for accounts with no password
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || echo "Cannot read shadow file"

# Check sudo access
grep -E "sudo|wheel" /etc/group
cat /etc/sudoers.d/* 2>/dev/null | grep -v "^#"

# Recent login activity
last -n 50 | head -20
```

### Disable Risky Accounts (Test First!)
```bash
# Document before changes
cp /etc/passwd /tmp/passwd_backup
cp /etc/shadow /tmp/shadow_backup 2>/dev/null

# Lock suspicious accounts (VERIFY FIRST - don't break scoring!)
# usermod -L suspicious_user
# passwd -l suspicious_user

# Change default passwords for critical accounts
# passwd root
# passwd [service_account]
```

### **🤝 Coordinate with Windows Team**: Share suspicious account names and patterns

---

## 📋 Task 4: Service Restoration Priority

### Critical Service Recovery
```bash
# Restart failed critical services
CRITICAL_SERVICES="ssh apache2 nginx mysql postgresql bind9 dhcp-server"
for service in $CRITICAL_SERVICES; do
    if ! systemctl is-active $service >/dev/null 2>&1; then
        echo "Restarting $service"
        systemctl restart $service
        sleep 3
        systemctl status $service --no-pager -l
    fi
done

# Check service startup configuration
for service in $CRITICAL_SERVICES; do
    systemctl is-enabled $service 2>/dev/null || echo "$service: not enabled"
done
```

### Service Configuration Verification
```bash
# Verify critical service configs (quick syntax check)
# Apache/Nginx
apache2ctl configtest 2>/dev/null || nginx -t 2>/dev/null

# SSH configuration
sshd -t 2>/dev/null && echo "SSH config OK" || echo "SSH config ERROR"

# MySQL/PostgreSQL (if running)
systemctl is-active mysql >/dev/null && mysqladmin ping 2>/dev/null
systemctl is-active postgresql >/dev/null && sudo -u postgres psql -c "SELECT 1;" >/dev/null 2>&1
```

---

## 📋 Task 5: Network Security Assessment

### SSH Security (Work with Firewall Team)
```bash
# Check SSH configuration
grep -E "PermitRootLogin|PasswordAuthentication|Port|AllowUsers|DenyUsers" /etc/ssh/sshd_config | grep -v "^#"

# Check SSH keys
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys 2>/dev/null | wc -l

# Active SSH sessions
who | grep pts
ss -t state established '( dport = :22 or sport = :22 )'
```

### **🤝 Coordinate with Firewall Team**: Share SSH port and access requirements for monitoring

### File Sharing Security
```bash
# Check Samba configuration
systemctl is-active smbd >/dev/null && smbstatus 2>/dev/null
testparm -s 2>/dev/null | head -20

# Check NFS exports
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# Check FTP services
systemctl is-active vsftpd >/dev/null || systemctl is-active proftpd >/dev/null
```

---

## 📋 Task 6: Firewall Configuration

### Firewall Status Check
```bash
# Check iptables/ufw/firewalld
iptables -L -n | head -20
ufw status verbose 2>/dev/null
firewall-cmd --list-all 2>/dev/null

# Check for active firewall rules
iptables -L INPUT -n --line-numbers
iptables -L OUTPUT -n --line-numbers
```

### **🚨 V2 Safety**: Firewall for Monitoring Only
```bash
# Enable logging for monitoring (DO NOT BLOCK SCORED SERVICES)
# iptables -A INPUT -j LOG --log-prefix "INPUT: " --log-level 4
# iptables -A OUTPUT -j LOG --log-prefix "OUTPUT: " --log-level 4

# Check that scored services are NOT blocked
iptables -L | grep -i drop
iptables -L | grep -i reject
```

**🚨 Critical**: Ensure no firewall rules block scored services - coordinate with Firewall team

---

## 📋 Task 7: Log Configuration & Analysis

### Enable Enhanced Logging
```bash
# Check rsyslog/journald configuration
systemctl status rsyslog || systemctl status systemd-journald
ls -la /var/log/

# Enable auth logging if not already
grep -E "auth|authpriv" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null

# Check log rotation
cat /etc/logrotate.conf | grep -E "weekly|daily|size"
```

### Critical Log Analysis (10 minutes max)
```bash
# Failed login attempts (last 2 hours)
grep "Failed password" /var/log/auth.log | tail -20 2>/dev/null
journalctl -u ssh --since "2 hours ago" | grep -i failed | tail -10

# Successful logins (last hour)
grep "Accepted password" /var/log/auth.log | tail -10 2>/dev/null
last -n 20 | head -10

# Service start/stop events
journalctl --since "2 hours ago" | grep -E "Started|Stopped|Failed" | tail -20
```

**⏰ Time Limit**: 10 minutes maximum for log analysis - focus on service restoration

---

## 📋 Task 8: Persistence Mechanism Check

### Startup Services and Scripts
```bash
# Check systemd services
systemctl list-unit-files --type=service | grep enabled | grep -v "@"

# Check init scripts (SysV)
ls -la /etc/init.d/ | grep -v "^total"
chkconfig --list 2>/dev/null | head -20

# Check cron jobs
crontab -l 2>/dev/null
ls -la /etc/cron.* 2>/dev/null
cat /etc/crontab
```

### Common Persistence Locations
```bash
# Check startup scripts
ls -la /etc/rc.local /etc/rc.d/rc.local 2>/dev/null
cat /etc/rc.local 2>/dev/null | grep -v "^#"

# Check profile scripts
ls -la /etc/profile.d/
cat ~/.bashrc ~/.bash_profile 2>/dev/null | grep -v "^#" | tail -10

# Check for suspicious files
find /etc -name "*.sh" -type f -mtime -1 2>/dev/null
find /usr/local/bin /usr/local/sbin -type f -mtime -1 2>/dev/null
```

**⏰ Time Limit**: 10 minutes maximum - document findings, don't deep-dive

---

## 📋 Task 9: Service-Specific Hardening

### Web Server Security (if applicable)
```bash
# Apache configuration
if systemctl is-active apache2 >/dev/null; then
    apache2ctl -S  # Show virtual hosts
    ls -la /etc/apache2/sites-enabled/
    grep -E "ServerTokens|ServerSignature" /etc/apache2/conf-available/* 2>/dev/null
fi

# Nginx configuration
if systemctl is-active nginx >/dev/null; then
    nginx -T 2>/dev/null | grep -E "server_name|listen|root" | head -10
    ls -la /etc/nginx/sites-enabled/
fi
```

### Database Security (if applicable)
```bash
# MySQL security
if systemctl is-active mysql >/dev/null; then
    mysql -e "SELECT User, Host FROM mysql.user;" 2>/dev/null | head -10
    mysql -e "SHOW DATABASES;" 2>/dev/null
fi

# PostgreSQL security
if systemctl is-active postgresql >/dev/null; then
    sudo -u postgres psql -c "\\du" 2>/dev/null
    sudo -u postgres psql -c "\\l" 2>/dev/null
fi
```

---

## 📋 Task 10: Documentation & Handoff Preparation

### Change Documentation
```bash
# Document all changes made
cat > /tmp/nix_changes.txt << EOF
*nix Team Change Log - $(date)
=====================================
Services Restarted: [List services]
Accounts Modified: [List accounts]
Firewall Changes: [List changes]
Configuration Changes: [List changes]
Issues Found: [List issues]
Coordination Needed: [List items for other teams]
EOF
```

### **🤝 Cross-Team Coordination Summary**
- **BIND Team**: DNS server status, resolution issues
- **Firewall Team**: SSH ports, web traffic, service ports
- **Windows Team**: Suspicious account patterns, cross-platform threats
- **All Teams**: Service status affecting scoring

### Status Report Template
```
*NIX TEAM STATUS - [TIME]
=========================
Critical Services: [GREEN/YELLOW/RED]
DNS Resolution: [WORKING/ISSUES]
Security Issues: [COUNT] found, [COUNT] resolved
Immediate Needs: [List urgent items]
Next Phase: Ready for Ongoing Ops / Need [X] more time
```

---

## 🎯 Transition to Ongoing Ops

### Readiness Checklist
- [ ] All critical services running and verified
- [ ] DNS resolution working (confirmed with BIND team)
- [ ] Immediate security threats contained
- [ ] Account security baseline established
- [ ] Logging and monitoring configured
- [ ] Change documentation completed
- [ ] Cross-team coordination items communicated

### **When to Transition**
- All critical tasks completed OR
- 2 hours elapsed (whichever comes first)
- Move to "*nix Team: Ongoing Ops" guide

---

## 🚨 Emergency Procedures

### Service Down Emergency
1. **Check DNS first** (coordinate with BIND team)
2. **Restart service**: `systemctl restart [service]`
3. **Check status**: `systemctl status [service] --no-pager -l`
4. **Check logs**: `journalctl -u [service] --since "10 minutes ago"`
5. **Escalate if needed**: Inform team lead within 10 minutes

### System Lockout Emergency
1. **Don't panic** - document what was changed
2. **Try console access** or alternate SSH session
3. **Contact team lead** immediately
4. **Consider marketplace revert** (costs points but may be faster)
5. **Document lessons learned** for team

### Common Emergency Commands
```bash
# Service management
systemctl status [service]
systemctl restart [service]
systemctl enable [service]
journalctl -u [service] -f

# Process management
ps aux | grep [process]
pkill [process]
kill -9 [PID]

# Network troubleshooting
ss -tulpn | grep [port]
netstat -tulpn | grep [port]
telnet [host] [port]

# File system issues
df -h
mount | grep -E "ext|xfs|btrfs"
lsof | grep [file]
```

---

*Focus on service restoration over perfect security. When in doubt, communicate with your team and prioritize scoring services.*

**Remember: Simple solutions often work better than complex ones in PvJ environment.**

