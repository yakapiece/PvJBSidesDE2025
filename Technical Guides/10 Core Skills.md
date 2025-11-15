## 🪟 **Windows Subteam – Core Skills (Ranked)**

1. **Detect & Kill Malicious Processes**
    
    - `tasklist`, `taskkill`, `Get-Process`, `Sysmon`
        
2. **Event Log Forensics**
    
    - `EventViewer`, `Get-WinEvent`, parsing Event ID 4624, 4688, 7045
        
3. **RDP/Service Hardening**
    
    - Disable RDP, remove unneeded services (`services.msc`)
        
4. **Registry Hunting for Persistence**
    
    - `reg query`, Autoruns, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
        
5. **PowerShell Abuse Detection**
    
    - Look for `Invoke-Expression`, base64 strings, `IEX`
        
6. **Account and Group Management**
    
    - Detect new admins, rogue accounts, using `net user`, `net localgroup`
        
7. **Scheduled Task Review and Cleanup**
    
    - `schtasks /query`, `TaskSchedulerView`
        
8. **Local Firewall Rules & Ingress Blocking**
    
    - `netsh advfirewall`, GPO lockdowns
        
9. **Defender Configuration & AV Tuning**
    
    - Enable real-time protection, monitor logs
        
10. **Snapshot / Restore Familiarity**
    
    - Rollbacks and volume shadow copies (`vssadmin`, `wbadmin`)
        

---

## 🐧 ***nix Subteam – Core Skills (Ranked)**

1. **Log File Triage**
    
    - `/var/log/auth.log`, `/var/log/syslog`, `last`, `journalctl`
        
2. **Process & Service Auditing**
    
    - `ps aux`, `systemctl`, `top`, `htop`
        
3. **User and Sudoers Review**
    
    - `cat /etc/passwd`, `sudo -l`, rogue accounts
        
4. **Cronjob & rc.local Hunting**
    
    - `crontab -l`, `ls -la /etc/cron*`, `/etc/init.d`
        
5. **SSH Key & Backdoor Removal**
    
    - `.ssh/authorized_keys`, `sshd_config`, rogue keys
        
6. **File Integrity & Malware Scan**
    
    - `tripwire`, `chkrootkit`, `rkhunter`, `find / -perm -4000`
        
7. **Netstat & Suspicious Connections**
    
    - `netstat -tulnp`, `lsof -i`
        
8. **Firewall (iptables/nftables) Mastery**
    
    - Flush or enforce default-deny policies
        
9. **Script-Based Remediation**
    
    - Bash scripting to reset ownerships, clean temp dirs, kill rogue daemons
        
10. **Config Hardening**
    
    - `/etc/hosts.allow`, `/etc/ssh/sshd_config`, disable password auth
        

---

## 🌐 **Firewall/Network Subteam – Core Skills (Ranked)**

1. **Block/Allow Rules on Demand**
    
    - pfSense rule creation & testing
        
2. **VLAN Segmentation & Isolation**
    
    - Understand VLAN tagging, guest vs internal
        
3. **Traffic Monitoring**
    
    - Wireshark/tcpdump basics, Suricata alerts
        
4. **Detect Beaconing or DNS Tunneling**
    
    - Regularity of traffic, domains in Suricata logs
        
5. **Port Scan Mitigation**
    
    - Block unused ports, rate-limiting with firewall
        
6. **Zero Trust Zoning**
    
    - Restrict access between segments aggressively
        
7. **Internal DNS Poisoning Defense**
    
    - Monitor for rogue DNS, DNS sinkholes
        
8. **Proxy Configuration (if in scope)**
    
    - Create logging proxies or MITM interception
        
9. **Redundant Path Tracing**
    
    - Understand alternate routes used by red team
        
10. **Firewall Log Forensics**
    
    - Analyze blocked/allowed traffic for lateral movement
        

---

## 🌐 **BIND/DNS Subteam – Core Skills (Ranked)**

1. **Zone File Verification**
    
    - Check for injected TXT records, rogue entries
        
2. **Log Review for Query Abuse**
    
    - `/var/log/named.log`, suspicious query patterns
        
3. **Detect & Prevent DNS Tunneling**
    
    - Use `dnstop`, Suricata DNS rules
        
4. **Recursive DNS Attack Defense**
    
    - Ensure recursion is locked down to local IPs only
        
5. **Response Spoofing Defense**
    
    - Verify TTLs, wildcard entries, reverse lookups
        
6. **Access Control Hardening**
    
    - `allow-query`, `allow-transfer`, `controls` settings
        
7. **Zone Transfer Defense**
    
    - Block `AXFR` attempts unless explicitly required
        
8. **Dynamic DNS Scrutiny**
    
    - Look for injected entries via `nsupdate`
        
9. **DNSSEC Awareness**
    
    - If in scope, validate signatures; prevent DNS injection
        
10. **Automated Check Scripts**
    

- Bash or Python to diff zones, monitor TTLs, flag changes
    

---

## 🛡️ **Blue Cell / General Defense – Core Skills (Ranked)**

1. **Rapid IOC Response Coordination**
    
    - Team comms + system-wide sweeps for hashes/IPs
        
2. **Live System Monitoring Tools**
    
    - `htop`, `Sysinternals`, `ELK`, Wazuh dashboards
        
3. **Incident Response Playbook Execution**
    
    - Step-by-step IR and rollback procedures
        
4. **Automated Threat Hunting**
    
    - Scripting for IOC detection, log scraping, anomaly detection
        
5. **Log Correlation and Timeline Building**
    
    - Stitch together events across systems
        
6. **Script Deployment at Scale**
    
    - Ansible, PowerShell Remoting, or remote execution tools
        
7. **Snapshot Management**
    
    - Create/restore in Proxmox or Hypervisor
        
8. **Fake Flag Strategy**
    
    - Deploy honeypots, fake credentials, booby-trapped flags
        
9. **Collaborative Tools Setup**
    
    - Shared notetaking, IOC tracking boards (Obsidian, Notion, etc.)
        
10. **Post-Incident Reports & Lessons Learned**
    
    - Document everything, analyze failures, suggest hardening
        
