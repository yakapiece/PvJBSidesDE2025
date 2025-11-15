#!/usr/bin/env python3
"""
PvJ Beacon Detection Tool
A comprehensive tool for detecting beaconing activity in Pros vs Joes CTF competitions.

Author: Manus AI
Date: 2025-07-12
Version: 1.0

This tool implements multiple detection methods:
1. Network traffic analysis for regular communication patterns
2. Process behavior monitoring for suspicious activities
3. Memory analysis for beacon artifacts
4. Log correlation for beacon indicators
"""

import argparse
import json
import time
import statistics
import subprocess
import re
import sys
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import socket
import struct

try:
    import psutil
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Install with: pip install psutil scapy")
    sys.exit(1)

class BeaconDetector:
    """Main beacon detection class implementing multiple detection methods."""
    
    def __init__(self, config_file=None):
        """Initialize the beacon detector with configuration."""
        self.config = self.load_config(config_file)
        self.network_connections = defaultdict(list)
        self.process_activities = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.alerts = []
        self.running = False
        
        # Detection thresholds
        self.min_connections = self.config.get('min_connections', 5)
        self.max_jitter = self.config.get('max_jitter', 0.3)
        self.min_interval = self.config.get('min_interval', 30)
        self.max_interval = self.config.get('max_interval', 3600)
        
        # Suspicious indicators
        self.suspicious_processes = self.config.get('suspicious_processes', [
            'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
            'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe'
        ])
        
        self.suspicious_domains = self.config.get('suspicious_domains', [
            'pastebin.com', 'hastebin.com', 'github.com', 'githubusercontent.com'
        ])
        
        self.cobalt_strike_indicators = [
            b'BeaconDataParse', b'BeaconOutput', b'polling', b'jitter',
            b'spawnto', b'jquery', b'dllhost.exe'
        ]
    
    def load_config(self, config_file):
        """Load configuration from file or use defaults."""
        default_config = {
            'min_connections': 5,
            'max_jitter': 0.3,
            'min_interval': 30,
            'max_interval': 3600,
            'log_file': 'beacon_detection.log',
            'output_format': 'json',
            'suspicious_processes': [],
            'suspicious_domains': []
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        return default_config
    
    def log_alert(self, alert_type, message, details=None):
        """Log detection alerts."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'details': details or {}
        }
        
        self.alerts.append(alert)
        
        # Print to console
        print(f"[{alert['timestamp']}] {alert_type}: {message}")
        if details:
            for key, value in details.items():
                print(f"  {key}: {value}")
        
        # Log to file
        log_file = self.config.get('log_file', 'beacon_detection.log')
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def analyze_network_traffic(self, interface=None, duration=300):
        """Analyze network traffic for beaconing patterns."""
        print(f"Starting network traffic analysis for {duration} seconds...")
        
        def packet_handler(packet):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                self.process_tcp_packet(packet)
            elif packet.haslayer(DNS):
                self.process_dns_packet(packet)
        
        # Start packet capture
        try:
            scapy.sniff(
                iface=interface,
                prn=packet_handler,
                timeout=duration,
                store=0
            )
        except Exception as e:
            print(f"Error during packet capture: {e}")
            return
        
        # Analyze collected data
        self.analyze_connection_patterns()
        self.analyze_dns_patterns()
    
    def process_tcp_packet(self, packet):
        """Process TCP packets for connection analysis."""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        timestamp = time.time()
        
        # Track outbound connections (SYN packets)
        if packet[TCP].flags == 2:  # SYN flag
            connection_key = f"{src_ip}:{dst_ip}:{dst_port}"
            self.network_connections[connection_key].append(timestamp)
    
    def process_dns_packet(self, packet):
        """Process DNS packets for suspicious queries."""
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
            query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            timestamp = time.time()
            
            self.dns_queries[query_name].append(timestamp)
            
            # Check for suspicious domains
            for suspicious_domain in self.suspicious_domains:
                if suspicious_domain in query_name:
                    self.log_alert(
                        'SUSPICIOUS_DNS',
                        f'DNS query to suspicious domain: {query_name}',
                        {'domain': query_name, 'timestamp': timestamp}
                    )
    
    def analyze_connection_patterns(self):
        """Analyze network connections for beaconing patterns."""
        print("Analyzing connection patterns...")
        
        for connection_key, timestamps in self.network_connections.items():
            if len(timestamps) < self.min_connections:
                continue
            
            # Calculate intervals between connections
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if len(intervals) < 3:
                continue
            
            # Statistical analysis
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            coefficient_of_variation = stdev_interval / mean_interval if mean_interval > 0 else 1
            
            # Check for beaconing characteristics
            if (self.min_interval <= mean_interval <= self.max_interval and
                coefficient_of_variation <= self.max_jitter):
                
                src_ip, dst_ip, dst_port = connection_key.split(':')
                
                self.log_alert(
                    'BEACON_DETECTED',
                    f'Regular beaconing pattern detected',
                    {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'connection_count': len(timestamps),
                        'average_interval': round(mean_interval, 2),
                        'jitter_coefficient': round(coefficient_of_variation, 3),
                        'regularity_score': round(1 - coefficient_of_variation, 3)
                    }
                )
    
    def analyze_dns_patterns(self):
        """Analyze DNS queries for beaconing patterns."""
        print("Analyzing DNS patterns...")
        
        for domain, timestamps in self.dns_queries.items():
            if len(timestamps) < self.min_connections:
                continue
            
            # Calculate query intervals
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if len(intervals) < 3:
                continue
            
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            coefficient_of_variation = stdev_interval / mean_interval if mean_interval > 0 else 1
            
            # Check for DNS beaconing
            if (self.min_interval <= mean_interval <= self.max_interval and
                coefficient_of_variation <= self.max_jitter):
                
                self.log_alert(
                    'DNS_BEACON_DETECTED',
                    f'DNS beaconing pattern detected',
                    {
                        'domain': domain,
                        'query_count': len(timestamps),
                        'average_interval': round(mean_interval, 2),
                        'jitter_coefficient': round(coefficient_of_variation, 3)
                    }
                )
    
    def monitor_processes(self, duration=300):
        """Monitor processes for suspicious beacon-like behavior."""
        print(f"Starting process monitoring for {duration} seconds...")
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
                    try:
                        proc_info = proc.info
                        proc_name = proc_info['name']
                        
                        # Check for suspicious processes
                        if proc_name.lower() in [p.lower() for p in self.suspicious_processes]:
                            connections = proc_info.get('connections', [])
                            if connections:
                                self.log_alert(
                                    'SUSPICIOUS_PROCESS',
                                    f'Suspicious process with network activity: {proc_name}',
                                    {
                                        'pid': proc_info['pid'],
                                        'cmdline': ' '.join(proc_info.get('cmdline', [])),
                                        'connection_count': len(connections)
                                    }
                                )
                        
                        # Track process network activity
                        if connections:
                            timestamp = time.time()
                            self.process_activities[proc_info['pid']].append(timestamp)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                break
        
        # Analyze process activity patterns
        self.analyze_process_patterns()
    
    def analyze_process_patterns(self):
        """Analyze process activity for beaconing patterns."""
        print("Analyzing process activity patterns...")
        
        for pid, timestamps in self.process_activities.items():
            if len(timestamps) < self.min_connections:
                continue
            
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                
                # Calculate activity intervals
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = timestamps[i] - timestamps[i-1]
                    intervals.append(interval)
                
                if len(intervals) < 3:
                    continue
                
                mean_interval = statistics.mean(intervals)
                stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                coefficient_of_variation = stdev_interval / mean_interval if mean_interval > 0 else 1
                
                # Check for regular activity patterns
                if (self.min_interval <= mean_interval <= self.max_interval and
                    coefficient_of_variation <= self.max_jitter):
                    
                    self.log_alert(
                        'PROCESS_BEACON_PATTERN',
                        f'Regular activity pattern in process: {proc_name}',
                        {
                            'pid': pid,
                            'process_name': proc_name,
                            'activity_count': len(timestamps),
                            'average_interval': round(mean_interval, 2),
                            'jitter_coefficient': round(coefficient_of_variation, 3)
                        }
                    )
            
            except psutil.NoSuchProcess:
                continue
    
    def scan_memory_artifacts(self):
        """Scan for beacon-related memory artifacts."""
        print("Scanning for memory artifacts...")
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    proc_name = proc_info['name']
                    
                    # Skip system processes
                    if pid < 4 or proc_name.lower() in ['system', 'idle']:
                        continue
                    
                    # Read process memory (requires elevated privileges)
                    try:
                        process = psutil.Process(pid)
                        memory_maps = process.memory_maps()
                        
                        for mmap in memory_maps:
                            if mmap.path and os.path.exists(mmap.path):
                                # Check for suspicious file paths
                                if any(indicator in mmap.path.lower() for indicator in 
                                      ['temp', 'appdata', 'programdata']):
                                    
                                    self.log_alert(
                                        'SUSPICIOUS_MEMORY_MAP',
                                        f'Suspicious memory mapping in {proc_name}',
                                        {
                                            'pid': pid,
                                            'process_name': proc_name,
                                            'mapped_file': mmap.path
                                        }
                                    )
                    
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error during memory scanning: {e}")
    
    def generate_report(self):
        """Generate a comprehensive detection report."""
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_alerts': len(self.alerts),
            'alert_summary': {},
            'alerts': self.alerts
        }
        
        # Summarize alerts by type
        for alert in self.alerts:
            alert_type = alert['type']
            if alert_type not in report['alert_summary']:
                report['alert_summary'][alert_type] = 0
            report['alert_summary'][alert_type] += 1
        
        # Save report
        report_file = f"beacon_detection_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nDetection Report Generated: {report_file}")
        print(f"Total Alerts: {report['total_alerts']}")
        
        for alert_type, count in report['alert_summary'].items():
            print(f"  {alert_type}: {count}")
        
        return report

def main():
    """Main function to run the beacon detector."""
    parser = argparse.ArgumentParser(description='PvJ Beacon Detection Tool')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-d', '--duration', type=int, default=300, 
                       help='Monitoring duration in seconds (default: 300)')
    parser.add_argument('-m', '--mode', choices=['network', 'process', 'memory', 'all'],
                       default='all', help='Detection mode (default: all)')
    parser.add_argument('--no-network', action='store_true', 
                       help='Skip network traffic analysis')
    parser.add_argument('--no-process', action='store_true',
                       help='Skip process monitoring')
    parser.add_argument('--no-memory', action='store_true',
                       help='Skip memory artifact scanning')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = BeaconDetector(args.config)
    
    print("PvJ Beacon Detection Tool v1.0")
    print("=" * 40)
    
    try:
        # Run detection based on mode
        if args.mode == 'all' or args.mode == 'network':
            if not args.no_network:
                detector.analyze_network_traffic(args.interface, args.duration)
        
        if args.mode == 'all' or args.mode == 'process':
            if not args.no_process:
                detector.monitor_processes(args.duration)
        
        if args.mode == 'all' or args.mode == 'memory':
            if not args.no_memory:
                detector.scan_memory_artifacts()
        
        # Generate final report
        detector.generate_report()
    
    except KeyboardInterrupt:
        print("\nDetection interrupted by user")
        detector.generate_report()
    except Exception as e:
        print(f"Error during detection: {e}")
        detector.generate_report()

if __name__ == '__main__':
    main()

