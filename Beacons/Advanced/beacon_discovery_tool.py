#!/usr/bin/env python3
"""
Advanced Beacon Discovery Instrumentation Tool
==============================================

This tool demonstrates comprehensive beacon discovery techniques including:
- Statistical timing analysis
- Jitter pattern detection
- URL randomness analysis
- Traffic volume consistency detection
- Multi-layer correlation analysis

Author: Manus AI
Purpose: Educational demonstration of beacon discovery methods
"""

import time
import json
import statistics
import math
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import argparse
import csv

class BeaconDiscoveryEngine:
    """Advanced beacon discovery and analysis engine"""
    
    def __init__(self, detection_threshold=0.7):
        self.detection_threshold = detection_threshold
        self.traffic_sessions = defaultdict(list)
        self.timing_data = defaultdict(list)
        self.size_data = defaultdict(list)
        self.url_data = defaultdict(list)
        self.analysis_results = {}
        
    def add_traffic_event(self, src_ip, dst_ip, timestamp, size, url=None, protocol="HTTP"):
        """Add a traffic event for analysis"""
        session_key = f"{src_ip}->{dst_ip}:{protocol}"
        
        event = {
            'timestamp': timestamp,
            'size': size,
            'url': url,
            'protocol': protocol
        }
        
        self.traffic_sessions[session_key].append(event)
        
        # Calculate timing intervals
        if len(self.traffic_sessions[session_key]) > 1:
            prev_event = self.traffic_sessions[session_key][-2]
            interval = timestamp - prev_event['timestamp']
            self.timing_data[session_key].append(interval)
        
        # Store size data
        self.size_data[session_key].append(size)
        
        # Store URL data if available
        if url:
            self.url_data[session_key].append(url)
    
    def analyze_timing_patterns(self, session_key):
        """Analyze timing patterns for beacon-like behavior"""
        intervals = self.timing_data[session_key]
        
        if len(intervals) < 5:
            return {'confidence': 0, 'reason': 'Insufficient data'}
        
        # Statistical analysis
        mean_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else float('inf')
        
        # Jitter detection using uniform distribution test
        min_interval = min(intervals)
        max_interval = max(intervals)
        interval_range = max_interval - min_interval
        
        # Kolmogorov-Smirnov test approximation for uniform distribution
        sorted_intervals = sorted(intervals)
        n = len(sorted_intervals)
        
        # Calculate D statistic (maximum difference between empirical and theoretical CDF)
        d_statistic = 0
        for i, interval in enumerate(sorted_intervals):
            empirical_cdf = (i + 1) / n
            theoretical_cdf = (interval - min_interval) / interval_range if interval_range > 0 else 0
            d_statistic = max(d_statistic, abs(empirical_cdf - theoretical_cdf))
        
        # Critical value for KS test (approximation)
        critical_value = 1.36 / math.sqrt(n)  # 95% confidence level
        uniform_distribution = d_statistic < critical_value
        
        # Regularity detection
        regularity_score = 1 / (1 + coefficient_of_variation) if coefficient_of_variation != float('inf') else 0
        
        # Jitter detection score
        jitter_score = 1 if uniform_distribution else 0
        
        # Combined confidence score
        confidence = (regularity_score * 0.6) + (jitter_score * 0.4)
        
        analysis = {
            'confidence': confidence,
            'mean_interval': mean_interval,
            'std_dev': std_dev,
            'coefficient_of_variation': coefficient_of_variation,
            'uniform_distribution': uniform_distribution,
            'd_statistic': d_statistic,
            'critical_value': critical_value,
            'regularity_score': regularity_score,
            'jitter_score': jitter_score,
            'interval_count': len(intervals),
            'min_interval': min_interval,
            'max_interval': max_interval
        }
        
        return analysis
    
    def analyze_size_patterns(self, session_key):
        """Analyze packet/request size patterns"""
        sizes = self.size_data[session_key]
        
        if len(sizes) < 5:
            return {'confidence': 0, 'reason': 'Insufficient data'}
        
        # Size consistency analysis
        unique_sizes = set(sizes)
        size_consistency = 1 - (len(unique_sizes) / len(sizes))
        
        # Most common size analysis
        size_counter = Counter(sizes)
        most_common_size, most_common_count = size_counter.most_common(1)[0]
        dominant_size_ratio = most_common_count / len(sizes)
        
        # Size variance analysis
        mean_size = statistics.mean(sizes)
        size_variance = statistics.variance(sizes) if len(sizes) > 1 else 0
        size_cv = math.sqrt(size_variance) / mean_size if mean_size > 0 else float('inf')
        
        # Confidence calculation
        confidence = (size_consistency * 0.5) + (dominant_size_ratio * 0.3) + (1 / (1 + size_cv) * 0.2)
        
        analysis = {
            'confidence': confidence,
            'size_consistency': size_consistency,
            'dominant_size_ratio': dominant_size_ratio,
            'most_common_size': most_common_size,
            'unique_sizes': len(unique_sizes),
            'total_requests': len(sizes),
            'mean_size': mean_size,
            'size_variance': size_variance,
            'size_cv': size_cv
        }
        
        return analysis
    
    def analyze_url_patterns(self, session_key):
        """Analyze URL patterns for randomness indicators"""
        urls = self.url_data[session_key]
        
        if len(urls) < 5:
            return {'confidence': 0, 'reason': 'Insufficient data'}
        
        # URL uniqueness analysis
        unique_urls = set(urls)
        url_uniqueness_ratio = len(unique_urls) / len(urls)
        
        # Path segment analysis
        path_segments = []
        for url in urls:
            # Extract path from URL
            path_match = re.search(r'https?://[^/]+(/.*)', url)
            if path_match:
                path = path_match.group(1)
                segments = [seg for seg in path.split('/') if seg]
                path_segments.extend(segments)
        
        # Randomness indicators
        random_indicators = 0
        total_segments = len(path_segments)
        
        if total_segments > 0:
            # Check for high entropy strings
            for segment in path_segments:
                if len(segment) > 8:
                    # Simple entropy calculation
                    char_counts = Counter(segment.lower())
                    entropy = -sum((count/len(segment)) * math.log2(count/len(segment)) 
                                 for count in char_counts.values())
                    if entropy > 3.5:  # High entropy threshold
                        random_indicators += 1
            
            randomness_ratio = random_indicators / total_segments
        else:
            randomness_ratio = 0
        
        # High uniqueness + high randomness = likely beacon
        confidence = (url_uniqueness_ratio * 0.7) + (randomness_ratio * 0.3)
        
        analysis = {
            'confidence': confidence,
            'url_uniqueness_ratio': url_uniqueness_ratio,
            'unique_urls': len(unique_urls),
            'total_urls': len(urls),
            'random_indicators': random_indicators,
            'total_segments': total_segments,
            'randomness_ratio': randomness_ratio
        }
        
        return analysis
    
    def correlate_indicators(self, session_key):
        """Correlate multiple indicators for final beacon assessment"""
        timing_analysis = self.analyze_timing_patterns(session_key)
        size_analysis = self.analyze_size_patterns(session_key)
        url_analysis = self.analyze_url_patterns(session_key)
        
        # Weight the different analyses
        weights = {
            'timing': 0.4,
            'size': 0.3,
            'url': 0.3
        }
        
        # Calculate weighted confidence
        total_confidence = (
            timing_analysis['confidence'] * weights['timing'] +
            size_analysis['confidence'] * weights['size'] +
            url_analysis['confidence'] * weights['url']
        )
        
        # Determine beacon likelihood
        beacon_likelihood = "HIGH" if total_confidence > 0.7 else "MEDIUM" if total_confidence > 0.4 else "LOW"
        
        correlation_result = {
            'session_key': session_key,
            'total_confidence': total_confidence,
            'beacon_likelihood': beacon_likelihood,
            'timing_analysis': timing_analysis,
            'size_analysis': size_analysis,
            'url_analysis': url_analysis,
            'is_beacon': total_confidence > self.detection_threshold
        }
        
        return correlation_result
    
    def analyze_all_sessions(self):
        """Analyze all collected traffic sessions"""
        results = {}
        
        for session_key in self.traffic_sessions.keys():
            if len(self.traffic_sessions[session_key]) >= 5:  # Minimum events for analysis
                results[session_key] = self.correlate_indicators(session_key)
        
        self.analysis_results = results
        return results
    
    def generate_report(self, output_file=None):
        """Generate a comprehensive analysis report"""
        if not self.analysis_results:
            self.analyze_all_sessions()
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_sessions': len(self.traffic_sessions),
            'analyzed_sessions': len(self.analysis_results),
            'detection_threshold': self.detection_threshold,
            'beacon_detections': [],
            'summary': {
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0,
                'total_beacons': 0
            }
        }
        
        for session_key, analysis in self.analysis_results.items():
            if analysis['beacon_likelihood'] == 'HIGH':
                report['summary']['high_confidence'] += 1
            elif analysis['beacon_likelihood'] == 'MEDIUM':
                report['summary']['medium_confidence'] += 1
            else:
                report['summary']['low_confidence'] += 1
            
            if analysis['is_beacon']:
                report['summary']['total_beacons'] += 1
                report['beacon_detections'].append(analysis)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        return report
    
    def print_summary(self):
        """Print a summary of detection results"""
        if not self.analysis_results:
            self.analyze_all_sessions()
        
        print("=== Beacon Discovery Analysis Summary ===")
        print(f"Total sessions analyzed: {len(self.analysis_results)}")
        print(f"Detection threshold: {self.detection_threshold}")
        print()
        
        beacon_count = 0
        for session_key, analysis in self.analysis_results.items():
            confidence = analysis['total_confidence']
            likelihood = analysis['beacon_likelihood']
            is_beacon = analysis['is_beacon']
            
            if is_beacon:
                beacon_count += 1
            
            print(f"Session: {session_key}")
            print(f"  Confidence: {confidence:.3f}")
            print(f"  Likelihood: {likelihood}")
            print(f"  Beacon: {'YES' if is_beacon else 'NO'}")
            print(f"  Timing confidence: {analysis['timing_analysis']['confidence']:.3f}")
            print(f"  Size confidence: {analysis['size_analysis']['confidence']:.3f}")
            print(f"  URL confidence: {analysis['url_analysis']['confidence']:.3f}")
            print()
        
        print(f"Total beacons detected: {beacon_count}")

def simulate_beacon_traffic(discovery_engine, beacon_type="regular"):
    """Simulate different types of beacon traffic for testing"""
    base_time = time.time()
    
    if beacon_type == "regular":
        # Regular beacon without jitter
        for i in range(20):
            timestamp = base_time + (i * 60)  # Every 60 seconds
            discovery_engine.add_traffic_event(
                "192.168.1.100", "203.0.113.10", 
                timestamp, 89, 
                f"https://example.com/api/status"
            )
    
    elif beacon_type == "jittered":
        # Beacon with jitter
        import random
        for i in range(20):
            jitter = random.uniform(-12, 12)  # 20% jitter on 60s interval
            timestamp = base_time + (i * 60) + jitter
            discovery_engine.add_traffic_event(
                "192.168.1.101", "203.0.113.11", 
                timestamp, 89, 
                f"https://cdn.example.com/assets/js/app.js?v={random.randint(1000,9999)}"
            )
    
    elif beacon_type == "random_urls":
        # Beacon with highly random URLs
        import random
        import string
        for i in range(20):
            timestamp = base_time + (i * 45)
            random_path = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            discovery_engine.add_traffic_event(
                "192.168.1.102", "203.0.113.12", 
                timestamp, random.randint(80, 95), 
                f"https://api.example.com/{random_path}"
            )

def main():
    parser = argparse.ArgumentParser(description='Beacon Discovery Instrumentation Tool')
    parser.add_argument('--mode', choices=['simulate', 'analyze'], default='simulate',
                       help='Mode: simulate traffic or analyze from file')
    parser.add_argument('--threshold', type=float, default=0.7,
                       help='Detection threshold (0.0-1.0)')
    parser.add_argument('--output', help='Output file for analysis report')
    parser.add_argument('--input', help='Input CSV file with traffic data')
    
    args = parser.parse_args()
    
    discovery_engine = BeaconDiscoveryEngine(detection_threshold=args.threshold)
    
    if args.mode == 'simulate':
        print("Simulating different types of beacon traffic...")
        
        # Simulate different beacon types
        simulate_beacon_traffic(discovery_engine, "regular")
        simulate_beacon_traffic(discovery_engine, "jittered") 
        simulate_beacon_traffic(discovery_engine, "random_urls")
        
        # Add some normal traffic
        base_time = time.time()
        normal_intervals = [5, 15, 30, 120, 300, 45, 90, 180]
        for i, interval in enumerate(normal_intervals):
            timestamp = base_time + sum(normal_intervals[:i+1])
            discovery_engine.add_traffic_event(
                "192.168.1.200", "203.0.113.20",
                timestamp, random.randint(500, 5000),
                f"https://www.google.com/search?q=query{i}"
            )
        
        print("Analysis complete!")
        discovery_engine.print_summary()
        
        if args.output:
            report = discovery_engine.generate_report(args.output)
            print(f"Report saved to: {args.output}")
    
    elif args.mode == 'analyze':
        if not args.input:
            print("Error: Input file required for analysis mode")
            return
        
        # Load traffic data from CSV
        try:
            with open(args.input, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    discovery_engine.add_traffic_event(
                        row['src_ip'], row['dst_ip'],
                        float(row['timestamp']), int(row['size']),
                        row.get('url'), row.get('protocol', 'HTTP')
                    )
            
            discovery_engine.print_summary()
            
            if args.output:
                report = discovery_engine.generate_report(args.output)
                print(f"Report saved to: {args.output}")
                
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found")
        except Exception as e:
            print(f"Error processing input file: {e}")

if __name__ == "__main__":
    main()

