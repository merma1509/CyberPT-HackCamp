"""
Network Sniffer Examples and Use Cases
Demonstrates various features and capabilities
"""

import time
import threading
from datetime import datetime, timedelta

from core import PacketCapture, PacketInfo, ThreatAlert
from detection import ThreatDetectionEngine
from reporting import AlertManager, ReportGenerator
from config import config, ThreatLevel

def basic_packet_capture_example():
    """Basic packet capture demonstration"""
    print("Basic Packet Capture Example")
    print("=" * 40)
    
    capture = PacketCapture()
    
    def packet_handler(packet_info):
        print(f"[{packet_info.timestamp.strftime('%H:%M:%S')}] "
              f"{packet_info.src_ip} -> {packet_info.dst_ip} "
              f"({packet_info.protocol}:{packet_info.dst_port}) "
              f"Size: {packet_info.size} bytes")
    
    capture.add_packet_handler(packet_handler)
    
    print("Starting packet capture for 30 seconds...")
    print("Note: This requires administrator privileges")
    
    try:
        capture.start_capture("auto")
        time.sleep(30)
        capture.stop_capture()
        
        stats = capture.get_statistics()
        print(f"\nCapture Statistics:")
        print(f"  Packets captured: {stats['packet_count']}")
        print(f"  Duration: {stats['duration_seconds']:.1f} seconds")
        print(f"  Packets/second: {stats['packets_per_second']:.1f}")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure you're running as administrator/root")

def threat_detection_example():
    """Advanced threat detection demonstration"""
    print("\nThreat Detection Example")
    print("=" * 40)
    
    capture = PacketCapture()
    detector = ThreatDetectionEngine()
    alert_manager = AlertManager()
    
    def analyze_packet(packet_info):
        # Run threat detection
        alerts = detector.analyze_packet(packet_info)
        
        # Handle alerts
        for alert in alerts:
            alert_manager.add_alert(alert)
            print(f"[{alert.threat_level.value.upper()}] {alert.threat_type}")
            print(f"   {alert.description}")
            print(f"   Source: {alert.src_ip} -> {alert.dst_ip}")
    
    capture.add_packet_handler(analyze_packet)
    
    print("Starting threat detection for 60 seconds...")
    print("Monitoring for: C2 communication, brute force, data leakage, etc.")
    
    try:
        capture.start_capture("auto")
        time.sleep(60)
        capture.stop_capture()
        
        # Display results
        stats = detector.get_statistics()
        print(f"\nThreat Detection Results:")
        print(f"  Total alerts: {stats['total_alerts']}")
        print(f"  High priority: {stats['high_priority_count']}")
        
        print(f"\nAlerts by type:")
        for threat_type, count in stats['alerts_by_type'].items():
            print(f"  {threat_type}: {count}")
        
    except Exception as e:
        print(f"Error: {e}")

def compliance_monitoring_example():
    """Compliance-focused monitoring example"""
    print("\nCompliance Monitoring Example")
    print("=" * 40)
    
    # Configure for compliance monitoring
    config.mask_private_ips = True
    config.anonymize_data = True
    config.enable_file_logging = True
    
    capture = PacketCapture()
    detector = ThreatDetectionEngine()
    alert_manager = AlertManager()
    report_generator = ReportGenerator(alert_manager, detector)
    
    def compliance_handler(packet_info):
        alerts = detector.analyze_packet(packet_info)
        for alert in alerts:
            alert_manager.add_alert(alert)
    
    capture.add_packet_handler(compliance_handler)
    
    print("Starting compliance monitoring for 45 seconds...")
    print("Focus: Unencrypted protocols, sensitive data, privacy compliance")
    
    try:
        capture.start_capture("auto")
        time.sleep(45)
        capture.stop_capture()
        
        # Generate compliance report
        report = report_generator.generate_compliance_report()
        
        print(f"\nCompliance Report Summary:")
        print(f"  Monitoring period: {report['timeframe']}")
        print(f"  Total alerts: {report['audit_trail']['total_log_entries']}")
        print(f"  Critical events: {report['audit_trail']['critical_events']}")
        print(f"  PII-related alerts: {report['data_protection']['alerts_with_potential_pii']}")
        print(f"  Unencrypted protocols: {report['data_protection']['unencrypted_protocols']}")
        
        print(f"\nPrivacy Settings:")
        print(f"  IPs masked: {report['privacy_metrics']['ips_masked']}")
        print(f"  Data anonymized: {report['privacy_metrics']['data_anonymized']}")
        print(f"  Log retention: {report['privacy_metrics']['log_retention_days']} days")
        
    except Exception as e:
        print(f"Error: {e}")

def real_time_dashboard_example():
    """Real-time dashboard example"""
    print("\nReal-time Dashboard Example")
    print("=" * 40)
    
    capture = PacketCapture()
    detector = ThreatDetectionEngine()
    alert_manager = AlertManager()
    
    # Track metrics
    metrics = {
        'start_time': datetime.now(),
        'packet_count': 0,
        'alert_count': 0,
        'threat_types': {}
    }
    
    def dashboard_handler(packet_info):
        metrics['packet_count'] += 1
        
        alerts = detector.analyze_packet(packet_info)
        for alert in alerts:
            metrics['alert_count'] += 1
            threat_type = alert.threat_type
            metrics['threat_types'][threat_type] = metrics['threat_types'].get(threat_type, 0) + 1
    
    capture.add_packet_handler(dashboard_handler)
    
    def display_dashboard():
        while capture.is_running:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            elapsed = (datetime.now() - metrics['start_time']).total_seconds()
            pps = metrics['packet_count'] / elapsed if elapsed > 0 else 0
            
            print("REAL-TIME DASHBOARD")
            print("=" * 50)
            print(f"Duration: {elapsed:.1f}s | Packets: {metrics['packet_count']} ({pps:.1f} pps)")
            print(f"Alerts: {metrics['alert_count']}")
            
            if metrics['threat_types']:
                print("\nThreat Types:")
                for threat_type, count in sorted(metrics['threat_types'].items(), 
                                               key=lambda x: x[1], reverse=True):
                    print(f"  {threat_type}: {count}")
            
            print(f"\nLast Update: {datetime.now().strftime('%H:%M:%S')}")
            print("Press Ctrl+C to stop")
            
            time.sleep(2)
    
    try:
        capture.start_capture("auto")
        
        # Start dashboard in separate thread
        dashboard_thread = threading.Thread(target=display_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Run for 60 seconds
        time.sleep(60)
        capture.stop_capture()
        
        print(f"\nFinal Statistics:")
        print(f"  Total packets: {metrics['packet_count']}")
        print(f"  Total alerts: {metrics['alert_count']}")
        print(f"  Unique threat types: {len(metrics['threat_types'])}")
        
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        capture.stop_capture()
    except Exception as e:
        print(f"Error: {e}")

def custom_detection_rules_example():
    """Custom detection rules example"""
    print("\nCustom Detection Rules Example")
    print("=" * 40)
    
    # Create custom detection logic
    class CustomDetector:
        def __init__(self):
            self.suspicious_ports = [4444, 5555, 6667, 8080, 9999]
            self.large_packet_threshold = 8000  # bytes
        
        def detect_custom_threats(self, packet_info):
            alerts = []
            
            # Custom rule 1: Suspicious ports
            if packet_info.dst_port in self.suspicious_ports:
                alert = ThreatAlert(
                    timestamp=packet_info.timestamp,
                    threat_type="Suspicious Port Activity",
                    threat_level=ThreatLevel.MEDIUM,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    description=f"Traffic on suspicious port {packet_info.dst_port}",
                    evidence={"port": packet_info.dst_port}
                )
                alerts.append(alert)
            
            # Custom rule 2: Large packets
            if packet_info.size > self.large_packet_threshold:
                alert = ThreatAlert(
                    timestamp=packet_info.timestamp,
                    threat_type="Large Packet Detected",
                    threat_level=ThreatLevel.LOW,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    description=f"Large packet: {packet_info.size} bytes",
                    evidence={"size": packet_info.size}
                )
                alerts.append(alert)
            
            return alerts
    
    capture = PacketCapture()
    custom_detector = CustomDetector()
    alert_manager = AlertManager()
    
    def custom_handler(packet_info):
        alerts = custom_detector.detect_custom_threats(packet_info)
        for alert in alerts:
            alert_manager.add_alert(alert)
            print(f"[CUSTOM] {alert.threat_type}")
            print(f"     {alert.description}")
    
    capture.add_packet_handler(custom_handler)
    
    print("Starting custom detection for 30 seconds...")
    print("Monitoring for: Suspicious ports, large packets")
    
    try:
        capture.start_capture("auto")
        time.sleep(30)
        capture.stop_capture()
        
        print(f"\nCustom Detection Results:")
        print(f"  Total custom alerts: {len(alert_manager.alerts)}")
        
    except Exception as e:
        print(f"Error: {e}")

def performance_monitoring_example():
    """Performance monitoring example"""
    print("\nPerformance Monitoring Example")
    print("=" * 40)
    
    capture = PacketCapture()
    
    # Performance metrics
    perf_metrics = {
        'start_time': None,
        'packet_times': [],
        'processing_times': [],
        'memory_usage': []
    }
    
    def performance_handler(packet_info):
        import time
        
        start_time = time.perf_counter()
        
        # Simulate some processing
        _ = packet_info.src_ip
        _ = packet_info.dst_ip
        _ = packet_info.size
        
        end_time = time.perf_counter()
        
        perf_metrics['processing_times'].append(end_time - start_time)
        perf_metrics['packet_times'].append(packet_info.timestamp)
    
    capture.add_packet_handler(performance_handler)
    
    print("Starting performance monitoring for 30 seconds...")
    
    try:
        perf_metrics['start_time'] = datetime.now()
        capture.start_capture("auto")
        time.sleep(30)
        capture.stop_capture()
        
        # Calculate performance statistics
        if perf_metrics['processing_times']:
            avg_processing = sum(perf_metrics['processing_times']) / len(perf_metrics['processing_times'])
            max_processing = max(perf_metrics['processing_times'])
            min_processing = min(perf_metrics['processing_times'])
            
            duration = (datetime.now() - perf_metrics['start_time']).total_seconds()
            pps = len(perf_metrics['packet_times']) / duration
            
            print(f"\nPerformance Statistics:")
            print(f"  Packets processed: {len(perf_metrics['packet_times'])}")
            print(f"  Processing rate: {pps:.1f} packets/second")
            print(f"  Avg processing time: {avg_processing*1000:.3f} ms")
            print(f"  Max processing time: {max_processing*1000:.3f} ms")
            print(f"  Min processing time: {min_processing*1000:.3f} ms")
        
    except Exception as e:
        print(f"Error: {e}")

def run_all_examples():
    """Run all examples with user confirmation"""
    examples = [
        ("Basic Packet Capture", basic_packet_capture_example),
        ("Threat Detection", threat_detection_example),
        ("Compliance Monitoring", compliance_monitoring_example),
        ("Real-time Dashboard", real_time_dashboard_example),
        ("Custom Detection Rules", custom_detection_rules_example),
        ("Performance Monitoring", performance_monitoring_example)
    ]
    
    print("Network Sniffer Examples")
    print("=" * 50)
    print("This will run various examples to demonstrate the sniffer's capabilities.")
    print("Note: Some examples require administrator privileges.")
    print()
    
    for name, example_func in examples:
        print(f"\n{'='*20} {name} {'='*20}")
        
        choice = input(f"Run {name} example? (y/n): ").strip().lower()
        if choice == 'y':
            try:
                example_func()
            except KeyboardInterrupt:
                print("\nExample interrupted by user")
            except Exception as e:
                print(f"Error running example: {e}")
        else:
            print("Skipping...")
        
        input("\nPress Enter to continue...")
    
    print("\nAll examples completed!")
    print("Key takeaways:")
    print("  - Modular design enables flexible usage")
    print("  - Advanced threat detection capabilities")
    print("  - Compliance-focused features")
    print("  - Real-time monitoring and reporting")
    print("  - Extensible architecture for custom rules")

if __name__ == "__main__":
    import os
    
    print("Network Sniffer Examples")
    print("=" * 30)
    print("Choose an example to run:")
    print()
    print("1. Basic Packet Capture")
    print("2. Threat Detection")
    print("3. Compliance Monitoring")
    print("4. Real-time Dashboard")
    print("5. Custom Detection Rules")
    print("6. Performance Monitoring")
    print("7. Run All Examples")
    print()
    
    choice = input("Enter your choice (1-7): ").strip()
    
    examples_map = {
        '1': ("Basic Packet Capture", basic_packet_capture_example),
        '2': ("Threat Detection", threat_detection_example),
        '3': ("Compliance Monitoring", compliance_monitoring_example),
        '4': ("Real-time Dashboard", real_time_dashboard_example),
        '5': ("Custom Detection Rules", custom_detection_rules_example),
        '6': ("Performance Monitoring", performance_monitoring_example),
        '7': ("All Examples", run_all_examples)
    }
    
    if choice in examples_map:
        name, func = examples_map[choice]
        print(f"\nRunning: {name}")
        print("=" * len(name))
        
        try:
            func()
        except KeyboardInterrupt:
            print("\nExample interrupted by user")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Invalid choice. Please run again.")
