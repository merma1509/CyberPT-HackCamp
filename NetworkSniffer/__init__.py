"""
Network Sniffer - Advanced Threat Detection System
A comprehensive, modularized network security monitoring tool
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__description__ = "Advanced network threat detection and analysis system"

# Import main classes for easy access
from .core import PacketCapture, PacketAnalyzer, PacketInfo, ThreatAlert
from .detection import ThreatDetectionEngine
from .reporting import AlertManager, ReportGenerator, Dashboard
from .config import config, compliance, ThreatLevel

# Convenience functions for quick usage
def quick_sniff(interface: str = "auto", timeout: int = 30):
    """Quick packet sniffing function"""
    capture = PacketCapture()
    
    def packet_handler(packet_info):
        print(f"[{packet_info.timestamp}] {packet_info.src_ip} -> {packet_info.dst_ip} "
              f"({packet_info.protocol}:{packet_info.dst_port})")
    
    capture.add_packet_handler(packet_handler)
    capture.start_capture(interface)
    
    import time
    time.sleep(timeout)
    capture.stop_capture()

def quick_analysis(interface: str = "auto", duration: int = 60):
    """Quick threat analysis function"""
    capture = PacketCapture()
    analyzer = PacketAnalyzer()
    detector = ThreatDetectionEngine()
    alert_manager = AlertManager()
    
    def analyze_packet(packet_info):
        analyzer.analyze_packet(packet_info)
        alerts = detector.analyze_packet(packet_info)
        for alert in alerts:
            alert_manager.add_alert(alert)
    
    capture.add_packet_handler(analyze_packet)
    capture.start_capture(interface)
    
    import time
    time.sleep(duration)
    capture.stop_capture()
    
    return {
        "packets_captured": capture.packet_count,
        "alerts_generated": len(alert_manager.alerts),
        "threats_detected": detector.get_statistics()
    }

# Module information
MODULE_INFO = {
    "name": "Network Sniffer",
    "version": __version__,
    "description": __description__,
    "components": [
        "core.py - Packet capture and analysis engine",
        "detection.py - Advanced threat detection algorithms",
        "reporting.py - Alert management and reporting system",
        "ui.py - User interface components",
        "config.py - Configuration and compliance settings"
    ],
    "features": [
        "Real-time packet capture and analysis",
        "Advanced threat detection (malware, intrusion, data leakage)",
        "Comprehensive reporting and alerting",
        "Compliance-focused design (GDPR, CCPA, etc.)",
        "Modular architecture for extensibility"
    ],
    "requirements": [
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "psutil>=5.9.0",
        "python-dateutil>=2.8.2"
    ]
}
