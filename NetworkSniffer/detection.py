"""
Threat detection engines
Implements sophisticated detection algorithms for various attack patterns
"""

import re
import hashlib
import time
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network

from core import PacketInfo, ThreatAlert
from config import config, ThreatLevel, network_config

@dataclass
class DetectionRule:
    """Base class for detection rules"""
    name: str
    description: str
    threat_level: ThreatLevel
    enabled: bool = True

class AnomalyDetector:
    """Detects anomalous network behavior"""
    
    def __init__(self):
        self.baseline_traffic = defaultdict(list)
        self.traffic_patterns = defaultdict(lambda: defaultdict(int))
        self.connection_history = deque(maxlen=1000)
        self.size_history = deque(maxlen=1000)
        
    def establish_baseline(self, packets: List[PacketInfo]):
        """Establish normal traffic baseline"""
        for packet in packets:
            hour_key = packet.timestamp.hour
            self.baseline_traffic[hour_key].append(packet.size)
            
            # Track protocol patterns
            self.traffic_patterns[packet.protocol][hour_key] += 1
    
    def detect_size_anomalies(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect unusually large or small packets"""
        hour_key = packet.timestamp.hour
        
        if hour_key in self.baseline_traffic and len(self.baseline_traffic[hour_key]) > 10:
            sizes = self.baseline_traffic[hour_key]
            mean_size = sum(sizes) / len(sizes)
            
            # Flag packets significantly larger than baseline
            if packet.size > mean_size * 5:
                return ThreatAlert(
                    timestamp=packet.timestamp,
                    threat_type="Size Anomaly",
                    threat_level=ThreatLevel.MEDIUM,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Unusually large packet: {packet.size} bytes",
                    evidence={"packet_size": packet.size, "baseline_mean": mean_size}
                )
        
        return None
    
    def detect_protocol_anomalies(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect unusual protocol usage"""
        hour_key = packet.timestamp.hour
        
        if self.traffic_patterns[packet.protocol][hour_key] == 0:
            # First time seeing this protocol at this hour
            return ThreatAlert(
                timestamp=packet.timestamp,
                threat_type="Protocol Anomaly",
                threat_level=ThreatLevel.LOW,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Unusual protocol detected: {packet.protocol}",
                evidence={"protocol": packet.protocol, "hour": hour_key}
            )
        
        return None

class MalwareDetector:
    """Detects malware communication patterns"""
    
    def __init__(self):
        self.c2_indicators = {
            # Common C2 ports
            "ports": [4444, 5555, 6667, 8080, 8443, 9999],
            # Suspicious user agents
            "user_agents": [
                r"wget.*", r"curl.*", r"python-requests.*", 
                r"powershell.*", r"cmd.*"
            ],
            # Known malicious domains patterns
            "domain_patterns": [
                r".*\.tk$", r".*\.ml$", r".*\.ga$",
                r"[a-f0-9]{32}\..*",  # Hash-based domains
                r"[a-z]{20,}\..*"     # Long random domains
            ]
        }
        
        self.beacon_patterns = defaultdict(list)
        self.dga_domains = set()
        
    def detect_c2_communication(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect command and control communication"""
        # Check for C2 ports
        if packet.dst_port in self.c2_indicators["ports"]:
            return ThreatAlert(
                timestamp=packet.timestamp,
                threat_type="C2 Communication",
                threat_level=ThreatLevel.HIGH,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Communication on suspicious C2 port {packet.dst_port}",
                evidence={"port": packet.dst_port}
            )
        
        # Check payload for C2 indicators
        if packet.payload:
            payload_str = packet.payload.decode('utf-8', errors='ignore').lower()
            
            # Check for suspicious user agents
            for pattern in self.c2_indicators["user_agents"]:
                if re.search(pattern, payload_str):
                    return ThreatAlert(
                        timestamp=packet.timestamp,
                        threat_type="Suspicious User Agent",
                        threat_level=ThreatLevel.MEDIUM,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        description="Suspicious user agent detected",
                        evidence={"user_agent": payload_str}
                    )
        
        return None
    
    def detect_beaconing(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect beaconing behavior (regular intervals)"""
        connection_key = f"{packet.src_ip}->{packet.dst_ip}"
        current_time = packet.timestamp
        
        self.beacon_patterns[connection_key].append(current_time)
        
        # Keep only recent connections
        self.beacon_patterns[connection_key] = [
            t for t in self.beacon_patterns[connection_key]
            if (current_time - t).total_seconds() < 3600  # Last hour
        ]
        
        # Check for regular intervals
        if len(self.beacon_patterns[connection_key]) >= 5:
            intervals = []
            times = sorted(self.beacon_patterns[connection_key])
            
            for i in range(1, len(times)):
                interval = (times[i] - times[i-1]).total_seconds()
                intervals.append(interval)
            
            # Check if intervals are consistent (beaconing)
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Low variance indicates regular intervals
                if variance < 10 and 30 < avg_interval < 3600:  # 30s to 1hr intervals
                    return ThreatAlert(
                        timestamp=current_time,
                        threat_type="Beaconing",
                        threat_level=ThreatLevel.HIGH,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        description="Regular beaconing behavior detected",
                        evidence={
                            "interval": avg_interval,
                            "variance": variance,
                            "connections": len(times)
                        }
                    )
        
        return None
    
    def detect_dga(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect Domain Generation Algorithm (DGA) activity"""
        if packet.payload:
            payload_str = packet.payload.decode('utf-8', errors='ignore')
            
            # Extract domain names from DNS queries
            domains = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload_str)
            
            for domain in domains:
                # Check against DGA patterns
                for pattern in self.c2_indicators["domain_patterns"]:
                    if re.match(pattern, domain.lower()):
                        return ThreatAlert(
                            timestamp=packet.timestamp,
                            threat_type="DGA Domain",
                            threat_level=ThreatLevel.HIGH,
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            description=f"Suspicious DGA domain: {domain}",
                            evidence={"domain": domain, "pattern": pattern}
                        )
        
        return None

class IntrusionDetector:
    """Detects intrusion attempts and attacks"""
    
    def __init__(self):
        self.login_attempts = defaultdict(list)
        self.failed_connections = defaultdict(int)
        self.suspicious_ips = set()
        self.blocked_ips = set()
        
    def detect_brute_force(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect brute force attacks"""
        # Check for authentication-related ports
        auth_ports = [22, 23, 3389, 5900, 1433, 3306, 5432]
        
        if packet.dst_port in auth_ports:
            current_time = packet.timestamp
            connection_key = f"{packet.src_ip}:{packet.dst_port}"
            
            self.login_attempts[connection_key].append(current_time)
            
            # Remove old attempts (last 5 minutes)
            self.login_attempts[connection_key] = [
                t for t in self.login_attempts[connection_key]
                if (current_time - t).total_seconds() < 300
            ]
            
            # Check for too many attempts
            if len(self.login_attempts[connection_key]) > 10:
                return ThreatAlert(
                    timestamp=current_time,
                    threat_type="Brute Force Attack",
                    threat_level=ThreatLevel.HIGH,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Brute force attack on port {packet.dst_port}",
                    evidence={
                        "attempts": len(self.login_attempts[connection_key]),
                        "port": packet.dst_port,
                        "timeframe": "5 minutes"
                    }
                )
        
        return None
    
    def detect_suspicious_ips(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect traffic from suspicious IP ranges"""
        try:
            src_ip = ip_address(packet.src_ip)
            
            # Check for private IP in public traffic
            if src_ip.is_private and not self._is_internal_network(packet.dst_ip):
                return ThreatAlert(
                    timestamp=packet.timestamp,
                    threat_type="Internal IP in Public Traffic",
                    threat_level=ThreatLevel.MEDIUM,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description="Private IP address in external traffic",
                    evidence={"src_ip": packet.src_ip}
                )
            
            # Check for known malicious ranges (simplified)
            # In practice, you'd use threat intelligence feeds
            suspicious_ranges = [
                ip_network("192.0.2.0/24"),     # TEST-NET-1
                ip_network("198.51.100.0/24"),  # TEST-NET-2
                ip_network("203.0.113.0/24"),   # TEST-NET-3
            ]
            
            for range_net in suspicious_ranges:
                if src_ip in range_net:
                    return ThreatAlert(
                        timestamp=packet.timestamp,
                        threat_type="Suspicious IP Range",
                        threat_level=ThreatLevel.HIGH,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        description="Traffic from suspicious IP range",
                        evidence={"ip_range": str(range_net)}
                    )
        
        except ValueError:
            pass
        
        return None
    
    def _is_internal_network(self, ip_str: str) -> bool:
        """Check if IP is in internal network"""
        try:
            ip = ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

class DataLeakageDetector:
    """Detects potential data leakage"""
    
    def __init__(self):
        self.data_patterns = {
            # Credit card patterns
            "credit_card": [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',           # MasterCard
                r'\b3[47][0-9]{13}\b',            # American Express
                r'\b3[0-9]{13}\b',                # Diners Club
                r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'  # Discover
            ],
            # Social Security Number patterns
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{3}\s\d{2}\s\d{4}\b',
                r'\b\d{9}\b'
            ],
            # Email patterns
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            # API key patterns
            "api_key": [
                r'[A-Za-z0-9]{32,}',  # Long alphanumeric strings
                r'sk-[A-Za-z0-9]{48}',  # Stripe keys
                r'AIza[0-9A-Za-z_-]{35}'  # Google API keys
            ]
        }
        
        self.outbound_data = defaultdict(int)
        
    def detect_sensitive_data(self, packet: PacketInfo) -> List[ThreatAlert]:
        """Detect sensitive data in packet payload"""
        alerts = []
        
        if not packet.payload:
            return alerts
        
        payload_str = packet.payload.decode('utf-8', errors='ignore')
        
        for data_type, patterns in self.data_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, payload_str)
                if matches:
                    alert = ThreatAlert(
                        timestamp=packet.timestamp,
                        threat_type="Sensitive Data Leakage",
                        threat_level=ThreatLevel.CRITICAL,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        description=f"Potential {data_type} data detected",
                        evidence={
                            "data_type": data_type,
                            "matches": len(matches),
                            "pattern": pattern
                        }
                    )
                    alerts.append(alert)
        
        return alerts
    
    def detect_large_transfers(self, packet: PacketInfo) -> Optional[ThreatAlert]:
        """Detect unusually large data transfers"""
        # Track outbound data
        if packet.size > 0:
            transfer_key = f"{packet.src_ip}->{packet.dst_ip}"
            self.outbound_data[transfer_key] += packet.size
            
            # Check for large transfers
            if self.outbound_data[transfer_key] > config.data_exfiltration_threshold:
                return ThreatAlert(
                    timestamp=packet.timestamp,
                    threat_type="Large Data Transfer",
                    threat_level=ThreatLevel.HIGH,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Large outbound data transfer detected",
                    evidence={
                        "bytes_transferred": self.outbound_data[transfer_key],
                        "threshold": config.data_exfiltration_threshold
                    }
                )
        
        return None

class ThreatDetectionEngine:
    """Main threat detection engine that coordinates all detectors"""
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.malware_detector = MalwareDetector()
        self.intrusion_detector = IntrusionDetector()
        self.data_leakage_detector = DataLeakageDetector()
        
        self.all_alerts: List[ThreatAlert] = []
        self.detection_rules: List[DetectionRule] = []
        
    def analyze_packet(self, packet: PacketInfo) -> List[ThreatAlert]:
        """Analyze packet with all detection engines"""
        alerts = []
        
        # Anomaly detection
        anomaly_alert = self.anomaly_detector.detect_size_anomalies(packet)
        if anomaly_alert:
            alerts.append(anomaly_alert)
        
        protocol_alert = self.anomaly_detector.detect_protocol_anomalies(packet)
        if protocol_alert:
            alerts.append(protocol_alert)
        
        # Malware detection
        c2_alert = self.malware_detector.detect_c2_communication(packet)
        if c2_alert:
            alerts.append(c2_alert)
        
        beacon_alert = self.malware_detector.detect_beaconing(packet)
        if beacon_alert:
            alerts.append(beacon_alert)
        
        dga_alert = self.malware_detector.detect_dga(packet)
        if dga_alert:
            alerts.append(dga_alert)
        
        # Intrusion detection
        brute_force_alert = self.intrusion_detector.detect_brute_force(packet)
        if brute_force_alert:
            alerts.append(brute_force_alert)
        
        ip_alert = self.intrusion_detector.detect_suspicious_ips(packet)
        if ip_alert:
            alerts.append(ip_alert)
        
        # Data leakage detection
        data_alerts = self.data_leakage_detector.detect_sensitive_data(packet)
        alerts.extend(data_alerts)
        
        transfer_alert = self.data_leakage_detector.detect_large_transfers(packet)
        if transfer_alert:
            alerts.append(transfer_alert)
        
        # Store all alerts
        self.all_alerts.extend(alerts)
        
        return alerts
    
    def get_alerts_summary(self) -> Dict[str, int]:
        """Get summary of alerts by type"""
        summary = defaultdict(int)
        for alert in self.all_alerts:
            summary[alert.threat_type] += 1
        return dict(summary)
    
    def get_high_priority_alerts(self) -> List[ThreatAlert]:
        """Get high and critical priority alerts"""
        return [
            alert for alert in self.all_alerts
            if alert.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        ]
    
    def clear_alerts(self):
        """Clear all stored alerts"""
        self.all_alerts.clear()
    
    def get_statistics(self) -> Dict[str, any]:
        """Get detection engine statistics"""
        return {
            "total_alerts": len(self.all_alerts),
            "alerts_by_level": {
                level.value: len([a for a in self.all_alerts if a.threat_level == level])
                for level in ThreatLevel
            },
            "alerts_by_type": self.get_alerts_summary(),
            "high_priority_count": len(self.get_high_priority_alerts())
        }
