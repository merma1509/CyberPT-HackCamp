"""
Core packet capture and analysis engine
Handles the fundamental packet processing logic
"""

import time
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Scapy not installed. Install with: pip install scapy")
    exit(1)

from config import config, ThreatLevel, network_config, compliance

@dataclass
class PacketInfo:
    """Structured packet information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    payload: Optional[bytes]
    flags: List[str]
    threat_level: ThreatLevel
    raw_packet: Any

@dataclass
class ThreatAlert:
    """Threat alert information"""
    timestamp: datetime
    threat_type: str
    threat_level: ThreatLevel
    src_ip: str
    dst_ip: str
    description: str
    evidence: Dict[str, Any]
    packet_count: int = 1

class PacketCapture:
    """Core packet capture engine"""
    
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.start_time = None
        self.capture_thread = None
        self.packet_handlers: List[Callable[[PacketInfo], None]] = []
        self.captured_packets: deque = deque(maxlen=config.max_packets)
        
    def add_packet_handler(self, handler: Callable[[PacketInfo], None]):
        """Add a packet handler function"""
        self.packet_handlers.append(handler)
    
    def remove_packet_handler(self, handler: Callable[[PacketInfo], None]):
        """Remove a packet handler function"""
        if handler in self.packet_handlers:
            self.packet_handlers.remove(handler)
    
    def _process_packet(self, packet):
        """Process a single packet"""
        try:
            packet_info = self._extract_packet_info(packet)
            
            if packet_info:
                self.captured_packets.append(packet_info)
                self.packet_count += 1
                
                # Call all registered handlers
                for handler in self.packet_handlers:
                    try:
                        handler(packet_info)
                    except Exception as e:
                        print(f"Error in packet handler: {e}")
                        
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract structured information from packet"""
        try:
            timestamp = datetime.now()
            
            # Basic packet info
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            protocol = "unknown"
            size = len(packet)
            payload = None
            flags = []
            threat_level = ThreatLevel.LOW
            
            # Ethernet layer
            if packet.haslayer(Ether):
                protocol = "Ethernet"
            
            # IP layer
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Apply privacy settings
                if config.mask_private_ips:
                    src_ip = self._mask_ip(src_ip)
                    dst_ip = self._mask_ip(dst_ip)
            
            # TCP layer
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "TCP"
                flags = packet[TCP].flags
                
                # Check for sensitive ports
                if dst_port in config.sensitive_ports or src_port in config.sensitive_ports:
                    threat_level = ThreatLevel.MEDIUM
                
                # Extract payload
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    
                    # Check for sensitive keywords
                    if self._contains_sensitive_data(payload):
                        threat_level = ThreatLevel.HIGH
            
            # UDP layer
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "UDP"
                
                # Check for sensitive ports
                if dst_port in config.sensitive_ports or src_port in config.sensitive_ports:
                    threat_level = ThreatLevel.MEDIUM
                
                # DNS detection
                if dst_port == 53 or src_port == 53:
                    threat_level = ThreatLevel.LOW
                
                # Extract payload
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
            
            # ICMP layer
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            # ARP layer
            elif packet.haslayer(ARP):
                protocol = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
            
            # HTTP layer
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                protocol = "HTTP"
                threat_level = ThreatLevel.MEDIUM  # Unencrypted HTTP
                
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if self._contains_sensitive_data(payload):
                        threat_level = ThreatLevel.HIGH
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=size,
                payload=payload if not config.anonymize_data else None,
                flags=flags,
                threat_level=threat_level,
                raw_packet=packet
            )
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def _mask_ip(self, ip: str) -> str:
        """Mask IP address for privacy"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.xxx.xxx"
            return "xxx.xxx.xxx.xxx"
        except:
            return "xxx.xxx.xxx.xxx"
    
    def _contains_sensitive_data(self, payload: bytes) -> bool:
        """Check if payload contains sensitive keywords"""
        if not payload:
            return False
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            return any(keyword in payload_str for keyword in config.sensitive_keywords)
        except:
            return False
    
    def start_capture(self, interface: str = None):
        """Start packet capture"""
        if self.is_running:
            print("Capture already running")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.packet_count = 0
        
        def capture_worker():
            try:
                # Handle interface selection
                if interface == "auto" or not interface:
                    # Let Scapy auto-detect interface
                    iface = None
                    print("Using auto-detected network interface")
                else:
                    iface = interface
                    print(f"Using network interface: {iface}")
                
                print(f"Starting packet capture...")
                
                # Start sniffing with better error handling
                sniff(
                    iface=iface,
                    prn=self._process_packet,
                    store=False,
                    timeout=config.timeout if config.timeout > 0 else None,
                    stop_filter=lambda x: not self.is_running,
                    promisc=config.promiscuous_mode
                )
                
            except Exception as e:
                print(f"Error in packet capture: {e}")
                if "Permission denied" in str(e) or "Operation not permitted" in str(e):
                    print("Permission denied. Please run as administrator/root.")
                elif "Interface" in str(e) or "No such device" in str(e):
                    print(f"Network interface error: {e}")
                    print("Available interfaces can be listed with: python main.py --list-interfaces")
                else:
                    print(f"Capture error: {e}")
            finally:
                self.is_running = False
        
        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        print(f"Packet capture stopped. Captured {self.packet_count} packets.")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics"""
        duration = 0
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "is_running": self.is_running,
            "packet_count": self.packet_count,
            "duration_seconds": duration,
            "packets_per_second": self.packet_count / duration if duration > 0 else 0,
            "start_time": self.start_time,
            "buffer_size": len(self.captured_packets)
        }

class PacketAnalyzer:
    """Advanced packet analysis engine"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self.port_scan_detector = defaultdict(list)
        self.dns_tracker = defaultdict(int)
        self.data_transfer_tracker = defaultdict(int)
        self.threat_alerts: List[ThreatAlert] = []
    
    def analyze_packet(self, packet_info: PacketInfo):
        """Analyze a packet for threats"""
        self._track_connections(packet_info)
        self._detect_port_scanning(packet_info)
        self._track_dns_queries(packet_info)
        self._track_data_transfers(packet_info)
        self._detect_anomalies(packet_info)
    
    def _track_connections(self, packet_info: PacketInfo):
        """Track connection patterns"""
        if packet_info.protocol in ["TCP", "UDP"]:
            connection_key = f"{packet_info.src_ip}:{packet_info.src_port}->{packet_info.dst_ip}:{packet_info.dst_port}"
            self.connection_tracker[connection_key].append(packet_info.timestamp)
    
    def _detect_port_scanning(self, packet_info: PacketInfo):
        """Detect potential port scanning activity"""
        if packet_info.protocol == "TCP":
            current_time = packet_info.timestamp
            recent_scans = [
                t for t in self.port_scan_detector[packet_info.src_ip]
                if (current_time - t).total_seconds() < 60
            ]
            
            recent_scans.append(current_time)
            self.port_scan_detector[packet_info.src_ip] = recent_scans
            
            if len(recent_scans) > config.port_scan_threshold:
                alert = ThreatAlert(
                    timestamp=current_time,
                    threat_type="Port Scanning",
                    threat_level=ThreatLevel.HIGH,
                    src_ip=packet_info.src_ip,
                    dst_ip="multiple",
                    description=f"Potential port scanning detected from {packet_info.src_ip}",
                    evidence={"ports_scanned": len(recent_scans), "timeframe": "60 seconds"}
                )
                self.threat_alerts.append(alert)
    
    def _track_dns_queries(self, packet_info: PacketInfo):
        """Track DNS query patterns"""
        if packet_info.protocol == "UDP" and packet_info.dst_port == 53:
            current_time = packet_info.timestamp
            time_key = current_time.strftime("%Y-%m-%d %H:%M")
            self.dns_tracker[time_key] += 1
            
            if self.dns_tracker[time_key] > config.dns_query_threshold:
                alert = ThreatAlert(
                    timestamp=current_time,
                    threat_type="DNS Tunneling",
                    threat_level=ThreatLevel.MEDIUM,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    description=f"High frequency DNS queries detected",
                    evidence={"query_count": self.dns_tracker[time_key], "timeframe": "1 minute"}
                )
                self.threat_alerts.append(alert)
    
    def _track_data_transfers(self, packet_info: PacketInfo):
        """Track data transfer volumes"""
        if packet_info.size > 0:
            transfer_key = f"{packet_info.src_ip}->{packet_info.dst_ip}"
            self.data_transfer_tracker[transfer_key] += packet_info.size
            
            if self.data_transfer_tracker[transfer_key] > config.data_exfiltration_threshold:
                alert = ThreatAlert(
                    timestamp=packet_info.timestamp,
                    threat_type="Data Exfiltration",
                    threat_level=ThreatLevel.CRITICAL,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    description=f"Large data transfer detected",
                    evidence={"bytes_transferred": self.data_transfer_tracker[transfer_key]}
                )
                self.threat_alerts.append(alert)
    
    def _detect_anomalies(self, packet_info: PacketInfo):
        """Detect various anomalies"""
        # Unencrypted traffic on sensitive ports
        if packet_info.dst_port in config.sensitive_ports:
            alert = ThreatAlert(
                timestamp=packet_info.timestamp,
                threat_type="Unencrypted Protocol",
                threat_level=ThreatLevel.MEDIUM,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                description=f"Unencrypted traffic on port {packet_info.dst_port}",
                evidence={"protocol": packet_info.protocol, "port": packet_info.dst_port}
            )
            self.threat_alerts.append(alert)
    
    def get_threat_alerts(self, level: ThreatLevel = None) -> List[ThreatAlert]:
        """Get threat alerts, optionally filtered by level"""
        if level:
            return [alert for alert in self.threat_alerts if alert.threat_level == level]
        return self.threat_alerts
    
    def clear_alerts(self):
        """Clear all threat alerts"""
        self.threat_alerts.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            "total_connections": len(self.connection_tracker),
            "port_scan_attempts": sum(len(scans) for scans in self.port_scan_detector.values()),
            "dns_queries": sum(self.dns_tracker.values()),
            "data_transfers": len(self.data_transfer_tracker),
            "threat_alerts": len(self.threat_alerts),
            "alerts_by_level": {
                level.value: len([a for a in self.threat_alerts if a.threat_level == level])
                for level in ThreatLevel
            }
        }
