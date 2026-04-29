"""
Configuration management for Network Sniffer
Handles settings, thresholds, and compliance parameters
"""

import os
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SnifferConfig:
    """Configuration settings for network sniffer"""
    
    # Network Interface Settings
    interface: str = "auto"  # "auto" for automatic detection
    promiscuous_mode: bool = True
    timeout: int = 30  # seconds
    
    # Packet Capture Settings
    max_packets: int = 1000
    packet_buffer_size: int = 65536
    store_packets: bool = False
    
    # Threat Detection Thresholds
    dns_query_threshold: int = 50  # queries per minute
    port_scan_threshold: int = 10  # ports per minute
    data_exfiltration_threshold: int = 100 * 1024 * 1024  # 100MB
    connection_threshold: int = 100  # connections per minute
    
    # Sensitive Ports (unencrypted protocols)
    sensitive_ports: List[int] = None
    sensitive_keywords: List[str] = None
    
    # Compliance Settings
    log_file: str = "network_sniffer.log"
    max_log_size: int = 100 * 1024 * 1024  # 100MB
    retain_logs_days: int = 30
    
    # Alert Settings
    enable_console_output: bool = True
    enable_file_logging: bool = True
    enable_real_time_alerts: bool = True
    
    # Privacy Settings
    mask_private_ips: bool = True
    exclude_internal_traffic: bool = False
    anonymize_data: bool = True
    
    def __post_init__(self):
        """Initialize default values"""
        if self.sensitive_ports is None:
            self.sensitive_ports = [
                21,   # FTP
                23,   # Telnet
                25,   # SMTP
                53,   # DNS
                80,   # HTTP
                110,  # POP3
                143,  # IMAP
                161,  # SNMP
                389,  # LDAP
                512,  # rexec
                513,  # rlogin
                514,  # rsh
                1433, # MSSQL
                3306, # MySQL
                3389, # RDP
                5432, # PostgreSQL
                5900, # VNC
            ]
        
        if self.sensitive_keywords is None:
            self.sensitive_keywords = [
                "password", "passwd", "pass", "secret", "key", "token",
                "credential", "auth", "login", "user", "username",
                "admin", "root", "administrator", "privilege",
                "ssn", "social", "credit", "card", "bank", "account",
                "confidential", "classified", "proprietary", "internal"
            ]

class ComplianceConfig:
    """Compliance and legal configuration"""
    
    # Legal Notice
    LEGAL_NOTICE = """
    NETWORK SNIFFER - LEGAL NOTICE
    ================================
    
    This tool is for authorized network security testing ONLY.
    
    REQUIREMENTS:
    - Only use on networks you own or have explicit written permission
    - Follow all applicable laws (GDPR, CCPA, etc.)
    - Obtain proper authorization before monitoring
    - Handle personal data according to privacy regulations
    - Maintain audit trails of all monitoring activities
    
    UNAUTHORIZED USE IS ILLEGAL AND PUNISHABLE BY LAW.
    """
    
    # Data Retention Policies
    class DataRetention:
        PACKET_DATA = 7  # days
        METADATA = 30    # days
        ALERTS = 90      # days
        ANALYTICS = 365  # days
    
    # Privacy Protection
    class PrivacyProtection:
        ANONYMIZE_IPS = True
        HASH_PAYLOADS = True
        EXCLUDE_PERSONAL_DATA = True
        MINIMIZE_DATA_COLLECTION = True
    
    # Regulatory Compliance
    REGULATORY_FRAMEWORKS = [
        "GDPR", "CCPA", "HIPAA", "PCI-DSS", "SOX",
        "NIST Cybersecurity Framework", "ISO 27001"
    ]

class NetworkConfig:
    """Network configuration and interface management"""
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255"),  # Loopback
    ]
    
    # Common ports by category
    PORT_CATEGORIES = {
        "web": [80, 443, 8080, 8443],
        "email": [25, 110, 143, 465, 587, 993, 995],
        "file_transfer": [20, 21, 22, 69, 989, 990],
        "remote_access": [22, 23, 3389, 5900],
        "database": [1433, 1521, 3306, 5432, 6379, 27017],
        "directory": [389, 636, 3268, 3269],
        "dns": [53],
        "dhcp": [67, 68],
        "snmp": [161, 162],
        "time": [123, 37],
    }
    
    @staticmethod
    def get_port_category(port: int) -> str:
        """Get category for a given port"""
        for category, ports in NetworkConfig.PORT_CATEGORIES.items():
            if port in ports:
                return category
        return "unknown"

# Global configuration instance
config = SnifferConfig()
compliance = ComplianceConfig()
network_config = NetworkConfig()
