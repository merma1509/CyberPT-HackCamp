# Network Sniffer - Threat Detection System

A comprehensive, modularized network security monitoring tool designed for cybersecurity requirements. Thispacket sniffer provides real-time threat detection, compliance reporting, and educational insights into network security.

## Modular Architecture

The project is organized into focused, maintainable modules:

```
NetworkSniffer/
├── __init__.py          # Package initialization and convenience functions
├── main.py              # Main application entry point
├── requirements.txt     # Python dependencies
├── core.py              # Core packet capture and analysis engine
├── detection.py         # threat detection algorithms
├── reporting.py         # Alert management and reporting system
├── ui.py                # User interface components
├── config.py            # Configuration and compliance settings
└── README.md            # This file
```

## Features

### Core Capabilities
- **Real-time Packet Capture**: High-performance packet sniffing with Scapy
- **Threat Detection**: Multiple detection engines for various attack patterns
- **Compliance-Focused**: Built-in GDPR, CCPA, and privacy compliance features
- **Modular Design**: Clean separation of concerns for maintainability
- **Educational Value**: Comprehensive learning materials and examples

### Threat Detection Engines

#### Malware Detection
- Command & Control (C2) communication detection
- Beaconing behavior analysis
- Domain Generation Algorithm (DGA) detection
- Suspicious user agent identification

#### **Intrusion Detection**
- Brute force attack detection
- Port scanning identification
- Suspicious IP range monitoring
- Authentication attack patterns

#### **Data Leakage Detection**
- Sensitive data pattern matching (PII, credit cards, API keys)
- Large data transfer monitoring
- Unencrypted protocol detection
- Content-based anomaly detection

#### **Anomaly Detection**
- Traffic pattern analysis
- Protocol usage anomalies
- Packet size anomalies
- Behavioral baseline establishment

### Reporting & Analytics
- Real-time dashboard with live statistics
- Comprehensive security reports
- Compliance-focused reporting
- Alert management and notification system
- Export capabilities (JSON, CSV)

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (required for packet capture)
- Network interface access

### Quick Installation

```bash
# Clone or download the project
cd NetworkSniffer

# Install dependencies automatically
python main.py --install-deps

# Run the application
python main.py
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Usage

### Interactive Mode

```bash
python main.py
```

This launches the interactive console interface with:
- Real-time packet capture
- Live threat detection
- Interactive dashboard
- Report generation
- Configuration management

### Programmatic Usage

```python
from NetworkSniffer import quick_sniff, quick_analysis

# Quick packet sniffing
quick_sniff(interface="eth0", timeout=30)

# Quick threat analysis
results = quick_analysis(interface="eth0", duration=60)
print(f"Alerts generated: {results['alerts_generated']}")
```

### Usage Examples

```python
from NetworkSniffer import (
    PacketCapture, ThreatDetectionEngine, 
    AlertManager, ReportGenerator
)

# Setup components
capture = PacketCapture()
detector = ThreatDetectionEngine()
alert_manager = AlertManager()

# Define packet handler
def handle_packet(packet_info):
    alerts = detector.analyze_packet(packet_info)
    for alert in alerts:
        alert_manager.add_alert(alert)

# Start capture
capture.add_packet_handler(handle_packet)
capture.start_capture("eth0")
```

## Configuration

### Basic Configuration

The system uses a comprehensive configuration system in `config.py`:

```python
# Threat detection thresholds
config.dns_query_threshold = 50  # queries per minute
config.port_scan_threshold = 10  # ports per minute
config.data_exfiltration_threshold = 100 * 1024 * 1024  # 100MB

# Privacy settings
config.mask_private_ips = True
config.anonymize_data = True
config.exclude_internal_traffic = False

# Alert settings
config.enable_console_output = True
config.enable_file_logging = True
config.enable_real_time_alerts = True
```

### Compliance Configuration

Built-in compliance for major regulations:
- GDPR (General Data Protection Regulation)
- CCPA (California Consumer Privacy Act)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI-DSS (Payment Card Industry Data Security Standard)

## Detection Capabilities

### Malware Communication Patterns
- **C2 Detection**: Identifies communication with known command and control servers
- **Beaconing**: Detects regular, automated communication patterns
- **DGA Detection**: Identifies domain generation algorithm usage
- **User Agent Analysis**: Detects suspicious automated tools

### Intrusion Attempts
- **Brute Force**: Identifies repeated authentication attempts
- **Port Scanning**: Detects systematic port enumeration
- **IP Reputation**: Flags traffic from suspicious ranges
- **Protocol Anomalies**: Identifies unusual protocol usage

### Data Protection
- **PII Detection**: Identifies personal information in traffic
- **Credit Card Patterns**: Detects payment card information
- **API Key Leakage**: Identifies exposed authentication tokens
- **Large Transfers**: Monitors for data exfiltration

## Reports & Analytics

### Report Types

1. **Summary Report**: Quick overview of recent activity
2. **Detailed Report**: Comprehensive analysis with recommendations
3. **Compliance Report**: Regulatory compliance assessment
4. **Custom Reports**: Flexible timeframes and filters

### Dashboard Features

- Real-time alert statistics
- Threat type distribution
- Top source/destination IPs
- Recent activity timeline
- System performance metrics

## ⚖️ Legal & Compliance

### Important Legal Notice

```
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
```

### Privacy Features

- **IP Masking**: Automatic masking of private IP addresses
- **Data Anonymization**: Optional payload anonymization
- **Minimal Data Collection**: Only captures necessary data
- **Configurable Retention**: Automatic cleanup of old data
- **Audit Logging**: Complete audit trail of all activities

## Educational Value

This tool serves as an excellent educational resource for:

### Learning Topics
- **Network Protocols**: Deep understanding of TCP/IP, UDP, ICMP
- **Packet Analysis**: Hands-on experience with packet dissection
- **Threat Detection**: Understanding attack patterns and signatures
- **Security Compliance**: Learning about regulatory requirements
- **Python Programming**: Advanced Python applications in security

### Use Cases
- **Cybersecurity Education**: Classroom demonstrations and labs
- **Security Research**: Protocol analysis and threat research
- **Network Administration**: Understanding network traffic patterns
- **Compliance Auditing**: Demonstrating compliance requirements

## New Features

### Machine Learning Integration
The modular design allows for easy integration of ML models for:
- Anomaly detection
- Behavioral analysis
- Pattern recognition
- Predictive threat intelligence

### Extensibility
The modular architecture supports:
- Custom detection rules
- Additional protocol parsers
- Integration with SIEM systems
- Custom alert handlers
- Third-party threat intelligence feeds

## Limitations & Considerations

### Technical Limitations
- Requires administrator privileges for packet capture
- May impact network performance on high-traffic networks
- Encrypted traffic (HTTPS, SSH) limits content analysis
- False positives may occur in complex network environments

### Legal Considerations
- Always obtain proper authorization before monitoring
- Follow local laws and regulations
- Respect privacy and data protection requirements
- Maintain proper documentation of monitoring activities

## Development & Contributing

### Project Structure
The modular design makes it easy to:
- Add new detection engines
- Implement custom alert handlers
- Create new report types
- Integrate with external systems
- Extend protocol support

### Testing
```bash
# Run basic functionality tests
python -m pytest tests/

# Test with sample traffic
python examples.py
```

## Support & Documentation

### Getting Help
- Check the configuration in `config.py`
- Review the legal notice and compliance requirements
- Ensure proper permissions and dependencies
- Consult the examples in `examples.py`

### Common Issues
- **Permission Denied**: Run as administrator/root
- **No Interface Detected**: Check network interface names
- **Missing Dependencies**: Run `python main.py --install-deps`
- **High Resource Usage**: Adjust capture limits and thresholds

## License

This project is provided for educational and authorized security testing purposes only. Users must comply with all applicable laws and regulations.

---

**Remember**: With great power comes great responsibility. Use this tool ethically, legally, and responsibly.
