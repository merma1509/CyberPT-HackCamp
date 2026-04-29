# Scripts Directory - Nmap Lab Automation Tools

This directory contains Python and Bash scripts for automating and analyzing your Nmap lab results.

## Available Scripts

### 1. nmap_parser.py

**Purpose**: Parse Nmap XML results and convert to structured data

**Features**:

- Parse Nmap XML output
- Extract host, port, service information
- Export to CSV and JSON formats
- Generate scan summaries

**Usage**:

```bash
# Basic parsing with summary
python3 nmap_parser.py scan_results.xml --summary

# Export to CSV
python3 nmap_parser.py scan_results.xml --csv -o results

# Export to JSON
python3 nmap_parser.py scan_results.xml --json -o results

# Combined export
python3 nmap_parser.py scan_results.xml --csv --json --summary -o analysis
```

**Output**:

- CSV file with port/service details
- JSON file with complete scan data
- Console summary with statistics

### 2. scan_automation.sh

**Purpose**: Automated reconnaissance pipeline

**Features**:

- Complete 5-step scanning process
- Host discovery → Port scanning → Service detection → Vulnerability scanning
- Automatic report generation
- Error handling and logging
- Timestamped output directories

**Usage**:

```bash
# Make executable
chmod +x scan_automation.sh

# Run full pipeline (requires sudo)
sudo ./scan_automation.sh

# Custom network
sudo ./scan_automation.sh -n 192.168.1.0/24

# Custom output directory
sudo ./scan_automation.sh -o /tmp/my_scan

# Help
./scan_automation.sh --help
```

**Process**:

1. **Host Discovery**: ARP-based network scanning
2. **Port Scanning**: Full TCP SYN scan
3. **Service Detection**: Version and OS detection
4. **Vulnerability Scanning**: NSE script scanning
5. **Analysis**: Result processing and reporting

**Output**:

- `scan_YYYYMMDD_HHMMSS/` directory with:
  - host_discovery.gnmap
  - port_scan.xml
  - service_detection.xml
  - vulnerability_scan.xml
  - scan_report.html
  - scan_results.csv
  - scan_summary.txt

### 3. network_visualizer.py

**Purpose**: Create network visualizations from scan results

**Features**:

- Network topology graphs
- Service breakdown charts
- Host detail views
- Risk-based color coding
- Multiple output formats

**Usage**:

```bash
# Generate topology view
python3 network_visualizer.py scan_results.csv --topology -o network

# Generate service breakdown
python3 network_visualizer.py scan_results.csv --breakdown -o services

# Generate host details
python3 network_visualizer.py scan_results.csv --hosts -o hosts

# Generate complete report
python3 network_visualizer.py scan_results.json --report -o analysis
```

**Visualizations**:

- **Topology**: Network graph with hosts and services
- **Breakdown**: Pie and bar charts of service categories
- **Details**: Host-specific service listings
- **Statistics**: Network metrics and counts

**Service Categories**:

- Web (HTTP, HTTPS, Apache, Tomcat)
- Database (MySQL, PostgreSQL, Oracle)
- Remote Access (SSH, Telnet, VNC, FTP)
- File Transfer (FTP, SMB, NFS)
- Mail (SMTP, POP3, IMAP)
- Development (Java RMI, RPC)
- System (NetBIOS, LDAP, DNS)

### 4. vulnerability_checker.py

**Purpose**: Security vulnerability assessment

**Features**:

- Cross-reference services/versions with CVE database
- Risk scoring and prioritization
- Automated recommendations
- Detailed vulnerability reports

**Usage**:

```bash
# Analyze scan results
python3 vulnerability_checker.py scan_results.json -o vuln_report.txt

# Help
python3 vulnerability_checker.py --help
```

**Vulnerability Database**:

- VSFTPD 2.3.4 (CVE-2011-2523)
- OpenSSH 4.7 (CVE-2008-5161)
- Apache 2.2.8 (CVE-2009-1195)
- MySQL 5.0.51a (CVE-2008-4098)
- Samba 3.0.20 (CVE-2007-6015)
- And more...

**Risk Assessment**:

- **Critical**: Score 10 (Immediate action required)
- **High**: Score 7 (Urgent remediation)
- **Medium**: Score 4 (Plan remediation)
- **Low**: Score 1 (Monitor and plan)

## Workflow Integration

### Complete Automated Pipeline

```bash
# Step 1: Run automated scan
sudo ./scan_automation.sh -n 192.168.56.0/24

# Step 2: Parse results
python3 nmap_parser.py scan_results/service_detection.xml --csv --json -o analysis

# Step 3: Generate visualizations
python3 network_visualizer.py analysis_scan_results.csv --report -o network_analysis

# Step 4: Check vulnerabilities
python3 vulnerability_checker.py analysis_scan_results.json -o security_assessment.txt
```

### Example Output Structure

```bash
scan_results/
├── scan_20240327_143022/
│   ├── host_discovery.gnmap
│   ├── port_scan.xml
│   ├── service_detection.xml
│   ├── vulnerability_scan.xml
│   ├── scan_report.html
│   ├── scan_results.csv
│   └── scan_summary.txt
├── analysis_scan_results.csv
├── analysis_scan_results.json
├── network_analysis_topology_20240327_143105.png
├── network_analysis_breakdown_20240327_143105.png
├── network_analysis_hosts_20240327_143105.png
├── network_analysis_stats_20240327_143105.txt
└── security_assessment.txt
```

## Dependencies

### Required Tools

- **nmap**: Network scanning
- **python3**: Script execution
- **bash**: Shell scripting
- **matplotlib**: Python visualization
- **networkx**: Network graphs
- **xsltproc**: HTML report generation (optional)

### Python Packages

Install required Python packages:
```bash
pip3 install matplotlib networkx
```

### Permissions

- **scan_automation.sh**: Requires root privileges for Nmap
- **Python scripts**: Standard user permissions
- **Output files**: Write permissions in output directory

## Customization

### Adding New Vulnerabilities

Edit `vulnerability_checker.py`:

```python
self.vuln_db['service_name'] = {
    'product_name': {
        'version': {
            'cve': 'CVE-XXXX-XXXX',
            'severity': 'HIGH',
            'description': 'Vulnerability description',
            'exploit_available': True
        }
    }
}
```

### Extending Service Categories

Edit `network_visualizer.py`:

```python
self.colors['new_category'] = '#FF5733'
service_categories['new_category'] = ['service1', 'service2']
```

### Custom Scan Profiles

Modify `scan_automation.sh`:

```bash
# Add new scan types
run_nmap "Custom Scan" "$target" "$output" "-sS -p 80,443,8080"
```

## Best Practices

### Security Considerations

- Only scan networks you own or have permission to test
- Use isolated lab environments
- Store results securely
- Follow responsible disclosure

### Performance Tips

- Use appropriate timing templates (-T0 to -T5)
- Limit concurrent scans to avoid network congestion
- Regularly update vulnerability databases

### Data Management

- Use timestamped output directories
- Compress old scan results
- Maintain scan history for trend analysis
- Export results in multiple formats

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with sudo for Nmap operations
2. **Missing Dependencies**: Install required Python packages
3. **XML Parse Errors**: Ensure valid Nmap XML output
4. **No Output**: Check file permissions and disk space

### Debug Mode

Enable verbose output:

```bash
# Bash script debug
bash -x ./scan_automation.sh

# Python script debug
python3 -v network_visualizer.py scan_results.csv --topology
```

This script suite provides a complete toolkit for Nmap-based network reconnaissance, analysis, and visualization in your cyber security lab.
