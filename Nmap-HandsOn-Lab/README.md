# Nmap Hands-On Lab - Complete Documentation

**From Zero Environment to Data Engineering Pipeline**

## Lab Overview

This lab builds a controlled reconnaissance platform that:

- Emulates real infrastructure (servers, web apps, IoT nodes)
- Enables repeatable scanning experiments
- Produces structured data outputs for downstream pipelines
- Supports both offensive (red) and defensive (blue) workflows

---

## STEP 1 — Hypervisor + Virtual Network Setup

### Objective

Install VirtualBox and create an isolated Layer-2 network for safe offensive testing.

### Commands Used

```powershell
# Verify VirtualBox installation
VBoxManage --version

# Check network configuration (Windows)
ipconfig /all

# Test connectivity (initial - showed misconfiguration)
ping 192.168.56.1

# After fix - correct connectivity test
ping 192.168.56.1
```

### Network Configuration

- **VirtualBox Host-Only Network**: vboxnet0
- **IP Range**: 192.168.56.0/24
- **Host IP**: 192.168.56.1
- **DHCP Range**: 192.168.56.100 - 192.168.56.200

### Errors Encountered & Fixes

#### Error 1: Incorrect IP Assignment

**Problem**: Host adapter assigned 192.168.56.0 (network address, not valid host IP)

```bash
IPv4 Address: 192.168.56.0 (Preferred)  # WRONG
```

**Root Cause**: VirtualBox Network Manager misconfigured

**Fix Applied**:

1. Open VirtualBox → File → Tools → Network Manager
2. Select vboxnet0
3. Set IPv4 Address: 192.168.56.1
4. Enable DHCP with proper range

#### Error 2: Misleading Ping Response

**Problem**:

```bash
ping 192.168.56.0  # SUCCESS (but misleading)
ping 192.168.56.1  # FAILED
```

**Root Cause**: Windows responds to .0 address locally (loopback behavior)

**Fix**: Corrected IP assignment, then ping worked properly

#### Error 3: PowerShell Adapter Name Mismatch

**Commands Failed**:

```powershell
Disable-NetAdapter -Name "VirtualBox Host-Only Ethernet Adapter"  # FAILED
```

**Root Cause**: Actual adapter name was "Ethernet", not full description

**Fix**: Use `Get-NetAdapter` to find correct name

### Key Learning Points

- Network addresses (.0) are not valid host IPs
- First usable IP in /24 network is .1
- VirtualBox creates Layer-2 broadcast domain
- Host-only adapter enables isolated lab environment

---

## STEP 2 — Kali Linux VM Setup (Attacker Node)

### Objective

Deploy attacker machine and learn how Nmap interfaces with OS networking stack.

### VM Specifications

- **RAM**: 4 GB minimum
- **CPU**: 2 cores
- **Network**: Host-only Adapter (vboxnet0)
- **Source**: Kali Linux VirtualBox OVA image

### Commands Used

```bash
# Verify network interface
ip a

# Test connectivity to host
ping 192.168.56.1

# First network scan (host discovery)
nmap -sn 192.168.56.0/24

# Privileged vs non-privileged comparison
whoami
sudo nmap -sn 192.168.56.0/24

# Install packet capture tool
sudo apt install tcpdump

# Monitor ARP traffic
sudo tcpdump -i eth0 arp
```

### Network Validation

Expected Kali IP: 192.168.56.X (e.g., 192.168.56.101)

### Key Learning Points

- Nmap automatically chooses ARP scan for local networks
- Root privileges required for SYN scans (-sS)
- ARP discovery is 100% accurate on local LAN
- tcpdump shows actual packet-level reconnaissance

---

## STEP 3 — Target Deployment (Metasploitable 2)

### Objective

Add vulnerable target system to create attacker-victim network.

### Download & Import Issues

#### Error 1: VMware Format Incompatibility

**Problem**: Downloaded VMware files, not VirtualBox OVA

```bash
Files present:
- Metasploitable.vmdk (virtual disk)
- Metasploitable.vmx (VMware config)
- Metasploitable.nvram, .vmsd, .vmxf (VMware metadata)
```

**Fix Applied**: Manual VM creation with disk attachment

#### Error 2: VMDK Import Failure

**Problem**: VirtualBox couldn't directly attach .vmdk

**Multiple Fix Attempts**:

**Attempt A - Direct Attachment**:

1. Create VM without disk
2. Settings → Storage → Add Hard Disk → Choose existing
3. Select Metasploitable.vmdk
4. Change controller to IDE (Metasploitable expects IDE)

**Attempt B - Disk Conversion** (Recommended):

```powershell
cd "C:\Program Files\Oracle\VirtualBox"
.\VBoxManage clonemedium disk ".\downloads\metasploitable-linux-2.0.0\Metasploitable2-Linux\Metasploitable.vmdk" ".\downloads\metasploitable.vdi" --format VDI
```

### Final Working Configuration

- **VM Name**: Metasploitable2
- **Type**: Linux
- **Version**: Ubuntu (32-bit)
- **Network**: Host-only Adapter (vboxnet0)
- **Login**: msfadmin / msfadmin

### Validation Commands

```bash
# Inside Metasploitable
ifconfig

# From Kali - test connectivity
ping 192.168.56.Y

# Network discovery - should show 3 hosts
sudo nmap -sn 192.168.56.0/24
```

### Key Learning Points

- VMware images need conversion or manual import
- IDE controller compatibility for older Linux systems
- Network isolation critical for safe testing

---

## STEP 4 — Port Scanning & Service Enumeration

### Objective

Perform deep reconnaissance on target using various Nmap techniques.

### Commands Used

#### Basic Discovery

```bash
# Confirm 3 hosts visible
sudo nmap -sn 192.168.56.0/24 -v
```

#### Port Scanning Techniques

```bash
# TCP SYN scan (stealth)
sudo nmap -sS 192.168.56.X

# Full port scan (all 65535)
sudo nmap -p- 192.168.56.X

# Service & version detection
sudo nmap -sV 192.168.56.X

# OS fingerprinting
sudo nmap -O 192.168.56.X

# Combined aggressive scan
sudo nmap -A 192.168.56.X
```

#### Output Management

```bash
# Multiple output formats
sudo nmap -A 192.168.56.X -oN metasploitable_scan.txt
sudo nmap -A 192.168.56.X -oX metasploitable_scan.xml
sudo nmap -A 192.168.56.X -oG metasploitable_scan.gnmap

# Vulnerability scanning
sudo nmap --script vuln 192.168.56.X
```

### Scan Results Summary

**Target IP**: 192.168.56.103
**Open Ports Identified**: 21 TCP services including:

- ftp (21), ssh (22), telnet (23), smtp (25)
- http (80), rpcbind (111), smb (139,445)
- exec (512), login (513), shell (514)
- mysql (3306), postgresql (5432), vnc (5900)
- And more...

**OS Detection**: Linux 2.6.9 - 2.6.33 (100% accuracy)

### Key Learning Points

- SYN scans faster and stealthier than TCP connect
- Version detection critical for vulnerability mapping
- OS detection uses TCP/IP stack fingerprinting
- Aggressive scans combine multiple techniques

---

## STEP 5 — Data Engineering & Analysis

### Objective

Convert raw Nmap data into structured, analyzable format.

### Commands Used

#### XML Processing

```bash
# Convert XML to HTML report
xsltproc metasploitable_scan.xml -o metasploitable_scan.html
```

#### CSV Extraction

```bash
# Extract open ports to CSV
grep "open" metasploitable_scan.txt | awk '{print $1","$2","$3}' > open_ports.csv
```

#### Data Visualization Attempts

#### Error 1: Missing nmaptocsv Tool

```bash
nmaptocsv --version  # FAILED: command not found
```

#### Error 2: CSV Structure Mismatch

**Python Code Failed**:
```python
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
with open("open_ports.csv") as f:
    reader = csv.DictReader(f)  # EXPECTED headers
    for row in reader:
        host = row['IP Address']  # FAILED: no such column
```

**Root Cause**: CSV had no headers, just raw data:

```csv
21/tcp,open,ftp
22/tcp,open,ssh
...
```

#### Fix 1: Raw CSV Parsing

```python
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
host = "192.168.56.103"  # hardcoded target IP

with open("open_ports.csv") as f:
    reader = csv.reader(f)  # raw reader, no headers
    for row in reader:
        port_proto = row[0]     # "21/tcp"
        service = row[2]        # "ftp"
        node = f"{service} ({port_proto})"
        G.add_edge(host, node)

nx.draw(G, with_labels=True, node_size=2000)
plt.show()
```

#### Fix 2: Add Headers to CSV

```bash
echo "Port,State,Service" > formatted_ports.csv
cat open_ports.csv >> formatted_ports.csv
```

**Updated Python Code**:

```python
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
host = "192.168.56.103"

with open("formatted_ports.csv") as f:
    reader = csv.DictReader(f)  # now works with headers
    for row in reader:
        node = f"{row['Service']} ({row['Port']})"
        G.add_edge(host, node)

pos = nx.spring_layout(G, k=0.5)
nx.draw(G, pos, with_labels=True, node_size=2000, font_size=8)
plt.show()
```

### Final Data Pipeline

1. **Nmap Scan** → XML output
2. **xsltproc** → HTML report
3. **grep/awk** → CSV extraction
4. **Python** → Network graph visualization
5. **Analysis** → Attack surface mapping

### Files Generated

- `metasploitable_scan.txt` - Human-readable
- `metasploitable_scan.xml` - Structured data
- `metasploitable_scan.html` - Visual report
- `open_ports.csv` - Raw port data
- `formatted_ports.csv` - Headered CSV
- Network graph visualization

### Key Learning Points

- XML format enables automated processing
- CSV extraction requires understanding data structure
- Visualization helps identify attack surface
- Data engineering transforms scans into intelligence

---

## Lab Architecture Summary

### Network Topology

```bash
[ Host Machine ]
│
[ VirtualBox   ]
│
┌─────────────── Host-Only Network (192.168.56.0/24) ───────────────┐
│                                                                   │
│  [ Kali Linux ]     192.168.56.101   → Attacker/Scanner           │
│  [ Metasploitable ] 192.168.56.103   → Vulnerable Target          │
│  [ Host Adapter ]   192.168.56.1     → Infrastructure/Gateway     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Scan Evolution

1. **Host Discovery** → ARP-based local network mapping
2. **Port Scanning** → Full TCP service enumeration
3. **Service Detection** → Version and application fingerprinting
4. **OS Detection** → System identification
5. **Data Engineering** → Structured analysis and visualization

### Skills Developed

- Virtual network design and isolation
- Cross-platform VM compatibility issues
- Nmap scan technique selection
- Data parsing and visualization
- Error troubleshooting in security tools

---

## Next Steps (Step 6+)

- Vulnerability analysis and CVE mapping
- Exploitation planning with Metasploit
- Automated scanning pipelines
- Blue team detection and monitoring
- IoT/UAV security extensions

---

## Safety & Compliance Notes

- All scans performed in isolated virtual environment
- No real networks or systems were scanned
- Metasploitable 2 is intentionally vulnerable for training
- Follow responsible disclosure practices in real engagements
