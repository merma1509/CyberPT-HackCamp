# Complete Command Log - Nmap Hands-On Lab

## STEP 1 - Environment Setup

### Windows PowerShell Commands

```powershell
# Verify VirtualBox installation
VBoxManage --version

# Check network configuration
ipconfig /all

# Test connectivity (before fix)
ping 192.168.56.1
ping 192.168.56.0

# Network adapter commands (failed)
Disable-NetAdapter -Name "VirtualBox Host-Only Ethernet Adapter"
Enable-NetAdapter -Name "VirtualBox Host-Only Ethernet Adapter"

# Test connectivity (after fix)
ping 192.168.56.1

# Attempted nmap on host (failed - expected)
nmap -sn 192.168.56.0/24
```

## STEP 2 - Kali Linux VM

### Kali Terminal Commands

```bash
# Network interface verification
ip a

# Connectivity test
ping 192.168.56.1

# Host discovery scans
nmap -sn 192.168.56.0/24
sudo nmap -sn 192.168.56.0/24

# Privilege check
whoami

# Packet capture installation and monitoring
sudo apt install tcpdump
sudo tcpdump -i eth0 arp

# Advanced host discovery with verbose output
sudo nmap -sn 192.168.56.0/24 -v
```

## STEP 3 - Metasploitable 2 Setup

### File Management Commands

```bash
# List downloaded files
ls metasploitable-linux-2.0.0/
ls metasploitable-linux-2.0.0/Metasploitable2-linux/

# VirtualBox disk conversion (attempted)
cd "C:\Program Files\Oracle\VirtualBox"
.\VBoxManage clonemedium disk ".\downloads\metasploitable-linux-2.0.0\Metasploitable2-Linux\Metasploitable.vmdk" ".\downloads\metasploitable.vdi" --format VDI
```

### Metasploitable Commands

```bash
# Network interface check
ifconfig

# DHCP client (if needed)
sudo dhclient eth0
```

### Kali Validation Commands

```bash
# Ping target
ping 192.168.56.Y

# Network discovery (should show 3 hosts)
sudo nmap -sn 192.168.56.0/24
```

## STEP 4 - Port Scanning & Service Enumeration

### Complete Nmap Command Set

```bash
# Target identification (replace X with actual IP)
TARGET="192.168.56.103"

# Basic discovery
sudo nmap -sn $TARGET -v

# TCP SYN scan
sudo nmap -sS $TARGET

# Full port scan
sudo nmap -p- $TARGET

# Service version detection
sudo nmap -sV $TARGET

# OS fingerprinting
sudo nmap -O $TARGET

# Combined OS and service detection
sudo nmap -O -sV $TARGET

# Aggressive scan (all-in-one)
sudo nmap -A $TARGET

# Multiple output formats
sudo nmap -A $TARGET -oN metasploitable_scan.txt
sudo nmap -A $TARGET -oX metasploitable_scan.xml
sudo nmap -A $TARGET -oG metasploitable_scan.gnmap

# Vulnerability scanning
sudo nmap --script vuln $TARGET

# Web enumeration
sudo nmap -p 80 --script=http-enum $TARGET
sudo nmap --script=http-vuln* $TARGET
```

## STEP 5 - Data Engineering & Analysis

### XML Processing Commands

```bash
# Convert XML to HTML report
xsltproc metasploitable_scan.xml -o metasploitable_scan.html

# List generated files
ls

# Extract open ports to CSV
grep "open" metasploitable_scan.txt | awk '{print $1","$2","$3}' > open_ports.csv

# Check CSV content
cat *.csv

# Attempt nmaptocsv (failed)
nmaptocsv --version
```

### Python Data Processing

```python
# Failed attempt 1 - DictReader with no headers
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
with open("open_ports.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        host = row['IP Address']
        service = roe['Service'] + ":" + row["Port"]
        G.add_edge(host, service)
nx.draw(G, with_labels=True, node_size=2000, node_color="skyblue")
plt.show()

# Failed attempt 2 - Wrong open() parameters
with open("open_ports.csv", sep=',') as f:
    reader = csv.DictReader(f)
    for row in reader:
        host = row.get(0)
        service = row.get(1) + ":" + row.get(2)
        G.add_edge(host, service)
nx.draw(G, with_labels=True, node_size=2000, node_color="skyblue")
plt.show()

# Working solution 1 - Raw CSV parsing
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
host = "192.168.56.103"

with open("open_ports.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        port_proto = row[0]
        service = row[2]
        node = f"{service} ({port_proto})"
        G.add_edge(host, node)

nx.draw(G, with_labels=True, node_size=2000)
plt.show()

# Working solution 2 - Add headers to CSV
echo "Port,State,Service" > formatted_ports.csv
cat open_ports.csv >> formatted_ports.csv

# Updated Python with headers
import networkx as nx
import matplotlib.pyplot as plt
import csv

G = nx.Graph()
host = "192.168.56.103"

with open("formatted_ports.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        node = f"{row['Service']} ({row['Port']})"
        G.add_edge(host, node)

pos = nx.spring_layout(G, k=0.5)
nx.draw(G, pos, with_labels=True, node_size=2000, font_size=8)
plt.show()
```

### File Operations

```bash
# Create formatted CSV with headers
echo "Port,State,Service" > formatted_ports.csv
cat open_ports.csv >> formatted_ports.csv

# Verify file contents
cat formatted_ports.csv
```

## File Structure Generated

```markdown
~/ (Kali home directory)
├── base.nmap
├── metasploitable_scan.txt
├── metasploitable_scan.xml
├── metasploitable_scan.gnmap
├── metasploitable_scan.html
├── open_ports.csv
├── formatted_ports.csv
└── [Standard directories: Desktop, Documents, Downloads, etc.]
```

## Key IP Addresses Used

- Host (Windows): 192.168.56.1
- Kali Linux: 192.168.56.101
- Metasploitable: 192.168.56.103
