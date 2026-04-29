# Network Architecture Diagram

## Lab Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    Host Machine (Windows)                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 VirtualBox Hypervisor                   │    │
│  │                                                         │    │
│  │  ┌────────────── Host-Only Network ───────────────┐     │    │
│  │  │                                               │     │    │
│  │  │  192.168.56.0/24                              │     │    │
│  │  │  ┌─────────────┐    ┌─────────────┐           │     │    │
│  │  │  │   Kali     │    │Metasploitable│           │     │    │
│  │  │  │  Linux     │    │      2      │           │     │    │
│  │  │  │Attacker    │    │   Target    │           │     │    │
│  │  │  │192.168.56.101│   │192.168.56.103│           │     │    │
│  │  │  └─────────────┘    └─────────────┘           │     │    │
│  │  │                                               │     │    │
│  │  │  ┌─────────────┐                              │     │    │
│  │  │  │Host Adapter│                              │     │    │
│  │  │  │192.168.56.1│                              │     │    │
│  │  │  └─────────────┘                              │     │    │
│  │  │                                               │     │    │
│  │  └───────────────────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## IP Address Assignment

| Component | IP Address | Role | Notes |
|-----------|------------|------|-------|
| Host Windows | 192.168.56.1 | Gateway/Infrastructure | VirtualBox Host-Only adapter |
| Kali Linux | 192.168.56.101 | Attacker/Scanner | Nmap execution point |
| Metasploitable 2 | 192.168.56.103 | Vulnerable Target | Intentionally insecure |

## Network Configuration Details

### VirtualBox Network Settings
- **Network Type**: Host-only Adapter
- **Network Name**: vboxnet0
- **Subnet**: 192.168.56.0/24
- **DHCP Range**: 192.168.56.100 - 192.168.56.200
- **Gateway**: 192.168.56.1 (Host machine)

### VM Network Adapters
```
Kali Linux:
├── Adapter 1: Host-only (vboxnet0)
└── Status: Connected

Metasploitable 2:
├── Adapter 1: Host-only (vboxnet0)
└── Status: Connected
```

## Traffic Flow

### Scan Direction
```
[Kali Linux] → Nmap packets → [Metasploitable 2]
     ↑                                    ↓
   Results                              Responses
```

### Packet Types
1. **ARP Discovery** - Host discovery on local network
2. **TCP SYN** - Port scanning (stealth)
3. **Service Probes** - Version detection
4. **OS Fingerprinting** - TCP/IP stack analysis
5. **NSE Scripts** - Vulnerability detection

## Security Isolation

### What's Isolated
- Internet access (blocked)
- Real network scanning (prevented)
- Malware spread (contained)
- Traffic leakage (prevented)

### What's Allowed
- Inter-VM communication
- Layer-2 broadcasts (ARP)
- TCP/UDP traffic between VMs
- Packet capture and analysis

## Data Flow Architecture

```
Nmap Scan → XML Output → Python Parser → CSV Data → Network Graph
    ↓           ↓            ↓           ↓           ↓
Raw Packets → Structured → Parsed Data → Analysis → Visualization
```

## Expansion Points

### Future Additions
1. **DVWA Server** - Web application target (192.168.56.102)
2. **IoT Simulation** - MQTT/HTTP services
3. **Traffic Monitor** - Wireshark/tshark capture point
4. **IDS/IPS** - Snort/Suricata detection

### Scaling Options
```
Single VM → Multi-VM → Container Cluster → Cloud Deployment
    ↓           ↓              ↓                ↓
Basic Lab → Advanced Lab → Distributed Scale → Enterprise Range
```

## Network Verification Commands

### From Kali Linux
```bash
# Verify own IP
ip a

# Test connectivity to host
ping 192.168.56.1

# Test connectivity to target
ping 192.168.56.103

# Discover all hosts
sudo nmap -sn 192.168.56.0/24
```

### From Metasploitable
```bash
# Verify network interface
ifconfig

# Test connectivity
ping 192.168.56.1
ping 192.168.56.101
```

### From Host Windows
```powershell
# Verify virtual adapter
ipconfig

# Test VM connectivity
ping 192.168.56.101
ping 192.168.56.103
```

## Troubleshooting Network Issues

### Common Problems
1. **No IP Assignment** → DHCP disabled
2. **Cannot Ping** → Wrong adapter type
3. **One-way Traffic** → Firewall rules
4. **No ARP Response** → VM not started

### Diagnostic Steps
1. Check VM network adapter settings
2. Verify VirtualBox network manager
3. Test with simple ping commands
4. Monitor with tcpdump if needed
