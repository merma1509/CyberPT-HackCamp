# Error Troubleshooting Guide - Nmap Hands-On Lab

## Complete Error Log with Solutions

### STEP 1 Errors

#### Error: Network Address Assignment

**Problem**: Host adapter assigned network address instead of host address

```bash
IPv4 Address: 192.168.56.0 (Preferred)  # WRONG - Network address
```

**Symptoms**:

- `ping 192.168.56.1` failed
- `ping 192.168.56.0` succeeded (misleading)

**Root Cause**: VirtualBox Network Manager misconfiguration

**Solution**:

1. Open VirtualBox → File → Tools → Network Manager
2. Select vboxnet0
3. Set IPv4 Address: 192.168.56.1
4. Enable DHCP: 192.168.56.100-192.168.56.200

**Verification**:

```powershell
ping 192.168.56.1  # Should succeed
```

#### Error: PowerShell Adapter Name Mismatch

**Problem**:

```powershell
Disable-NetAdapter -Name "VirtualBox Host-Only Ethernet Adapter"  # FAILED
```

**Root Cause**: Actual adapter name was "Ethernet" not full description

**Solution**:

```powershell
Get-NetAdapter  # Find correct name
```

### STEP 2 Errors

#### Error: Nmap Not Found on Windows

**Problem**:

```powershell
nmap -sn 192.168.56.0/24  # FAILED: command not found
```

**Root Cause**: Nmap not installed on Windows host (expected behavior)

**Solution**: Run Nmap inside Kali VM, not Windows host

**Learning Point**: Lab design isolates tools to VM environment

### STEP 3 Errors

#### Error: VMware Format Incompatibility

**Problem**: Downloaded VMware files instead of VirtualBox format

```bash
Files: .vmdk, .vmx, .nvram, .vmsd, .vmxf  # VMware format
```

**Solution Attempts**:

**Attempt A - Manual VM Creation**:

1. Create VM without disk
2. Settings → Storage → Add Hard Disk → Choose existing
3. Select .vmdk file
4. Change controller to IDE (Metasploitable compatibility)

**Attempt B - Disk Conversion**:

```powershell
cd "C:\Program Files\Oracle\VirtualBox"
.\VBoxManage clonemedium disk "source.vmdk" "target.vdi" --format VDI
```

#### Error: VMDK Import Failure

**Problem**: VirtualBox couldn't attach .vmdk directly

**Root Cause**: Controller type mismatch (IDE vs SATA)

**Solution**: Use IDE controller for older Linux systems

### STEP 4 Errors

#### Error: No VM Network Connectivity

**Problem**: Metasploitable no IP address

**Symptoms**:

- `ifconfig` shows no eth0 IP
- `ping` from Kali fails

**Solution**:

```bash
sudo dhclient eth0  # Request DHCP
```

**Prevention**: Ensure Host-only adapter selected in VM settings

### STEP 5 Errors

#### Error: Missing nmaptocsv Tool

**Problem**:

```bash
nmaptocsv --version  # FAILED: command not found
```

**Root Cause**: Tool not installed in Kali

**Solution**: Use built-in tools (grep, awk, Python) instead

#### Error: CSV Structure Mismatch

**Problem**: Python code expected headers, CSV had none

```python
reader = csv.DictReader(f)  # EXPECTS headers
host = row['IP Address']    # FAILED: no such column
```

**Root Cause**: CSV format was:

```bash
21/tcp,open,ftp  # No header row
```

**Solutions**:

**Option 1 - Raw Parsing**:

```python
reader = csv.reader(f)  # No headers expected
port_proto = row[0]
service = row[2]
```

**Option 2 - Add Headers**:

```bash
echo "Port,State,Service" > formatted_ports.csv
cat open_ports.csv >> formatted_ports.csv
```

#### Error: Python open() Parameters

**Problem**:

```python
with open("open_ports.csv", sep=',') as f:  # FAILED
```

**Root Cause**: `open()` doesn't accept `sep` parameter

**Solution**: Use `csv.reader()` for delimiter specification

#### Error: Typo in Variable Name

**Problem**:

```python
service = roe['Service']  # FAILED: 'roe' not defined
```

**Root Cause**: Typo (should be 'row')

**Solution**:

```python
service = row['Service']  # Corrected
```

## General Troubleshooting Patterns

### Network Issues

1. **Symptom**: Can't ping between VMs
2. **Check**: Both VMs on same network adapter
3. **Check**: DHCP enabled and working
4. **Fix**: Reassign network adapters, restart VMs

### VM Import Issues

1. **Symptom**: VM won't start or boot
2. **Check**: Disk format compatibility
3. **Check**: Controller type (IDE vs SATA)
4. **Fix**: Convert disk format or change controller

### Data Processing Issues

1. **Symptom**: Python KeyError or parsing errors
2. **Check**: CSV structure vs code expectations
3. **Check**: File paths and permissions
4. **Fix**: Match data structure to code or vice versa

### Permission Issues

1. **Symptom**: Nmap scans fail or limited
2. **Check**: Running as non-root user
3. **Fix**: Use `sudo` for privileged scans

## Prevention Strategies

### Before Starting Each Step

1. **Verify network connectivity** with simple ping
2. **Check file permissions** before processing
3. **Validate data structure** before parsing
4. **Test with simple commands** before complex ones

### Common Check Commands

```bash
# Network verification
ip a
ping [target]

# File verification
ls -la
head [filename]

# Service verification
whoami
sudo nmap --version
```

## Learning Outcomes from Errors

1. **Network Architecture**: Understanding Layer-2 vs Layer-3 addressing
2. **Virtualization**: Cross-platform VM compatibility issues
3. **Data Processing**: Structure matters more than tools
4. **Security Context**: Isolation prevents real-world damage
5. **Debugging Methodology**: Systematic symptom → root cause → solution

## Quick Reference Solutions

| Error Type        | Quick Fix          | Command                                          |
| ----------------- | ------------------ | ------------------------------------------------ |
| No IP             | DHCP request       | `sudo dhclient eth0`                             |
| CSV parsing       | Use raw reader     | `csv.reader()` instead of `csv.DictReader()`     |
| Permission denied | Use sudo           | `sudo nmap`                                      |
| VM won't boot     | Change controller  | IDE for old Linux                                |
| Network isolation | Check adapter      | Host-only, not NAT                               |
