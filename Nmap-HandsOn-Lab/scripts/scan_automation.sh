#!/bin/bash

# Nmap Scan Automation Script
# Author: CyberHack Lab
# Description: Automated reconnaissance pipeline

# Configuration
NETWORK="192.168.56.0/24"
OUTPUT_DIR="./scan_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_DIR="${OUTPUT_DIR}/scan_${TIMESTAMP}"

# Create output directory
mkdir -p "$SCAN_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Function to check if target is reachable
check_connectivity() {
    local target=$1
    if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to run nmap with error handling
run_nmap() {
    local scan_type=$1
    local target=$2
    local output_file=$3
    local options=$4
    
    log "Starting ${scan_type} scan on ${target}"
    
    if sudo nmap $options "$target" -oA "$output_file" 2>/dev/null; then
        log "${scan_type} scan completed successfully"
        return 0
    else
        error "${scan_type} scan failed on ${target}"
        return 1
    fi
}

# Function to extract live hosts
extract_live_hosts() {
    local grep_file=$1
    local hosts_file="${SCAN_DIR}/live_hosts"
    
    log "Extracting live hosts from ${grep_file}"
    grep "Up" "$grep_file" | awk '{print $2}' > "$hosts_file"
    
    local host_count=$(wc -l < "$hosts_file")
    log "Found ${host_count} live hosts"
    
    echo "$hosts_file"
}

# Function to analyze scan results
analyze_results() {
    local xml_file=$1
    local summary_file="${SCAN_DIR}/scan_summary"
    
    log "Analyzing scan results from ${xml_file}"
    
    # Count open ports
    local open_ports=$(grep -c "state=\"open\"" "$xml_file" 2>/dev/null || echo "0")
    local total_hosts=$(grep -c "<host " "$xml_file" 2>/dev/null || echo "0")
    
    # Generate summary
    cat > "$summary_file" << EOF
Scan Summary - $(date)
========================
Total Hosts Scanned: $total_hosts
Total Open Ports Found: $open_ports
Scan Results: $xml_file
Output Directory: $SCAN_DIR

EOF
    
    log "Analysis complete. Summary saved to ${summary_file}"
}

# Main execution
main() {
    log "Starting automated reconnaissance pipeline"
    log "Target Network: ${NETWORK}"
    log "Output Directory: ${SCAN_DIR}"
    
    # Step 1: Host Discovery
    log "=== STEP 1: Host Discovery ==="
    local grep_file="${SCAN_DIR}/host_discovery"
    
    if ! run_nmap "Host Discovery" "$NETWORK" "$grep_file" "-sn -oG"; then
        error "Host discovery failed. Exiting."
        exit 1
    fi
    
    # Nmap creates .gnmap extension automatically
    # local actual_grep_file="${SCAN_DIR}/host_discovery.gnmap"
    #  if [ ! -f "$actual_grep_file" ]; then
        # actual_grep_file="${SCAN_DIR}/host_discovery.gnmap.gnmap"
    # fi
    
    local hosts_file=$(extract_live_hosts "$grep_file")
    
    if [ ! -s "$hosts_file" ]; then
        warning "No live hosts found. Scanning network directly."
        hosts_file="/dev/null"
    fi
    
    # Step 2: Port Scanning
    log "=== STEP 2: Port Scanning ==="
    local ports_file="${SCAN_DIR}/port_scan"
    
    # Run port scan on all live hosts or network
    if [ -s "$hosts_file" ] && [ "$hosts_file" != "/dev/null" ]; then
        if ! run_nmap "Port Scan" "-iL $hosts_file" "$ports_file" "-sS -p- -T4"; then
            error "Port scanning failed. Exiting."
            exit 1
        fi
    else
        if ! run_nmap "Port Scan" "$NETWORK" "$ports_file" "-sS -p- -T4"; then
            error "Port scanning failed. Exiting."
            exit 1
        fi
    fi
    
    # Step 3: Service Detection
    log "=== STEP 3: Service Detection ==="
    local services_file="${SCAN_DIR}/service_detection"
    
    if [ -s "$hosts_file" ] && [ "$hosts_file" != "/dev/null" ]; then
        if ! run_nmap "Service Detection" "-iL $hosts_file" "$services_file" "-sV -sC -O"; then
            error "Service detection failed. Exiting."
            exit 1
        fi
    else
        if ! run_nmap "Service Detection" "$NETWORK" "$services_file" "-sV -sC -O"; then
            error "Service detection failed. Exiting."
            exit 1
        fi
    fi
    
    # Step 4: Vulnerability Scanning
    log "=== STEP 4: Vulnerability Scanning ==="
    local vuln_file="${SCAN_DIR}/vulnerability_scan"
    
    if [ -s "$hosts_file" ] && [ "$hosts_file" != "/dev/null" ]; then
        if ! run_nmap "Vulnerability" "-iL $hosts_file" "$vuln_file" "--script vuln"; then
            warning "Vulnerability scanning failed or incomplete"
        else
            log "Vulnerability scanning completed"
        fi
    else
        if ! run_nmap "Vulnerability" "$NETWORK" "$vuln_file" "--script vuln"; then
            warning "Vulnerability scanning failed or incomplete"
        else
            log "Vulnerability scanning completed"
        fi
    fi
    
    # Step 5: Analysis
    log "=== STEP 5: Analysis ==="
    analyze_results "$services_file"
    
    # Step 6: Generate Reports
    log "=== STEP 6: Report Generation ==="
    
    # Convert XML to HTML if xsltproc is available
    if command -v xsltproc >/dev/null 2>&1; then
        local html_file="${SCAN_DIR}/scan_report.html"
        xsltproc "$services_file" -o "$html_file"
        log "HTML report generated: ${html_file}"
    else
        warning "xsltproc not available. HTML report not generated."
    fi
    
    # Convert to CSV using Python parser if available
    if command -v python3 >/dev/null 2>&1; then
        if [ -f "./nmap_parser.py" ]; then
            local csv_file="${SCAN_DIR}/scan_results.csv"
            python3 ./nmap_parser.py "$services_file" --csv -o "${SCAN_DIR}/scan_results"
            log "CSV results generated: ${csv_file}"
        else
            warning "nmap_parser.py not found. CSV export skipped."
        fi
    else
        warning "Python3 not available. CSV export skipped."
    fi
    
    # Generate final summary
    log "=== SCAN COMPLETE ==="
    log "All results saved in: ${SCAN_DIR}"
    log "Files generated:"
    ls -la "$SCAN_DIR"
}

# Script usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -n, --network NETWORK    Target network (default: $NETWORK)"
    echo "  -o, --output DIR       Output directory (default: $OUTPUT_DIR)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Scan default network"
    echo "  $0 -n 192.168.1.0/24              # Scan custom network"
    echo "  $0 -o /tmp/scan_results              # Custom output directory"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--network)
            NETWORK="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            SCAN_DIR="${OUTPUT_DIR}/scan_${TIMESTAMP}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    error "This script requires root privileges for Nmap scans"
    error "Please run with: sudo $0"
    exit 1
fi

# Check dependencies
for cmd in nmap grep awk ping; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error "Required command not found: $cmd"
        exit 1
    fi
done

# Run main function
main
