#!/usr/bin/env python3
"""
Nmap XML Parser - Convert scan results to structured data
Author: CyberHack Lab
Description: Parse Nmap XML output and extract host/port/service information
"""

import xml.etree.ElementTree as ET
import csv
import json
import argparse
from datetime import datetime

class NmapParser:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()
        
    def extract_hosts(self):
        """Extract host information from XML"""
        hosts = []
        
        for host in self.root.findall('host'):
            host_info = {}
            
            # Get IP address
            address = host.find('address')
            if address is not None:
                host_info['ip'] = address.get('addr')
                host_info['addr_type'] = address.get('addrtype')
            
            # Get host status
            status = host.find('status')
            if status is not None:
                host_info['status'] = status.get('state')
            
            # Get OS information
            os_match = host.find('.//osmatch')
            if os_match is not None:
                host_info['os'] = os_match.get('name')
                host_info['os_accuracy'] = os_match.get('accuracy')
            
            # Get ports
            ports = self.extract_ports(host)
            host_info['ports'] = ports
            
            # Get host scripts
            hostscripts = host.find('.//hostscript')
            if hostscripts is not None:
                host_info['hostscripts'] = self.extract_scripts(hostscripts)
            
            hosts.append(host_info)
        
        return hosts
    
    def extract_ports(self, host):
        """Extract port information from host element"""
        ports = []
        
        # TCP ports
        tcp_ports = host.find('.//table[@key="tcp"]')
        if tcp_ports is not None:
            for port in tcp_ports.findall('port'):
                port_info = self.extract_port_info(port, 'tcp')
                ports.append(port_info)
        
        # UDP ports
        udp_ports = host.find('.//table[@key="udp"]')
        if udp_ports is not None:
            for port in udp_ports.findall('port'):
                port_info = self.extract_port_info(port, 'udp')
                ports.append(port_info)
        
        return ports
    
    def extract_port_info(self, port, protocol):
        """Extract detailed port information"""
        port_info = {
            'protocol': protocol,
            'port': port.get('portid'),
            'state': None,
            'service': None,
            'version': None,
            'product': None,
            'extra_info': None,
            'scripts': []
        }
        
        # Get port state
        state = port.find('state')
        if state is not None:
            port_info['state'] = state.get('state')
            port_info['reason'] = state.get('reason')
            port_info['reason_ttl'] = state.get('reason_ttl')
        
        # Get service information
        service = port.find('service')
        if service is not None:
            port_info['service'] = service.get('name')
            port_info['version'] = service.get('version')
            port_info['product'] = service.get('product')
            port_info['extra_info'] = service.get('extrainfo')
            port_info['method'] = service.get('method')
            port_info['conf'] = service.get('conf')
        
        # Get script results
        scripts = port.find('script')
        if scripts is not None:
            for script in scripts:
                script_info = {
                    'id': script.get('id'),
                    'output': script.get('output')
                }
                port_info['scripts'].append(script_info)
        
        return port_info
    
    def extract_scripts(self, scripts_element):
        """Extract script information"""
        scripts = []
        for script in scripts_element.findall('script'):
            script_info = {
                'id': script.get('id'),
                'output': script.get('output')
            }
            scripts.append(script_info)
        return scripts
    
    def to_csv(self, output_file):
        """Export parsed data to CSV format"""
        hosts = self.extract_hosts()
        
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['ip', 'status', 'protocol', 'port', 'state', 'service', 'version', 'product', 'extra_info']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for host in hosts:
                for port in host.get('ports', []):
                    row = {
                        'ip': host.get('ip'),
                        'status': host.get('status'),
                        'protocol': port.get('protocol'),
                        'port': port.get('port'),
                        'state': port.get('state'),
                        'service': port.get('service'),
                        'version': port.get('version'),
                        'product': port.get('product'),
                        'extra_info': port.get('extra_info')
                    }
                    writer.writerow(row)
    
    def to_json(self, output_file):
        """Export parsed data to JSON format"""
        hosts = self.extract_hosts()
        
        with open(output_file, 'w') as jsonfile:
            json.dump(hosts, jsonfile, indent=2)
    
    def generate_summary(self):
        """Generate summary statistics"""
        hosts = self.extract_hosts()
        
        total_hosts = len(hosts)
        total_ports = 0
        open_ports = 0
        services = {}
        
        for host in hosts:
            for port in host.get('ports', []):
                total_ports += 1
                if port.get('state') == 'open':
                    open_ports += 1
                    
                    service = port.get('service', 'unknown')
                    services[service] = services.get(service, 0) + 1
        
        return {
            'scan_date': datetime.now().isoformat(),
            'total_hosts': total_hosts,
            'total_ports_scanned': total_ports,
            'open_ports': open_ports,
            'unique_services': len(services),
            'service_breakdown': services
        }

def main():
    parser = argparse.ArgumentParser(description='Parse Nmap XML results')
    parser.add_argument('xml_file', help='Nmap XML file to parse')
    parser.add_argument('-o', '--output', help='Output file prefix')
    parser.add_argument('--csv', action='store_true', help='Export to CSV')
    parser.add_argument('--json', action='store_true', help='Export to JSON')
    parser.add_argument('--summary', action='store_true', help='Show summary statistics')
    
    args = parser.parse_args()
    
    try:
        nmap_parser = NmapParser(args.xml_file)
        
        if args.summary:
            summary = nmap_parser.generate_summary()
            print("=== Nmap Scan Summary ===")
            print(f"Scan Date: {summary['scan_date']}")
            print(f"Total Hosts: {summary['total_hosts']}")
            print(f"Total Ports Scanned: {summary['total_ports_scanned']}")
            print(f"Open Ports: {summary['open_ports']}")
            print(f"Unique Services: {summary['unique_services']}")
            print("\nService Breakdown:")
            for service, count in summary['service_breakdown'].items():
                print(f"  {service}: {count}")
        
        if args.csv:
            csv_file = f"{args.output}.csv" if args.output else "nmap_results.csv"
            nmap_parser.to_csv(csv_file)
            print(f"CSV exported to: {csv_file}")
        
        if args.json:
            json_file = f"{args.output}.json" if args.output else "nmap_results.json"
            nmap_parser.to_json(json_file)
            print(f"JSON exported to: {json_file}")
    
    except FileNotFoundError:
        print(f"Error: File '{args.xml_file}' not found")
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")

if __name__ == "__main__":
    main()
