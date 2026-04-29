#!/usr/bin/env python3
"""
Network Visualization Tool - Create network graphs from Nmap results
Author: CyberHack Lab
Description: Generate network topology graphs and service visualizations
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import argparse
import json
import csv
from datetime import datetime

class NetworkVisualizer:
    def __init__(self):
        self.G = nx.Graph()
        self.colors = {
            'web': '#FF6B6B',
            'database': '#4ECDC4',
            'remote_access': '#FF8C00',
            'file_transfer': '#2E8B57',
            'mail': '#A9A9A9',
            'development': '#DDA0DD',
            'system': '#17A2B8',
            'unknown': '#666666'
        }
        
    def load_from_csv(self, csv_file):
        """Load network data from CSV file"""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('state') == 'open':
                        self.add_host_service(row['ip'], row['service'], row['port'], row.get('product', ''))
        except FileNotFoundError:
            print(f"Error: CSV file '{csv_file}' not found")
            return False
        return True
    
    def load_from_json(self, json_file):
        """Load network data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                for host in data:
                    ip = host.get('ip')
                    for port in host.get('ports', []):
                        if port.get('state') == 'open':
                            self.add_host_service(
                                ip, 
                                port.get('service'), 
                                port.get('port'), 
                                port.get('product', '')
                            )
        except FileNotFoundError:
            print(f"Error: JSON file '{json_file}' not found")
            return False
        return True
    
    def categorize_service(self, service_name):
        """Categorize services by type"""
        service_categories = {
            'web': ['http', 'https', 'apache', 'nginx', 'tomcat', 'iis'],
            'database': ['mysql', 'postgresql', 'oracle', 'mssql', 'mongodb', 'redis'],
            'remote_access': ['ssh', 'telnet', 'vnc', 'rdp', 'ftp'],
            'file_transfer': ['ftp', 'tftp', 'smb', 'nfs', 'cifs'],
            'mail': ['smtp', 'pop3', 'imap', 'submission'],
            'development': ['java-rmi', 'rpcbind', 'mysql', 'postgresql'],
            'system': ['netbios', 'ldap', 'kerberos', 'ntp', 'dns']
        }
        
        service_lower = service_name.lower() if service_name else ''
        
        for category, services in service_categories.items():
            if any(svc in service_lower for svc in services):
                return category
        
        return 'unknown'
    
    def add_host_service(self, ip, service, port, product):
        """Add host and service to graph"""
        # Add host node
        self.G.add_node(ip, type='host')
        
        # Add service node
        service_id = f"{service}_{port}"
        category = self.categorize_service(service)
        
        self.G.add_node(service_id, 
                     type='service', 
                     service=service,
                     port=port,
                     product=product,
                     category=category)
        
        # Add edge between host and service
        self.G.add_edge(ip, service_id)
    
    def create_topology_view(self, output_file):
        """Create network topology diagram"""
        plt.figure(figsize=(12, 8))
        
        # Separate nodes by type
        host_nodes = [n for n, d in self.G.nodes(data=True) if d.get('type') == 'host']
        service_nodes = [n for n, d in self.G.nodes(data=True) if d.get('type') == 'service']
        
        # Layout
        pos = nx.spring_layout(self.G, k=2, iterations=50)
        
        # Draw host nodes
        nx.draw_networkx_nodes(self.G, pos, nodelist=host_nodes, 
                           node_color='lightblue', node_size=1000, alpha=0.8)
        
        # Draw service nodes by category
        for category in self.colors.keys():
            category_nodes = [n for n, d in self.G.nodes(data=True) 
                           if d.get('category') == category]
            if category_nodes:
                nx.draw_networkx_nodes(self.G, pos, nodelist=category_nodes,
                                   node_color=self.colors[category], 
                                   node_size=300, alpha=0.7)
        
        # Draw edges
        nx.draw_networkx_edges(self.G, pos, alpha=0.5, width=1)
        
        # Create legend
        legend_patches = [mpatches.Patch(color=color, label=label) 
                        for label, color in self.colors.items()]
        plt.legend(handles=legend_patches, loc='upper right', bbox_to_anchor=(1.15, 1))
        
        # Add labels for hosts
        host_labels = {node: node for node in host_nodes}
        nx.draw_networkx_labels(self.G, pos, labels=host_labels, font_size=10)
        
        plt.title(f'Network Topology - {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                 fontsize=14, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Network topology saved to: {output_file}")
    
    def create_service_breakdown(self, output_file):
        """Create service breakdown chart"""
        # Count services by category
        category_counts = {}
        for node, data in self.G.nodes(data=True):
            if data.get('type') == 'service':
                category = data.get('category', 'unknown')
                category_counts[category] = category_counts.get(category, 0) + 1
        
        if not category_counts:
            print("No services found for breakdown")
            return
        
        # Create pie chart
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Pie chart
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        colors = [self.colors.get(cat, '#666666') for cat in categories]
        
        wedges, texts, autotexts = ax1.pie(counts, labels=categories, colors=colors, 
                                          autopct='%1.1f%%', startangle=90)
        ax1.set_title('Service Distribution by Category', fontweight='bold')
        
        # Bar chart
        ax2.bar(categories, counts, color=colors)
        ax2.set_title('Service Count by Category', fontweight='bold')
        ax2.set_ylabel('Number of Services')
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Service breakdown saved to: {output_file}")
    
    def create_host_details(self, output_file):
        """Create detailed host information view"""
        # Group services by host
        host_services = {}
        for node, data in self.G.nodes(data=True):
            if data.get('type') == 'service':
                # Find connected host
                neighbors = list(self.G.neighbors(node))
                if neighbors:
                    host = neighbors[0]  # Service should only connect to one host
                    if host not in host_services:
                        host_services[host] = []
                    
                    service_info = {
                        'service': data.get('service'),
                        'port': data.get('port'),
                        'product': data.get('product'),
                        'category': data.get('category')
                    }
                    host_services[host].append(service_info)
        
        if not host_services:
            print("No host information available")
            return
        
        # Create detailed view
        fig, ax = plt.subplots(figsize=(16, 10))
        ax.axis('tight')
        ax.axis('off')
        
        y_pos = 0.9
        for host, services in host_services.items():
            # Host header
            ax.text(0.05, y_pos, f'Host: {host}', fontsize=12, fontweight='bold')
            y_pos -= 0.08
            
            # Service list
            for i, service in enumerate(services[:10]):  # Limit to 10 services per host
                service_text = f"  Port {service['port']}/{service['service'].upper()} - {service.get('product', 'Unknown')}"
                color = self.colors.get(service['category'], '#666666')
                ax.text(0.05, y_pos, service_text, fontsize=9, color=color)
                y_pos -= 0.04
            
            if len(services) > 10:
                ax.text(0.05, y_pos, f"  ... and {len(services) - 10} more", 
                       fontsize=9, style='italic', color='gray')
                y_pos -= 0.04
            
            y_pos -= 0.06
        
        plt.title(f'Host Service Details - {datetime.now().strftime("%Y-%m-%d %H:%M")}', 
                 fontsize=14, fontweight='bold')
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Host details saved to: {output_file}")
    
    def generate_report(self, output_prefix):
        """Generate complete visualization report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate all visualizations
        self.create_topology_view(f"{output_prefix}_topology_{timestamp}.png")
        self.create_service_breakdown(f"{output_prefix}_breakdown_{timestamp}.png")
        self.create_host_details(f"{output_prefix}_hosts_{timestamp}.png")
        
        # Generate statistics
        stats = self.generate_statistics()
        stats_file = f"{output_prefix}_stats_{timestamp}.txt"
        with open(stats_file, 'w') as f:
            f.write(stats)
        
        print(f"Complete report generated with prefix: {output_prefix}")
        print(f"Statistics saved to: {stats_file}")
    
    def generate_statistics(self):
        """Generate network statistics"""
        total_nodes = len(self.G.nodes())
        host_nodes = len([n for n, d in self.G.nodes(data=True) if d.get('type') == 'host'])
        service_nodes = len([n for n, d in self.G.nodes(data=True) if d.get('type') == 'service'])
        total_edges = len(self.G.edges())
        
        # Service categories
        category_counts = {}
        for node, data in self.G.nodes(data=True):
            if data.get('type') == 'service':
                category = data.get('category', 'unknown')
                category_counts[category] = category_counts.get(category, 0) + 1
        
        stats = f"""
Network Statistics - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
================================================

Node Information:
- Total Nodes: {total_nodes}
- Host Nodes: {host_nodes}
- Service Nodes: {service_nodes}
- Total Connections: {total_edges}

Service Categories:
"""
        for category, count in sorted(category_counts.items()):
            stats += f"- {category.replace('_', ' ').title()}: {count}\n"
        
        return stats

def main():
    parser = argparse.ArgumentParser(description='Create network visualizations from scan results')
    parser.add_argument('input_file', help='CSV or JSON file with scan results')
    parser.add_argument('-o', '--output', help='Output file prefix', default='network_analysis')
    parser.add_argument('--topology', action='store_true', help='Generate topology view')
    parser.add_argument('--breakdown', action='store_true', help='Generate service breakdown')
    parser.add_argument('--hosts', action='store_true', help='Generate host details')
    parser.add_argument('--report', action='store_true', help='Generate complete report')
    
    args = parser.parse_args()
    
    visualizer = NetworkVisualizer()
    
    # Load data based on file extension
    if args.input_file.endswith('.json'):
        if not visualizer.load_from_json(args.input_file):
            exit(1)
    elif args.input_file.endswith('.csv'):
        if not visualizer.load_from_csv(args.input_file):
            exit(1)
    else:
        print("Error: Input file must be .csv or .json")
        exit(1)
    
    # Generate visualizations
    if args.topology or args.report:
        visualizer.create_topology_view(f"{args.output}_topology.png")
    
    if args.breakdown or args.report:
        visualizer.create_service_breakdown(f"{args.output}_breakdown.png")
    
    if args.hosts or args.report:
        visualizer.create_host_details(f"{args.output}_hosts.png")
    
    if args.report:
        visualizer.generate_report(args.output)
    elif not any([args.topology, args.breakdown, args.hosts]):
        print("No visualization specified. Use --topology, --breakdown, --hosts, or --report")
        print("Or use --report for all visualizations")

if __name__ == "__main__":
    main()
