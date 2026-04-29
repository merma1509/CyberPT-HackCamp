"""
User interface for network sniffer
Provides CLI, web interface, and visualization components
"""

import os
import sys
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()
except ImportError:
    print("Colorama not installed. Install with: pip install colorama")
    # Fallback colors
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

from core import PacketCapture, PacketAnalyzer
from detection import ThreatDetectionEngine
from reporting import AlertManager, ReportGenerator, Dashboard
from config import config, compliance
from privileges import PrivilegeManager

class ConsoleUI:
    """Command-line interface for network sniffer"""
    
    def __init__(self):
        self.packet_capture = PacketCapture()
        self.packet_analyzer = PacketAnalyzer()
        self.detection_engine = ThreatDetectionEngine()
        self.alert_manager = AlertManager()
        self.report_generator = ReportGenerator(self.alert_manager, self.detection_engine)
        self.dashboard = Dashboard(self.alert_manager, self.detection_engine)
        
        self.is_running = False
        self.display_thread = None
        
        # Setup packet handlers
        self.packet_capture.add_packet_handler(self._handle_packet)
        self.alert_manager.add_alert_callback(self._handle_alert)
    
    def _handle_packet(self, packet_info):
        """Handle incoming packets"""
        # Analyze packet
        self.packet_analyzer.analyze_packet(packet_info)
        
        # Run threat detection
        alerts = self.detection_engine.analyze_packet(packet_info)
        
        # Add alerts
        for alert in alerts:
            self.alert_manager.add_alert(alert)
    
    def _handle_alert(self, alert):
        """Handle new alerts"""
        if config.enable_real_time_alerts:
            self._display_alert(alert)
    
    def _display_alert(self, alert):
        """Display alert to console"""
        color_map = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN
        }
        
        color = color_map.get(alert.threat_level.value, Fore.WHITE)
        
        print(f"\n{color}[{alert.threat_level.value.upper()}] {alert.threat_type}{Style.RESET_ALL}")
        print(f"  {color}Description: {alert.description}{Style.RESET_ALL}")
        print(f"  {color}Source: {alert.src_ip} -> Destination: {alert.dst_ip}{Style.RESET_ALL}")
        print(f"  {color}Time: {alert.timestamp.strftime('%H:%M:%S')}{Style.RESET_ALL}")
    
    def show_banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    NETWORK SNIFFER v1.0                        ║
║              Advanced Threat Detection System                 ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}IMPORTANT LEGAL NOTICE:{Style.RESET_ALL}
This tool is for authorized network security testing ONLY.
- Only use on networks you own or have explicit permission
- Follow all applicable laws (GDPR, CCPA, etc.)
- Unauthorized use is illegal and punishable by law

{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}"""
        print(banner)
        input()
    
    def show_main_menu(self):
        """Display main menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
            print(f"║                    NETWORK SNIFFER MENU                        ║")
            print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}1.{Style.RESET_ALL} Start Packet Capture")
            print(f"{Fore.GREEN}2.{Style.RESET_ALL} Stop Packet Capture")
            print(f"{Fore.GREEN}3.{Style.RESET_ALL} View Real-time Dashboard")
            print(f"{Fore.GREEN}4.{Style.RESET_ALL} View Recent Alerts")
            print(f"{Fore.GREEN}5.{Style.RESET_ALL} Generate Reports")
            print(f"{Fore.GREEN}6.{Style.RESET_ALL} Configuration")
            print(f"{Fore.GREEN}7.{Style.RESET_ALL} System Statistics")
            print(f"{Fore.RED}8.{Style.RESET_ALL} Exit")
            
            choice = input(f"\n{Fore.CYAN}Enter your choice (1-8): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.start_capture_interactive()
            elif choice == '2':
                self.stop_capture()
            elif choice == '3':
                self.show_dashboard()
            elif choice == '4':
                self.show_alerts()
            elif choice == '5':
                self.generate_reports_menu()
            elif choice == '6':
                self.show_configuration()
            elif choice == '7':
                self.show_statistics()
            elif choice == '8':
                if self.confirm_exit():
                    break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
                time.sleep(2)
    
    def start_capture_interactive(self):
        """Start packet capture with user input"""
        print(f"\n{Fore.YELLOW}Packet Capture Configuration{Style.RESET_ALL}")
        print("=" * 40)
        
        # Get available interfaces
        interfaces = PrivilegeManager.get_network_interfaces()
        
        if not interfaces:
            print("No network interfaces detected. Using auto-detection.")
            interface = "auto"
        else:
            interface = PrivilegeManager.select_interface(interfaces)
        
        print(f"\n{Fore.GREEN}Starting packet capture...{Style.RESET_ALL}")
        print(f"Interface: {interface}")
        print(f"Promiscuous mode: {config.promiscuous_mode}")
        print(f"Max packets: {config.max_packets}")
        
        # Test packet capture permissions
        print(f"\n{Fore.YELLOW}Testing packet capture permissions...{Style.RESET_ALL}")
        try:
            from privileges import test_packet_capture_permission
            if not test_packet_capture_permission():
                print(f"{Fore.RED}Packet capture permissions not available{Style.RESET_ALL}")
                print("This may limit functionality. Continuing anyway...")
            else:
                print(f"{Fore.GREEN}Packet capture permissions available{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}Could not test packet capture permissions: {e}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Press Ctrl+C to stop capture{Style.RESET_ALL}")
        
        try:
            self.packet_capture.start_capture(interface)
            self.is_running = True
            
            # Start display thread
            self.display_thread = threading.Thread(target=self._display_stats, daemon=True)
            self.display_thread.start()
            
            # Wait for capture to complete or user interrupt
            while self.packet_capture.is_running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Stopping capture...{Style.RESET_ALL}")
            self.stop_capture()
        except Exception as e:
            print(f"{Fore.RED}Error starting capture: {e}{Style.RESET_ALL}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.packet_capture.stop_capture()
        self.is_running = False
        print(f"{Fore.GREEN}Packet capture stopped.{Style.RESET_ALL}")
    
    def _display_stats(self):
        """Display real-time statistics"""
        while self.is_running:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            stats = self.packet_capture.get_statistics()
            alert_stats = self.detection_engine.get_statistics()
            
            print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
            print(f"║                    REAL-TIME STATISTICS                        ║")
            print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}Capture Statistics:{Style.RESET_ALL}")
            print(f"  Status: {Fore.GREEN}Running{Style.RESET_ALL if stats['is_running'] else Fore.RED}Stopped{Style.RESET_ALL}")
            print(f"  Packets Captured: {stats['packet_count']}")
            print(f"  Duration: {stats['duration_seconds']:.1f} seconds")
            print(f"  Packets/Second: {stats['packets_per_second']:.1f}")
            
            print(f"\n{Fore.YELLOW}Threat Detection:{Style.RESET_ALL}")
            print(f"  Total Alerts: {alert_stats['total_alerts']}")
            print(f"  Critical: {Fore.RED}{alert_stats['alerts_by_level']['critical']}{Style.RESET_ALL}")
            print(f"  High: {Fore.RED}{alert_stats['alerts_by_level']['high']}{Style.RESET_ALL}")
            print(f"  Medium: {Fore.YELLOW}{alert_stats['alerts_by_level']['medium']}{Style.RESET_ALL}")
            print(f"  Low: {Fore.GREEN}{alert_stats['alerts_by_level']['low']}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Last Updated: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Press Ctrl+C to stop capture{Style.RESET_ALL}")
            
            time.sleep(2)
    
    def show_dashboard(self):
        """Show real-time dashboard"""
        print(f"\n{Fore.CYAN}Real-time Dashboard{Style.RESET_ALL}")
        print("=" * 40)
        
        dashboard_data = self.dashboard.get_dashboard_data()
        
        print(f"\n{Fore.GREEN}Alert Summary (Last 60 Minutes):{Style.RESET_ALL}")
        print(f"  Total Alerts: {dashboard_data['total_alerts']}")
        print(f"  Critical: {Fore.RED}{dashboard_data['critical_alerts']}{Style.RESET_ALL}")
        print(f"  High: {Fore.RED}{dashboard_data['high_alerts']}{Style.RESET_ALL}")
        print(f"  Medium: {Fore.YELLOW}{dashboard_data['medium_alerts']}{Style.RESET_ALL}")
        print(f"  Low: {Fore.GREEN}{dashboard_data['low_alerts']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Top Threat Types:{Style.RESET_ALL}")
        for threat in dashboard_data['top_threats']:
            print(f"  {threat['threat_type']}: {threat['count']}")
        
        print(f"\n{Fore.CYAN}Recent Activity:{Style.RESET_ALL}")
        for activity in dashboard_data['recent_activity'][:5]:
            time_str = activity['timestamp'].split('T')[1].split('.')[0]
            print(f"  {time_str} [{activity['threat_level'].upper()}] {activity['threat_type']}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def show_alerts(self):
        """Show recent alerts"""
        print(f"\n{Fore.CYAN}Recent Alerts{Style.RESET_ALL}")
        print("=" * 40)
        
        # Get recent alerts
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=60)
        
        if not recent_alerts:
            print(f"{Fore.GREEN}No recent alerts found.{Style.RESET_ALL}")
        else:
            for alert in sorted(recent_alerts, key=lambda x: x.timestamp, reverse=True):
                color_map = {
                    "critical": Fore.RED + Style.BRIGHT,
                    "high": Fore.RED,
                    "medium": Fore.YELLOW,
                    "low": Fore.GREEN
                }
                
                color = color_map.get(alert.threat_level.value, Fore.WHITE)
                
                print(f"\n{color}[{alert.threat_level.value.upper()}] {alert.threat_type}{Style.RESET_ALL}")
                print(f"  {alert.description}")
                print(f"  Source: {alert.src_ip} -> Destination: {alert.dst_ip}")
                print(f"  Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def generate_reports_menu(self):
        """Show reports generation menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print(f"{Fore.CYAN}Generate Reports{Style.RESET_ALL}")
            print("=" * 30)
            
            print(f"\n{Fore.GREEN}1.{Style.RESET_ALL} Summary Report (Last Hour)")
            print(f"{Fore.GREEN}2.{Style.RESET_ALL} Detailed Report (Last 24 Hours)")
            print(f"{Fore.GREEN}3.{Style.RESET_ALL} Compliance Report")
            print(f"{Fore.GREEN}4.{Style.RESET_ALL} Custom Report")
            print(f"{Fore.RED}5.{Style.RESET_ALL} Back to Main Menu")
            
            choice = input(f"\n{Fore.CYAN}Enter your choice (1-5): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self._generate_summary_report()
            elif choice == '2':
                self._generate_detailed_report()
            elif choice == '3':
                self._generate_compliance_report()
            elif choice == '4':
                self._generate_custom_report()
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
                time.sleep(2)
    
    def _generate_summary_report(self):
        """Generate summary report"""
        print(f"\n{Fore.YELLOW}Generating Summary Report...{Style.RESET_ALL}")
        
        report = self.report_generator.generate_summary_report()
        filename = self.report_generator.export_report(report, "summary", "json")
        
        print(f"{Fore.GREEN}Report generated: {filename}{Style.RESET_ALL}")
        
        # Display summary
        print(f"\n{Fore.CYAN}Report Summary:{Style.RESET_ALL}")
        print(f"  Total Alerts: {report['total_alerts']}")
        print(f"  High Priority Alerts: {report['high_priority_alerts']}")
        print(f"  Timeframe: {report['timeframe']}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def _generate_detailed_report(self):
        """Generate detailed report"""
        print(f"\n{Fore.YELLOW}Generating Detailed Report...{Style.RESET_ALL}")
        
        report = self.report_generator.generate_detailed_report(hours=24)
        filename = self.report_generator.export_report(report, "detailed", "json")
        
        print(f"{Fore.GREEN}Report generated: {filename}{Style.RESET_ALL}")
        
        # Display summary
        print(f"\n{Fore.CYAN}Report Summary:{Style.RESET_ALL}")
        print(f"  Total Alerts: {report['total_alerts']}")
        print(f"  Timeframe: {report['timeframe']}")
        print(f"  Recommendations: {len(report['recommendations'])}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def _generate_compliance_report(self):
        """Generate compliance report"""
        print(f"\n{Fore.YELLOW}Generating Compliance Report...{Style.RESET_ALL}")
        
        report = self.report_generator.generate_compliance_report()
        filename = self.report_generator.export_report(report, "compliance", "json")
        
        print(f"{Fore.GREEN}Report generated: {filename}{Style.RESET_ALL}")
        
        # Display summary
        print(f"\n{Fore.CYAN}Compliance Summary:{Style.RESET_ALL}")
        print(f"  Frameworks: {', '.join(report['compliance_frameworks'])}")
        print(f"  PII-related Alerts: {report['data_protection']['alerts_with_potential_pii']}")
        print(f"  Unencrypted Protocol Alerts: {report['data_protection']['unencrypted_protocols']}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def _generate_custom_report(self):
        """Generate custom report"""
        print(f"\n{Fore.YELLOW}Custom Report Generation{Style.RESET_ALL}")
        
        try:
            hours = int(input("Enter timeframe in hours (1-168): "))
            if hours < 1 or hours > 168:
                raise ValueError
            
            report = self.report_generator.generate_detailed_report(hours=hours)
            filename = self.report_generator.export_report(report, f"custom_{hours}h", "json")
            
            print(f"{Fore.GREEN}Report generated: {filename}{Style.RESET_ALL}")
            
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number between 1 and 168.{Style.RESET_ALL}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def show_configuration(self):
        """Show current configuration"""
        print(f"\n{Fore.CYAN}Current Configuration{Style.RESET_ALL}")
        print("=" * 30)
        
        print(f"\n{Fore.GREEN}Network Settings:{Style.RESET_ALL}")
        print(f"  Interface: {config.interface}")
        print(f"  Promiscuous Mode: {config.promiscuous_mode}")
        print(f"  Max Packets: {config.max_packets}")
        
        print(f"\n{Fore.YELLOW}Threat Detection:{Style.RESET_ALL}")
        print(f"  DNS Query Threshold: {config.dns_query_threshold}/min")
        print(f"  Port Scan Threshold: {config.port_scan_threshold}/min")
        print(f"  Data Exfiltration Threshold: {config.data_exfiltration_threshold/(1024*1024):.1f}MB")
        
        print(f"\n{Fore.MAGENTA}Privacy Settings:{Style.RESET_ALL}")
        print(f"  Mask Private IPs: {config.mask_private_ips}")
        print(f"  Anonymize Data: {config.anonymize_data}")
        print(f"  Log Retention: {config.retain_logs_days} days")
        
        print(f"\n{Fore.CYAN}Compliance:{Style.RESET_ALL}")
        print(f"  Legal Frameworks: {', '.join(compliance.REGULATORY_FRAMEWORKS[:3])}...")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def show_statistics(self):
        """Show system statistics"""
        print(f"\n{Fore.CYAN}System Statistics{Style.RESET_ALL}")
        print("=" * 30)
        
        # Capture statistics
        capture_stats = self.packet_capture.get_statistics()
        print(f"\n{Fore.GREEN}Capture Engine:{Style.RESET_ALL}")
        print(f"  Status: {'Running' if capture_stats['is_running'] else 'Stopped'}")
        print(f"  Total Packets: {capture_stats['packet_count']}")
        print(f"  Buffer Size: {capture_stats['buffer_size']}")
        
        # Analysis statistics
        analysis_stats = self.packet_analyzer.get_statistics()
        print(f"\n{Fore.YELLOW}Analysis Engine:{Style.RESET_ALL}")
        print(f"  Total Connections: {analysis_stats['total_connections']}")
        print(f"  DNS Queries: {analysis_stats['dns_queries']}")
        print(f"  Data Transfers: {analysis_stats['data_transfers']}")
        
        # Detection statistics
        detection_stats = self.detection_engine.get_statistics()
        print(f"\n{Fore.MAGENTA}Threat Detection:{Style.RESET_ALL}")
        print(f"  Total Alerts: {detection_stats['total_alerts']}")
        print(f"  High Priority: {detection_stats['high_priority_count']}")
        
        # Alert statistics
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=60)
        print(f"\n{Fore.CYAN}Recent Activity (Last Hour):{Style.RESET_ALL}")
        print(f"  Alerts: {len(recent_alerts)}")
        
        input(f"\n{Fore.GREEN}Press Enter to continue...{Style.RESET_ALL}")
    
    def confirm_exit(self) -> bool:
        """Confirm exit from application"""
        print(f"\n{Fore.RED}Are you sure you want to exit?{Style.RESET_ALL}")
        print(f"All monitoring will be stopped.")
        
        choice = input("Enter 'yes' to confirm: ").strip().lower()
        return choice == 'yes'
    
    def run(self):
        """Run the console UI"""
        try:
            self.show_banner()
            self.show_main_menu()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Shutting down...{Style.RESET_ALL}")
            self.stop_capture()
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        finally:
            print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")

def main():
    """Main entry point for console UI"""
    ui = ConsoleUI()
    ui.run()

if __name__ == "__main__":
    main()
