"""
Main entry point for Network Sniffer
Coordinates all components and handles application lifecycle
"""

import sys
import os
import argparse
import signal
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from ui import ConsoleUI
from config import compliance
from privileges import PrivilegeManager, setup_privileges

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nShutting down Network Sniffer...")
    sys.exit(0)

def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux
            return os.geteuid() == 0
    except:
        return False

def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    try:
        import scapy
    except ImportError:
        missing_deps.append("scapy")
    
    try:
        import colorama
    except ImportError:
        missing_deps.append("colorama")
    
    return missing_deps

def install_dependencies():
    """Install missing dependencies"""
    import subprocess
    
    missing = check_dependencies()
    if missing:
        print("Installing missing dependencies...")
        for dep in missing:
            print(f"Installing {dep}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                print(f"✓ {dep} installed successfully")
            except subprocess.CalledProcessError:
                print(f"✗ Failed to install {dep}")
                return False
        
        print("\nAll dependencies installed successfully!")
        return True
    
    return True

def display_welcome():
    """Display welcome message and legal notice"""
    print("=" * 60)
    print("    NETWORK SNIFFER - Advanced Threat Detection System")
    print("=" * 60)
    print()
    print(compliance.LEGAL_NOTICE)
    print("=" * 60)
    print()

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="Network Sniffer - Threat Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start interactive mode
  python main.py --install-deps     # Install dependencies
  python main.py --check-privs      # Check admin privileges
  python main.py --elevate          # Auto-elevate privileges
        """
    )
    
    parser.add_argument(
        "--install-deps", 
        action="store_true",
        help="Install required dependencies"
    )
    
    parser.add_argument(
        "--check-privs", 
        action="store_true",
        help="Check administrator privileges"
    )
    
    parser.add_argument(
        "--elevate", 
        action="store_true",
        help="Attempt to elevate privileges automatically"
    )
    
    parser.add_argument(
        "--no-priv-check", 
        action="store_true",
        help="Skip administrator privilege check"
    )
    
    parser.add_argument(
        "--list-interfaces", 
        action="store_true",
        help="List available network interfaces"
    )
    
    args = parser.parse_args()
    
    # Handle command line arguments
    if args.install_deps:
        if install_dependencies():
            print("\n✓ Dependencies installed successfully!")
            print("You can now run the sniffer with: python main.py")
        else:
            print("\n✗ Failed to install some dependencies")
            print("Please install manually: pip install -r requirements.txt")
        return
    
    if args.check_privs:
        if PrivilegeManager.is_admin():
            print("Running with administrator privileges")
        else:
            print("Not running with administrator privileges")
            print("Please run as administrator/root for packet capture")
        return
    
    if args.list_interfaces:
        print("Available Network Interfaces:")
        print("=" * 50)
        
        interfaces = PrivilegeManager.get_network_interfaces()
        if not interfaces:
            print("No interfaces detected or insufficient privileges.")
        else:
            for i, interface in enumerate(interfaces, 1):
                status = "Active" if interface['active'] else "✗ Inactive"
                print(f"{i}. {interface['name']}")
                print(f"   IP: {interface['ip']}")
                print(f"   Netmask: {interface['netmask']}")
                print(f"   Status: {status}")
                print()
        return
    
    # Display welcome message
    display_welcome()
    
    # Check dependencies
    missing_deps = check_dependencies()
    if missing_deps:
        print(f"✗ Missing dependencies: {', '.join(missing_deps)}")
        print("Install with: python main.py --install-deps")
        print("Or manually: pip install -r requirements.txt")
        sys.exit(1)
    
    # Setup privileges
    if not args.no_priv_check:
        if not setup_privileges(auto_elevate=args.elevate):
            print("Exiting due to privilege requirements.")
            sys.exit(1)
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Start the console UI
        ui = ConsoleUI()
        ui.run()
        
    except KeyboardInterrupt:
        print("\n\nShutting down Network Sniffer...")
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        print("Please check your configuration and try again.")
        sys.exit(1)
    finally:
        print("Network Sniffer stopped.")

if __name__ == "__main__":
    main()
