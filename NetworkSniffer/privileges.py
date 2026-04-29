"""
Privilege escalation and system administration utilities
Handles administrator privilege checking and elevation
"""

import os
import sys
import subprocess
import platform
from typing import Tuple, Optional

class PrivilegeManager:
    """Manages system privileges and elevation"""
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix/Linux/macOS
                return os.geteuid() == 0
        except Exception:
            return False
    
    @staticmethod
    def get_current_user() -> str:
        """Get current username"""
        try:
            if platform.system() == "Windows":
                return os.environ.get('USERNAME', 'unknown')
            else:
                return os.environ.get('USER', 'unknown')
        except Exception:
            return "unknown"
    
    @staticmethod
    def elevate_privileges() -> bool:
        """Attempt to elevate privileges"""
        try:
            if platform.system() == "Windows":
                # On Windows, we need to restart with admin rights
                return PrivilegeManager._elevate_windows()
            else:
                # On Unix systems, we can use sudo
                return PrivilegeManager._elevate_unix()
        except Exception as e:
            print(f"Error elevating privileges: {e}")
            return False
    
    @staticmethod
    def _elevate_windows() -> bool:
        """Elevate privileges on Windows"""
        try:
            import ctypes
            import win32com.shell.shell as shell
            
            # Get the path to current Python executable
            python_exe = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            
            # Build the command
            params = ' '.join([python_exe, script_path] + sys.argv[1:])
            
            # Request elevation
            result = shell.ShellExecuteEx(
                nShow=1,  # SW_NORMAL
                fMask=64,  # SEE_MASK_NOCLOSEPROCESS
                lpVerb="runas",  # Request elevation
                lpFile=python_exe,
                lpParameters=params
            )
            
            return result['hInstApp'] > 32
            
        except ImportError:
            # Fallback method using ctypes
            try:
                import ctypes
                from ctypes import wintypes
                
                # ShellExecuteW function
                shell32 = ctypes.windll.shell32
                ShellExecuteW = shell32.ShellExecuteW
                ShellExecuteW.argtypes = [
                    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.INT
                ]
                ShellExecuteW.restype = wintypes.HINSTANCE
                
                # Get paths
                python_exe = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                params = ' '.join([python_exe, script_path] + sys.argv[1:])
                
                # Execute with elevation
                result = ShellExecuteW(
                    None, "runas", python_exe, params, None, 1
                )
                
                return result > 32
                
            except Exception as e:
                print(f"Windows elevation failed: {e}")
                return False
        except Exception as e:
            print(f"Windows elevation error: {e}")
            return False
    
    @staticmethod
    def _elevate_unix() -> bool:
        """Elevate privileges on Unix systems"""
        try:
            # Check if we're already running as root
            if os.geteuid() == 0:
                return True
            
            # Re-run with sudo
            script_path = os.path.abspath(sys.argv[0])
            params = ' '.join([script_path] + sys.argv[1:])
            
            # Use sudo to re-run the script
            cmd = f"sudo python {params}"
            
            # Execute and exit current process
            os.execvp("sudo", ["sudo", "python"] + sys.argv)
            
            return True
            
        except Exception as e:
            print(f"Unix elevation failed: {e}")
            return False
    
    @staticmethod
    def check_and_request_elevation(auto_elevate: bool = False) -> Tuple[bool, str]:
        """Check privileges and optionally request elevation"""
        current_user = PrivilegeManager.get_current_user()
        
        if PrivilegeManager.is_admin():
            return True, f"Running as administrator: {current_user}"
        
        if not auto_elevate:
            return False, f"Running as regular user: {current_user}"
        
        print(f"Current user: {current_user}")
        print("Administrator privileges required for packet capture.")
        
        if platform.system() == "Windows":
            print("Attempting to elevate privileges...")
            if PrivilegeManager.elevate_privileges():
                return True, "Successfully elevated privileges"
            else:
                return False, "Failed to elevate privileges"
        else:
            print("Please run with sudo: sudo python main.py")
            return False, "Manual elevation required"
    
    @staticmethod
    def get_network_interfaces() -> list:
        """Get available network interfaces"""
        try:
            import netifaces
            
            interfaces = []
            for interface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            interfaces.append({
                                'name': interface,
                                'ip': addr['addr'],
                                'netmask': addr.get('netmask', ''),
                                'active': True
                            })
                except KeyError:
                    continue
            
            return interfaces
            
        except ImportError:
            # Fallback method
            try:
                import socket
                
                # Get hostname and try to get local IP
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                return [
                    {
                        'name': 'default',
                        'ip': local_ip,
                        'netmask': '255.255.255.0',
                        'active': True
                    }
                ]
                
            except Exception:
                return [
                    {
                        'name': 'auto',
                        'ip': 'unknown',
                        'netmask': 'unknown',
                        'active': True
                    }
                ]
    
    @staticmethod
    def select_interface(interfaces: list) -> str:
        """Let user select network interface"""
        if not interfaces:
            return "auto"
        
        if len(interfaces) == 1:
            return interfaces[0]['name']
        
        print("\nAvailable Network Interfaces:")
        print("=" * 50)
        
        for i, interface in enumerate(interfaces, 1):
            status = "✓ Active" if interface['active'] else "✗ Inactive"
            print(f"{i}. {interface['name']} ({interface['ip']}) - {status}")
        
        print(f"{len(interfaces) + 1}. Auto-detect")
        
        while True:
            try:
                choice = int(input(f"\nSelect interface (1-{len(interfaces) + 1}): "))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]['name']
                elif choice == len(interfaces) + 1:
                    return "auto"
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")

def setup_privileges(auto_elevate: bool = False) -> bool:
    """Setup privileges for the application"""
    print("Checking system privileges...")
    
    # Check current privileges
    has_admin, message = PrivilegeManager.check_and_request_elevation(auto_elevate)
    print(f"Status: {message}")
    
    if not has_admin:
        print("\n⚠️  WARNING: Limited functionality without administrator privileges")
        print("Features that may not work:")
        print("  • Packet capture")
        print("  • Network interface access")
        print("  • Deep packet inspection")
        print("\nOptions:")
        print("  1. Continue with limited functionality")
        print("  2. Exit and run as administrator")
        print("  3. Attempt privilege elevation")
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == '2':
            print("Please run this application as administrator/root")
            return False
        elif choice == '3':
            if PrivilegeManager.elevate_privileges():
                print("Privilege elevation successful!")
                return True
            else:
                print("Privilege elevation failed. Continuing with limited functionality.")
        elif choice != '1':
            print("Invalid choice. Continuing with limited functionality.")
    
    return True

def test_packet_capture_permission() -> bool:
        """Test if packet capture permissions are available"""
        try:
            import scapy.all as scapy
            
            # Try to create a socket (basic test)
            test_socket = scapy.conf.L2socket()
            test_socket.close()
            return True
            
        except Exception as e:
            print(f"Packet capture permission test failed: {e}")
            return False
