"""
Utility functions for network sniffer
Helper functions for various operations
"""

import os
import sys
import time
import json
import hashlib
import platform
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

def get_system_info() -> Dict[str, Any]:
    """Get system information for debugging"""
    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "platform_release": platform.release(),
        "architecture": platform.architecture()[0],
        "processor": platform.processor(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "current_user": os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
        "current_directory": os.getcwd(),
        "script_directory": os.path.dirname(os.path.abspath(__file__))
    }

def format_bytes(bytes_count: int) -> str:
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535

def hash_string(data: str, algorithm: str = "sha256") -> str:
    """Hash string using specified algorithm"""
    try:
        if algorithm == "md5":
            return hashlib.md5(data.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data.encode()).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(data.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception as e:
        print(f"Error hashing data: {e}")
        return ""

def anonymize_ip(ip: str) -> str:
    """Anonymize IP address for privacy"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        if ip_obj.is_private:
            return "192.168.xxx.xxx"
        elif ip_obj.is_loopback:
            return "127.0.0.1"
        else:
            # For public IPs, mask the last octet
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
            return "xxx.xxx.xxx.xxx"
    except:
        return "xxx.xxx.xxx.xxx"

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    import re
    
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename or "unnamed"

def create_directory_if_not_exists(directory: str) -> bool:
    """Create directory if it doesn't exist"""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False

def save_json(data: Any, filename: str, directory: str = "data") -> bool:
    """Save data to JSON file"""
    try:
        if not create_directory_if_not_exists(directory):
            return False
        
        filepath = os.path.join(directory, sanitize_filename(filename))
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return True
    except Exception as e:
        print(f"Error saving JSON file: {e}")
        return False

def load_json(filename: str, directory: str = "data") -> Optional[Any]:
    """Load data from JSON file"""
    try:
        filepath = os.path.join(directory, sanitize_filename(filename))
        
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return None

def get_time_ranges() -> Dict[str, datetime]:
    """Get common time ranges for filtering"""
    now = datetime.now()
    
    return {
        "now": now,
        "1_hour_ago": now - timedelta(hours=1),
        "6_hours_ago": now - timedelta(hours=6),
        "24_hours_ago": now - timedelta(hours=24),
        "1_week_ago": now - timedelta(weeks=1),
        "1_month_ago": now - timedelta(days=30)
    }

def calculate_statistics(numbers: List[float]) -> Dict[str, float]:
    """Calculate basic statistics for a list of numbers"""
    if not numbers:
        return {
            "count": 0,
            "mean": 0,
            "median": 0,
            "min": 0,
            "max": 0,
            "sum": 0
        }
    
    numbers_sorted = sorted(numbers)
    count = len(numbers)
    mean = sum(numbers) / count
    
    if count % 2 == 0:
        median = (numbers_sorted[count//2 - 1] + numbers_sorted[count//2]) / 2
    else:
        median = numbers_sorted[count//2]
    
    return {
        "count": count,
        "mean": mean,
        "median": median,
        "min": min(numbers),
        "max": max(numbers),
        "sum": sum(numbers)
    }

def rate_limiter(calls_per_second: float):
    """Simple rate limiter decorator"""
    min_interval = 1.0 / calls_per_second
    
    def decorator(func):
        last_called = [0.0]
        
        def wrapper(*args, **kwargs):
            current_time = time.time()
            elapsed = current_time - last_called[0]
            
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            
            last_called[0] = time.time()
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def debug_print(message: str, level: str = "INFO"):
    """Debug print with timestamp and level"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def check_port_availability(port: int) -> bool:
    """Check if a port is available"""
    import socket
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result != 0  # Port is available if connection fails
    except:
        return False

def get_available_port(start_port: int = 8000, max_port: int = 9000) -> int:
    """Find an available port in a range"""
    for port in range(start_port, max_port + 1):
        if check_port_availability(port):
            return port
    return None

def cleanup_old_files(directory: str, days_old: int = 7, pattern: str = "*"):
    """Clean up old files in a directory"""
    import glob
    
    try:
        if not os.path.exists(directory):
            return
        
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        pattern_path = os.path.join(directory, pattern)
        
        for filepath in glob.glob(pattern_path):
            if os.path.getmtime(filepath) < cutoff_time:
                try:
                    os.remove(filepath)
                    debug_print(f"Deleted old file: {filepath}")
                except Exception as e:
                    debug_print(f"Error deleting file {filepath}: {e}", "ERROR")
    
    except Exception as e:
        debug_print(f"Error in cleanup: {e}", "ERROR")

def validate_config(config_dict: Dict[str, Any]) -> List[str]:
    """Validate configuration dictionary"""
    errors = []
    
    # Check required fields
    required_fields = ["interface", "max_packets", "timeout"]
    for field in required_fields:
        if field not in config_dict:
            errors.append(f"Missing required field: {field}")
    
    # Validate numeric fields
    numeric_fields = ["max_packets", "timeout", "dns_query_threshold"]
    for field in numeric_fields:
        if field in config_dict:
            try:
                value = int(config_dict[field])
                if value < 0:
                    errors.append(f"Field {field} must be positive")
            except ValueError:
                errors.append(f"Field {field} must be a number")
    
    # Validate boolean fields
    boolean_fields = ["promiscuous_mode", "enable_console_output"]
    for field in boolean_fields:
        if field in config_dict:
            if not isinstance(config_dict[field], bool):
                errors.append(f"Field {field} must be boolean")
    
    return errors

def create_backup_file(filepath: str) -> str:
    """Create a backup of a file"""
    import shutil
    
    if not os.path.exists(filepath):
        return ""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{filepath}.backup_{timestamp}"
    
    try:
        shutil.copy2(filepath, backup_path)
        return backup_path
    except Exception as e:
        debug_print(f"Error creating backup: {e}", "ERROR")
        return ""

# Performance monitoring
class PerformanceMonitor:
    """Simple performance monitoring utility"""
    
    def __init__(self):
        self.start_time = time.time()
        self.checkpoints = {}
    
    def checkpoint(self, name: str):
        """Add a performance checkpoint"""
        self.checkpoints[name] = time.time()
    
    def get_elapsed(self, from_checkpoint: str = None) -> float:
        """Get elapsed time"""
        if from_checkpoint and from_checkpoint in self.checkpoints:
            return time.time() - self.checkpoints[from_checkpoint]
        return time.time() - self.start_time
    
    def get_summary(self) -> Dict[str, float]:
        """Get performance summary"""
        summary = {"total_elapsed": self.get_elapsed()}
        
        prev_time = self.start_time
        for name, checkpoint_time in self.checkpoints.items():
            summary[f"{name}_elapsed"] = checkpoint_time - prev_time
            prev_time = checkpoint_time
        
        return summary
