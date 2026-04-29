"""
Reporting and logging system for network sniffer
Handles alert generation, logging, and report creation
"""

import json
import logging
import threading
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import asdict

from core import PacketInfo, ThreatAlert
from config import config, compliance
from detection import ThreatDetectionEngine

class AlertManager:
    """Manages threat alerts and notifications"""
    
    def __init__(self):
        self.alerts: List[ThreatAlert] = []
        self.alert_callbacks: List[callable] = []
        self.alert_lock = threading.Lock()
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        # Configure root logger
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(config.log_file),
                logging.StreamHandler() if config.enable_console_output else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Log legal notice
        self.logger.info("=" * 50)
        self.logger.info(compliance.LEGAL_NOTICE)
        self.logger.info("=" * 50)
    
    def add_alert(self, alert: ThreatAlert):
        """Add a new threat alert"""
        with self.alert_lock:
            self.alerts.append(alert)
            
            # Log the alert
            log_message = (
                f"[{alert.threat_level.value.upper()}] {alert.threat_type}: "
                f"{alert.description} (Source: {alert.src_ip}, Dest: {alert.dst_ip})"
            )
            
            if alert.threat_level.value == "critical":
                self.logger.critical(log_message)
            elif alert.threat_level.value == "high":
                self.logger.error(log_message)
            elif alert.threat_level.value == "medium":
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
            
            # Call alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
    
    def add_alert_callback(self, callback: callable):
        """Add a callback function for new alerts"""
        self.alert_callbacks.append(callback)
    
    def get_recent_alerts(self, minutes: int = 60) -> List[ThreatAlert]:
        """Get alerts from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        with self.alert_lock:
            return [
                alert for alert in self.alerts
                if alert.timestamp >= cutoff_time
            ]
    
    def get_alerts_by_level(self, level: str) -> List[ThreatAlert]:
        """Get alerts by threat level"""
        with self.alert_lock:
            return [
                alert for alert in self.alerts
                if alert.threat_level.value == level
            ]
    
    def clear_old_alerts(self, days: int = 7):
        """Clear alerts older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with self.alert_lock:
            original_count = len(self.alerts)
            self.alerts = [
                alert for alert in self.alerts
                if alert.timestamp >= cutoff_date
            ]
            
            cleared_count = original_count - len(self.alerts)
            if cleared_count > 0:
                self.logger.info(f"Cleared {cleared_count} old alerts")

class ReportGenerator:
    """Generates various types of security reports"""
    
    def __init__(self, alert_manager: AlertManager, detection_engine: ThreatDetectionEngine):
        self.alert_manager = alert_manager
        self.detection_engine = detection_engine
    
    def generate_summary_report(self) -> Dict:
        """Generate a summary report of current security status"""
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=60)
        
        return {
            "report_type": "summary",
            "generated_at": datetime.now().isoformat(),
            "timeframe": "last_60_minutes",
            "total_alerts": len(recent_alerts),
            "alerts_by_level": {
                level.value: len([a for a in recent_alerts if a.threat_level.value == level])
                for level in ["low", "medium", "high", "critical"]
            },
            "alerts_by_type": self._count_alerts_by_type(recent_alerts),
            "top_source_ips": self._get_top_source_ips(recent_alerts, limit=10),
            "top_destination_ips": self._get_top_destination_ips(recent_alerts, limit=10),
            "high_priority_alerts": len([
                a for a in recent_alerts 
                if a.threat_level.value in ["high", "critical"]
            ])
        }
    
    def generate_detailed_report(self, hours: int = 24) -> Dict:
        """Generate a detailed security report"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.alert_manager.alert_lock:
            relevant_alerts = [
                alert for alert in self.alert_manager.alerts
                if alert.timestamp >= cutoff_time
            ]
        
        return {
            "report_type": "detailed",
            "generated_at": datetime.now().isoformat(),
            "timeframe": f"last_{hours}_hours",
            "total_alerts": len(relevant_alerts),
            "alerts_by_level": {
                level.value: len([a for a in relevant_alerts if a.threat_level.value == level])
                for level in ["low", "medium", "high", "critical"]
            },
            "alerts_by_type": self._count_alerts_by_type(relevant_alerts),
            "timeline": self._generate_alert_timeline(relevant_alerts),
            "top_source_ips": self._get_top_source_ips(relevant_alerts),
            "top_destination_ips": self._get_top_destination_ips(relevant_alerts),
            "threat_patterns": self._analyze_threat_patterns(relevant_alerts),
            "recommendations": self._generate_recommendations(relevant_alerts)
        }
    
    def generate_compliance_report(self) -> Dict:
        """Generate compliance-focused report"""
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=1440)  # 24 hours
        
        return {
            "report_type": "compliance",
            "generated_at": datetime.now().isoformat(),
            "timeframe": "last_24_hours",
            "compliance_frameworks": compliance.REGULATORY_FRAMEWORKS,
            "data_protection": {
                "alerts_with_potential_pii": len([
                    a for a in recent_alerts 
                    if "sensitive" in a.threat_type.lower() or "data" in a.threat_type.lower()
                ]),
                "unencrypted_protocols": len([
                    a for a in recent_alerts 
                    if "unencrypted" in a.threat_type.lower()
                ])
            },
            "privacy_metrics": {
                "ips_masked": config.mask_private_ips,
                "data_anonymized": config.anonymize_data,
                "log_retention_days": config.retain_logs_days
            },
            "audit_trail": {
                "total_log_entries": len(recent_alerts),
                "critical_events": len([
                    a for a in recent_alerts if a.threat_level.value == "critical"
                ]),
                "high_risk_events": len([
                    a for a in recent_alerts if a.threat_level.value == "high"
                ])
            }
        }
    
    def _count_alerts_by_type(self, alerts: List[ThreatAlert]) -> Dict[str, int]:
        """Count alerts by type"""
        type_counts = {}
        for alert in alerts:
            type_counts[alert.threat_type] = type_counts.get(alert.threat_type, 0) + 1
        return type_counts
    
    def _get_top_source_ips(self, alerts: List[ThreatAlert], limit: int = 10) -> List[Dict]:
        """Get top source IPs from alerts"""
        ip_counts = {}
        for alert in alerts:
            ip_counts[alert.src_ip] = ip_counts.get(alert.src_ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "alert_count": count} for ip, count in sorted_ips[:limit]]
    
    def _get_top_destination_ips(self, alerts: List[ThreatAlert], limit: int = 10) -> List[Dict]:
        """Get top destination IPs from alerts"""
        ip_counts = {}
        for alert in alerts:
            ip_counts[alert.dst_ip] = ip_counts.get(alert.dst_ip, 0) + 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "alert_count": count} for ip, count in sorted_ips[:limit]]
    
    def _generate_alert_timeline(self, alerts: List[ThreatAlert]) -> List[Dict]:
        """Generate timeline of alerts"""
        timeline = []
        for alert in sorted(alerts, key=lambda x: x.timestamp):
            timeline.append({
                "timestamp": alert.timestamp.isoformat(),
                "threat_type": alert.threat_type,
                "threat_level": alert.threat_level.value,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "description": alert.description
            })
        return timeline
    
    def _analyze_threat_patterns(self, alerts: List[ThreatAlert]) -> Dict:
        """Analyze patterns in threats"""
        patterns = {
            "repeated_sources": {},
            "time_patterns": {},
            "protocol_patterns": {}
        }
        
        # Analyze repeated sources
        for alert in alerts:
            patterns["repeated_sources"][alert.src_ip] = \
                patterns["repeated_sources"].get(alert.src_ip, 0) + 1
        
        # Analyze time patterns
        for alert in alerts:
            hour = alert.timestamp.hour
            patterns["time_patterns"][hour] = \
                patterns["time_patterns"].get(hour, 0) + 1
        
        return patterns
    
    def _generate_recommendations(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate security recommendations based on alerts"""
        recommendations = []
        
        # Check for specific alert types
        alert_types = [alert.threat_type for alert in alerts]
        
        if "Brute Force Attack" in alert_types:
            recommendations.append(
                "Implement account lockout policies and multi-factor authentication"
            )
        
        if "Unencrypted Protocol" in alert_types:
            recommendations.append(
                "Migrate sensitive services to encrypted protocols (HTTPS, SSH, SFTP)"
            )
        
        if "C2 Communication" in alert_types:
            recommendations.append(
                "Investigate potential malware infections and implement network segmentation"
            )
        
        if "Sensitive Data Leakage" in alert_types:
            recommendations.append(
                "Implement data loss prevention (DLP) solutions and encrypt sensitive data"
            )
        
        if "Port Scanning" in alert_types:
            recommendations.append(
                "Configure firewall rules and implement intrusion detection systems"
            )
        
        # General recommendations
        if len(alerts) > 50:
            recommendations.append(
                "Consider implementing a Security Information and Event Management (SIEM) system"
            )
        
        return recommendations
    
    def export_report(self, report: Dict, filename: str, format: str = "json"):
        """Export report to file"""
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_dir}/{filename}_{timestamp}.{format}"
        
        if format == "json":
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        elif format == "csv":
            # Convert to CSV format (simplified)
            import csv
            with open(filename, 'w', newline='') as f:
                if "timeline" in report:
                    writer = csv.DictWriter(f, fieldnames=[
                        "timestamp", "threat_type", "threat_level", 
                        "src_ip", "dst_ip", "description"
                    ])
                    writer.writeheader()
                    writer.writerows(report["timeline"])
        
        return filename

class Dashboard:
    """Real-time dashboard for monitoring"""
    
    def __init__(self, alert_manager: AlertManager, detection_engine: ThreatDetectionEngine):
        self.alert_manager = alert_manager
        self.detection_engine = detection_engine
        self.update_callbacks = []
    
    def get_dashboard_data(self) -> Dict:
        """Get current dashboard data"""
        recent_alerts = self.alert_manager.get_recent_alerts(minutes=60)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_alerts": len(recent_alerts),
            "critical_alerts": len([a for a in recent_alerts if a.threat_level.value == "critical"]),
            "high_alerts": len([a for a in recent_alerts if a.threat_level.value == "high"]),
            "medium_alerts": len([a for a in recent_alerts if a.threat_level.value == "medium"]),
            "low_alerts": len([a for a in recent_alerts if a.threat_level.value == "low"]),
            "top_threats": self._get_top_threats(recent_alerts),
            "recent_activity": self._get_recent_activity(recent_alerts, limit=10)
        }
    
    def _get_top_threats(self, alerts: List[ThreatAlert], limit: int = 5) -> List[Dict]:
        """Get top threat types"""
        threat_counts = {}
        for alert in alerts:
            threat_counts[alert.threat_type] = threat_counts.get(alert.threat_type, 0) + 1
        
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"threat_type": threat, "count": count} for threat, count in sorted_threats[:limit]]
    
    def _get_recent_activity(self, alerts: List[ThreatAlert], limit: int = 10) -> List[Dict]:
        """Get recent alert activity"""
        recent = sorted(alerts, key=lambda x: x.timestamp, reverse=True)[:limit]
        
        return [
            {
                "timestamp": alert.timestamp.isoformat(),
                "threat_type": alert.threat_type,
                "threat_level": alert.threat_level.value,
                "src_ip": alert.src_ip,
                "description": alert.description
            }
            for alert in recent
        ]
    
    def register_update_callback(self, callback: callable):
        """Register callback for dashboard updates"""
        self.update_callbacks.append(callback)
    
    def notify_update(self):
        """Notify all registered callbacks of dashboard update"""
        for callback in self.update_callbacks:
            try:
                callback(self.get_dashboard_data())
            except Exception as e:
                print(f"Error in dashboard update callback: {e}")
