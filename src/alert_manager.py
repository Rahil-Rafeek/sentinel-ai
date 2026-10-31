"""
Sentinel AI — Alert Management Service
Orchestrates alert lifecycles, de-duplication, analyst workflows,
status updates, and CSV exports with SQLite persistence.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
import logging

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.storage import (
    init_database,
    insert_alert,
    get_alerts,
    get_alert_by_id,
    update_alert,
    get_alert_stats,
    clear_all_alerts
)
from src.severity import calculate_severity, SEVERITY_COLORS

logger = logging.getLogger("sentinel.alert_manager")


class AlertManager:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path
        if self.db_path:
            init_database(self.db_path)
        else:
            init_database()

    def process_and_create_alert(self, detection: Dict[str, Any]) -> Optional[str]:
        """
        Evaluates detection result, assesses multi-factor severity,
        de-duplicates against recent open alerts, and persists to SQLite.
        """
        category = detection.get("category", "General Anomaly")
        if category == "Benign" or not detection.get("is_threat", True):
            return None

        src_ip = detection.get("src_ip", "UNKNOWN")
        dst_ip = detection.get("dst_ip", "UNKNOWN")
        dst_port = int(detection.get("dst_port", 0))
        confidence = float(detection.get("confidence", 0.85))
        bytes_transferred = int(detection.get("bytes_sent", 0))

        # Multi-factor severity calculation
        severity, priority = calculate_severity(
            threat_category=category,
            confidence=confidence,
            rule_matches_count=detection.get("rule_matches_count", 1),
            dst_port=dst_port,
            bytes_transferred=bytes_transferred
        )

        alert_payload = {
            "timestamp": detection.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "protocol": detection.get("protocol", "TCP"),
            "category": category,
            "severity": severity,
            "priority": priority,
            "detection_method": detection.get("detection_method", "Rule-Based Engine"),
            "confidence": confidence,
            "status": "Open",
            "evidence": detection.get("evidence", "Anomalous traffic signature identified."),
            "recommended_action": detection.get("recommended_action", "Investigate endpoint and enforce security controls.")
        }

        if self.db_path:
            return insert_alert(alert_payload, db_path=self.db_path)
        return insert_alert(alert_payload)

    def get_filtered_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 500
    ) -> pd.DataFrame:
        """Returns filtered alerts as a formatted Pandas DataFrame."""
        if self.db_path:
            alerts = get_alerts(self.db_path, status, severity, category, search_query, limit)
        else:
            alerts = get_alerts(status_filter=status, severity_filter=severity, category_filter=category, search_query=search_query, limit=limit)

        if not alerts:
            return pd.DataFrame()

        df = pd.DataFrame(alerts)
        return df

    def get_statistics(self) -> Dict[str, Any]:
        """Returns overview alert metrics."""
        if self.db_path:
            return get_alert_stats(self.db_path)
        return get_alert_stats()

    def update_alert_status(
        self,
        alert_id: str,
        new_status: Optional[str] = None,
        analyst_notes: Optional[str] = None,
        resolution_comment: Optional[str] = None
    ) -> bool:
        """Updates alert metadata with analyst remarks."""
        if self.db_path:
            return update_alert(alert_id, new_status, analyst_notes, resolution_comment, self.db_path)
        return update_alert(alert_id, new_status, analyst_notes, resolution_comment)

    def export_csv(self, df: pd.DataFrame) -> bytes:
        """Serializes alert records to CSV byte buffer for download."""
        if df.empty:
            return b"No alerts found\n"
        return df.to_csv(index=False).encode("utf-8")

    def seed_initial_demo_alerts(self) -> int:
        """
        Seeds deterministic demo alerts if database is currently empty.
        Ensures immediate SOC readiness on initial startup.
        """
        stats = self.get_statistics()
        if stats.get("total_alerts", 0) > 0:
            return 0  # Already has alerts

        demo_alerts = [
            {
                "timestamp": "2026-10-26 08:34:12",
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.12",
                "destination_port": 22,
                "protocol": "TCP",
                "category": "Brute-Force Login",
                "severity": "Critical",
                "priority": 1,
                "detection_method": "Rule-Based Engine (Sliding Window)",
                "confidence": 0.96,
                "status": "Open",
                "evidence": "Observed 14 consecutive failed SSH authentication attempts within 120s window. Threshold is 5.",
                "recommended_action": "Quarantine IP 192.168.1.105 on edge firewall. Verify root password lockout."
            },
            {
                "timestamp": "2026-10-26 09:12:45",
                "source_ip": "192.168.1.189",
                "destination_ip": "10.0.0.15",
                "destination_port": 1433,
                "protocol": "TCP",
                "category": "Port Scanning",
                "severity": "High",
                "priority": 2,
                "detection_method": "Hybrid (ML + Recon Rule)",
                "confidence": 0.91,
                "status": "Investigating",
                "evidence": "Host contacted 22 distinct destination ports across 45 seconds using SYN probe patterns.",
                "recommended_action": "Apply rate-limiting on ingress subnet. Inspect exposed SQL and RDP ports on target 10.0.0.15."
            },
            {
                "timestamp": "2026-10-26 10:05:01",
                "source_ip": "192.168.1.220",
                "destination_ip": "10.0.0.5",
                "destination_port": 443,
                "protocol": "TCP",
                "category": "Abnormally High Traffic",
                "severity": "Critical",
                "priority": 1,
                "detection_method": "ML Model (Random Forest)",
                "confidence": 0.98,
                "status": "Open",
                "evidence": "Traffic burst of 12,450 packets in 2.1 seconds (5,928 pkts/s, 7.8 MB/s throughput). Threshold: 2000 pkts/s.",
                "recommended_action": "Engage upstream DDoS mitigation scrubbing. Check web front-end socket pool saturation."
            },
            {
                "timestamp": "2026-10-26 10:45:22",
                "source_ip": "10.0.0.45",
                "destination_ip": "198.51.100.99",
                "destination_port": 443,
                "protocol": "TCP",
                "category": "Suspicious User Behaviour",
                "severity": "Critical",
                "priority": 1,
                "detection_method": "Rule-Based Engine (Exfiltration)",
                "confidence": 0.94,
                "status": "Open",
                "evidence": "Transferred 78.4 MB outbound data to external IP following unauthorized request to '/api/v1/dump'.",
                "recommended_action": "Revoke database access token for service account. Isolate host 10.0.0.45 and initiate forensic capture."
            },
            {
                "timestamp": "2026-10-26 11:02:18",
                "source_ip": "192.168.1.114",
                "destination_ip": "185.220.101.5",
                "destination_port": 80,
                "protocol": "TCP",
                "category": "Malicious URL/Indicator",
                "severity": "High",
                "priority": 2,
                "detection_method": "Threat Intelligence Heuristic",
                "confidence": 0.93,
                "status": "Resolved",
                "evidence": "Destination matches known Tor/C2 exit relay indicator 185.220.101.5. URL contained high-entropy payload token.",
                "recommended_action": "Sinkholed destination IP on internal DNS resolver. Verified endpoint AV scan clean."
            }
        ]

        inserted = 0
        for alert in demo_alerts:
            if self.db_path:
                insert_alert(alert, self.db_path)
            else:
                insert_alert(alert)
            inserted += 1

        return inserted
