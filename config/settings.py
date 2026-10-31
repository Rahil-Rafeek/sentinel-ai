"""
Sentinel AI — Configuration & Settings Module
Defines system constants, threat thresholds, file paths, and default configurations.
"""

from pathlib import Path
from typing import Dict, Any, List

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
MODELS_DIR = BASE_DIR / "models"
SRC_DIR = BASE_DIR / "src"
ASSETS_DIR = BASE_DIR / "assets"
DB_PATH = BASE_DIR / "sentinel_alerts.db"

# Ensure directories exist
for p in [SAMPLE_DATA_DIR, MODELS_DIR, ASSETS_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# Threat Categories
THREAT_CATEGORIES = [
    "Benign",
    "Brute-Force Login",
    "Port Scanning",
    "Abnormally High Traffic",
    "Suspicious User Behaviour",
    "Malicious URL/Indicator"
]

# Severity Levels
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

# Alert Statuses
ALERT_STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]

# Detection Thresholds (Configurable via UI or Config)
DEFAULT_DETECTION_THRESHOLDS: Dict[str, Any] = {
    # 1. Brute-Force Login Rule
    "failed_login_threshold": 5,        # 5 or more failed logins
    "failed_login_window_seconds": 300, # within 5 minutes (300 sec)

    # 2. Port Scanning Rule
    "port_scan_port_threshold": 8,      # 8 or more distinct destination ports
    "port_scan_window_seconds": 60,     # within 60 seconds

    # 3. Abnormally High Traffic Rule
    "packet_rate_threshold": 2000.0,    # packets per second
    "byte_rate_threshold": 5_000_000.0, # bytes per second (5 MB/s)
    "traffic_zscore_threshold": 3.0,    # standard deviations above mean

    # 4. Suspicious User Behaviour Rule
    "exfiltration_bytes_threshold": 25_000_000, # 25 MB single transfer
    "outbound_ratio_threshold": 10.0,           # bytes sent / bytes received ratio
    "sensitive_endpoints": [
        "/admin",
        "/api/v1/dump",
        "/backup.tar.gz",
        "/etc/passwd",
        "/.env",
        "/db_export",
        "/actuator/env",
        "/wp-login.php"
    ],

    # 5. Malicious URL/Indicator Rule
    "url_entropy_threshold": 4.1,       # Shannon entropy cutoff
    "suspicious_url_keywords": [
        "login-verify",
        "update-account",
        "secure-banking",
        "phish",
        "malware",
        "payload",
        "c2-beacon",
        "credential-harvest",
        ".onion",
        "exploit"
    ],
    "suspicious_tlds": [".xyz", ".top", ".ru", ".tk", ".onion", ".click", ".bid"]
}

# Known Threat Intelligence Indicators (Sample IOCs for local matching)
KNOWN_MALICIOUS_INDICATORS = {
    "ips": [
        "198.51.100.45",
        "203.0.113.195",
        "185.220.101.5",
        "45.154.255.89",
        "194.26.29.112"
    ],
    "domains": [
        "secure-auth-update.xyz",
        "login-appleid-verify.top",
        "crypto-bonus-drop.click",
        "c2-direct-beacon.ru",
        "cloud-telemetry-sink.net"
    ],
    "cves": {
        "Brute-Force Login": ["CVE-2023-48795 (Terrapin)", "CWE-307"],
        "Port Scanning": ["MITRE ATT&CK T1046 (Network Service Discovery)"],
        "Abnormally High Traffic": ["MITRE ATT&CK T1498 (Network Denial of Service)"],
        "Suspicious User Behaviour": ["MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)"],
        "Malicious URL/Indicator": ["MITRE ATT&CK T1566 (Phishing)", "MITRE ATT&CK T1204"]
    }
}

# Column Mapping Defaults for input data normalization
STANDARD_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration_sec",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "failed_login_count",
    "requested_resource",
    "user_agent"
]

COLUMN_SYNONYMS = {
    "timestamp": ["timestamp", "time", "date", "event_time", "flow_start", "Timestamp"],
    "src_ip": ["src_ip", "source_ip", "srcip", "Source IP", "src_addr", "ip_src"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "dstip", "Destination IP", "dst_addr", "ip_dst"],
    "src_port": ["src_port", "source_port", "srcport", "Source Port", "sport"],
    "dst_port": ["dst_port", "dest_port", "destination_port", "dstport", "Destination Port", "dport"],
    "protocol": ["protocol", "proto", "Protocol", "ip_proto"],
    "duration_sec": ["duration_sec", "duration", "flow_duration", "Flow Duration", "elapsed_sec"],
    "bytes_sent": ["bytes_sent", "bytes_out", "orig_bytes", "Tot Bytes Out", "src_bytes", "sent_bytes"],
    "bytes_received": ["bytes_received", "bytes_in", "resp_bytes", "Tot Bytes In", "dst_bytes", "recv_bytes"],
    "packets_sent": ["packets_sent", "pkts_sent", "orig_pkts", "Total Fwd Packets", "sent_pkts"],
    "packets_received": ["packets_received", "pkts_received", "resp_pkts", "Total Bwd Packets", "recv_pkts"],
    "failed_login_count": ["failed_login_count", "failed_logins", "login_fails", "auth_failures"],
    "requested_resource": ["requested_resource", "url", "uri", "path", "resource", "target_url"],
    "user_agent": ["user_agent", "useragent", "http_user_agent", "client_ua"]
}
