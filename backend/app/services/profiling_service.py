import re
import pandas as pd
import numpy as np
from typing import Any

SEMANTIC_FIELD_PATTERNS = {
    "timestamp": {
        "patterns": [r"^time(stamp)?$", r"^date(time)?$", r"^flow_start$", r"^ts$", r"^event_time$"],
        "required_for": ["Time-Series Ingress Analytics", "Sliding-Window Brute Force", "Port Scan Velocity"],
        "explanation": "Timestamp coordinates temporal detection windows and ingress activity charts."
    },
    "src_ip": {
        "patterns": [r"^src_?ip$", r"^source_?ip$", r"^orig_?ip$", r"^client_?ip$", r"^saddr$", r"^origin$"],
        "required_for": ["Attacker Quarantine", "Port Scan Tracking", "Network Topology"],
        "explanation": "Identifies the source host or client endpoint initiating the network connection."
    },
    "dst_ip": {
        "patterns": [r"^dst_?ip$", r"^dest_?ip$", r"^destination_?ip$", r"^target_?ip$", r"^server_?ip$", r"^daddr$"],
        "required_for": ["Target Vulnerability Analysis", "Network Topology Graph"],
        "explanation": "Identifies the destination infrastructure, server, or target endpoint."
    },
    "src_port": {
        "patterns": [r"^src_?port$", r"^source_?port$", r"^sport$", r"^orig_?port$"],
        "required_for": ["Flow Correlation", "Ephemeral Port Analysis"],
        "explanation": "Client source port assigned to outbound socket session."
    },
    "dst_port": {
        "patterns": [r"^dst_?port$", r"^dest_?port$", r"^destination_?port$", r"^target_?port$", r"^dport$"],
        "required_for": ["Port Scanning Detection", "Targeted Service Histogram"],
        "explanation": "Target service port (e.g., 22 for SSH, 80/443 for Web, 1433 for SQL)."
    },
    "protocol": {
        "patterns": [r"^proto(col)?$", r"^transport$", r"^ip_proto$"],
        "required_for": ["L4 Vector Attribution (TCP/UDP/ICMP)"],
        "explanation": "Network transport protocol layer."
    },
    "packet_count": {
        "patterns": [r"^tot(al)?_?pkts?$", r"^packets?$", r"^pkts?$", r"^packet_?count$"],
        "required_for": ["Volumetric Flood Detection", "DDoS Ingress Metrics"],
        "explanation": "Total number of network frames or packets transmitted."
    },
    "byte_count": {
        "patterns": [r"^tot(al)?_?bytes?$", r"^bytes?$", r"^byte_?count$", r"^vol_?bytes?$", r"^bytes_?transferred$"],
        "required_for": ["Data Exfiltration Detection", "Throughput Profiling"],
        "explanation": "Cumulative payload and frame volume in bytes."
    },
    "duration": {
        "patterns": [r"^duration(_?sec)?$", r"^dur$", r"^flow_?duration$", r"^elapsed$"],
        "required_for": ["Persistent C2 Beaconing", "Slow-and-Low Probe Detection"],
        "explanation": "Session or flow elapsed duration in seconds."
    },
    "login_failures": {
        "patterns": [r"^failed_?logins?$", r"^login_?failures?$", r"^failed_?attempts?$", r"^auth_?fail_?count$"],
        "required_for": ["Brute-Force Login Detection"],
        "explanation": "Count of consecutive failed authentication challenges."
    },
    "url": {
        "patterns": [r"^url$", r"^uri$", r"^domain$", r"^host$", r"^target_?url$", r"^query_?string$"],
        "required_for": ["Malicious URL & Lexical Entropy Detector"],
        "explanation": "Uniform Resource Identifier or target web hostname."
    },
    "user": {
        "patterns": [r"^user(name)?$", r"^account$", r"^identity$", r"^login_?id$"],
        "required_for": ["Account Hijacking", "User Behavior Analytics"],
        "explanation": "Targeted username or corporate identity."
    },
    "label": {
        "patterns": [r"^label$", r"^attack$", r"^threat$", r"^category$", r"^class$", r"^is_?attack$", r"^attack_?class$"],
        "required_for": ["Supervised Machine Learning Training & Evaluation"],
        "explanation": "Ground-truth benchmark label for supervised model validation."
    }
}

def infer_column_mappings(columns: list[str]) -> tuple[dict[str, str | None], list[dict[str, Any]]]:
    """
    Intelligently inspect column headers and match them with semantic roles using regex & heuristics.
    """
    suggested_mapping: dict[str, str | None] = {}
    mapping_details: list[dict[str, Any]] = []
    assigned_columns = set()

    for target_field, meta in SEMANTIC_FIELD_PATTERNS.items():
        best_match = None
        best_confidence = 0.0

        for col in columns:
            clean_col = col.lower().strip()
            # Test exact or regex pattern match
            for pat in meta["patterns"]:
                if re.search(pat, clean_col):
                    best_match = col
                    best_confidence = 0.95
                    break
            if best_match:
                break

            # Fallback substring match
            if target_field.replace("_", "") in clean_col.replace("_", ""):
                best_match = col
                best_confidence = 0.75
                break

        if best_match and best_match not in assigned_columns:
            suggested_mapping[target_field] = best_match
            assigned_columns.add(best_match)
        else:
            suggested_mapping[target_field] = None
            best_confidence = 0.0

        mapping_details.append({
            "target_field": target_field,
            "source_column": suggested_mapping[target_field],
            "confidence": best_confidence,
            "explanation": meta["explanation"],
            "required_for": meta["required_for"]
        })

    return suggested_mapping, mapping_details

def assess_compatibility(mapping: dict[str, str | None], df: pd.DataFrame) -> tuple[str, list[str]]:
    """
    Determine whether a dataset is:
    - cybersecurity_compatible: has sufficient network/auth/threat indicators
    - partially_compatible: has some fields (e.g. URLs only or auth logs only)
    - general_tabular: general data suitable for statistical outlier profiling
    - invalid: empty or unprocessable
    """
    if df.empty or len(df.columns) == 0:
        return "invalid", ["Dataset contains 0 rows or columns."]

    reasons = []
    has_network = bool(mapping.get("src_ip") and (mapping.get("dst_port") or mapping.get("dst_ip")))
    has_traffic = bool(mapping.get("packet_count") or mapping.get("byte_count"))
    has_auth = bool(mapping.get("login_failures") or mapping.get("user"))
    has_url = bool(mapping.get("url"))
    has_label = bool(mapping.get("label"))

    if has_network and (has_traffic or has_auth or has_label):
        reasons.append("Complete network flow telemetry detected (endpoints, volumes, or auth indicators).")
        reasons.append("All 5 modular cybersecurity detectors and ML classification pipelines are supported.")
        return "cybersecurity_compatible", reasons

    supported_modules = []
    if has_auth:
        supported_modules.append("Brute-Force Login Detector")
    if has_network and mapping.get("dst_port"):
        supported_modules.append("Port Scan Detector")
    if has_traffic:
        supported_modules.append("Traffic Volume Anomaly Detector")
    if has_url:
        supported_modules.append("Malicious URL / C2 Detector")
    if has_label:
        supported_modules.append("Supervised Model Evaluation")

    if supported_modules:
        reasons.append(f"Partial telemetry detected. Active detectors: {', '.join(supported_modules)}.")
        missing = [k for k, v in mapping.items() if not v and k in ['src_ip', 'dst_port', 'packet_count', 'url']]
        if missing:
            reasons.append(f"Unavailable detectors require unmapped fields: {', '.join(missing)}.")
        return "partially_compatible", reasons

    reasons.append("No standard cybersecurity fields detected (no IP endpoints, URLs, or auth logs).")
    reasons.append("General tabular profiling and statistical anomaly analysis (Isolation Forest) will be applied.")
    reasons.append("Statistical anomalies are explicitly tagged and NOT claimed as confirmed cyberattacks.")
    return "general_tabular", reasons

def generate_data_profile(df: pd.DataFrame) -> dict[str, Any]:
    """
    Profile dataset quality: column types, missing value counts, duplicate rows, and 5-row sample preview.
    """
    column_types = {}
    missing_values = {}

    for col in df.columns:
        dtype_str = str(df[col].dtype)
        if "int" in dtype_str or "float" in dtype_str:
            column_types[col] = "numeric"
        elif "datetime" in dtype_str:
            column_types[col] = "datetime"
        else:
            column_types[col] = "categorical"
        missing_values[col] = int(df[col].isna().sum())

    duplicates = int(df.duplicated().sum())

    # Replace NaN with None for valid JSON serialization
    sample_df = df.head(5).copy()
    sample_df = sample_df.replace({np.nan: None})
    sample_rows = sample_df.to_dict(orient="records")

    return {
        "total_rows": int(len(df)),
        "total_columns": int(len(df.columns)),
        "duplicate_rows": duplicates,
        "column_types": column_types,
        "missing_values": missing_values,
        "sample_rows": sample_rows
    }
