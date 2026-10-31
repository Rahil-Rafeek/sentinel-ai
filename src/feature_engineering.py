"""
Sentinel AI — Feature Engineering Module
Transforms raw network records into high-signal cybersecurity features
for machine learning classification and anomaly detection.
"""

import math
from collections import Counter
from typing import List
import numpy as np
import pandas as pd

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import DEFAULT_DETECTION_THRESHOLDS, KNOWN_MALICIOUS_INDICATORS


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (bits per character) of a string."""
    if not text or not isinstance(text, str):
        return 0.0
    s = text.strip()
    if len(s) <= 1:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derives engineering cybersecurity features from standardized input dataframe.
    Safe against missing columns, division by zero, and invalid types.
    """
    df_feat = pd.DataFrame(index=df.index)

    # 1. Total volumes & Ratios
    bytes_sent = df["bytes_sent"].fillna(0).astype(float)
    bytes_recv = df["bytes_received"].fillna(0).astype(float)
    pkts_sent = df["packets_sent"].fillna(1).astype(float)
    pkts_recv = df["packets_received"].fillna(1).astype(float)
    duration = df["duration_sec"].fillna(0.1).astype(float).clip(lower=0.001)

    total_bytes = bytes_sent + bytes_recv
    total_pkts = pkts_sent + pkts_recv

    df_feat["duration_sec"] = duration
    df_feat["total_bytes"] = total_bytes
    df_feat["total_packets"] = total_pkts
    df_feat["bytes_sent"] = bytes_sent
    df_feat["bytes_received"] = bytes_recv

    # Rates
    df_feat["packet_rate"] = total_pkts / duration
    df_feat["byte_rate"] = total_bytes / duration

    # Asymmetry Ratios (Key for Exfiltration and C2 beaconing)
    df_feat["bytes_ratio"] = bytes_sent / (bytes_recv + 1.0)
    df_feat["packets_ratio"] = pkts_sent / (pkts_recv + 1.0)
    df_feat["bytes_per_packet"] = total_bytes / (total_pkts + 1.0)

    # 2. Port & Protocol Signals
    dst_port = df["dst_port"].fillna(0).astype(int)
    df_feat["dst_port"] = dst_port
    df_feat["is_well_known_port"] = (dst_port < 1024).astype(int)
    df_feat["is_common_web_port"] = dst_port.isin([80, 443, 8080, 8443]).astype(int)
    df_feat["is_auth_port"] = dst_port.isin([22, 3389, 21, 23, 1433, 3306, 5432]).astype(int)

    # Protocol dummy features
    proto_series = df["protocol"].fillna("TCP").astype(str).str.upper()
    df_feat["proto_tcp"] = (proto_series == "TCP").astype(int)
    df_feat["proto_udp"] = (proto_series == "UDP").astype(int)
    df_feat["proto_other"] = (~proto_series.isin(["TCP", "UDP"])).astype(int)

    # 3. Authentication & Behavioral Signals
    df_feat["failed_login_count"] = df["failed_login_count"].fillna(0).astype(int)

    # 4. URL & Resource Heuristic Signals
    resources = df["requested_resource"].fillna("").astype(str)
    sensitive_endpoints = DEFAULT_DETECTION_THRESHOLDS.get("sensitive_endpoints", [])
    suspicious_keywords = DEFAULT_DETECTION_THRESHOLDS.get("suspicious_url_keywords", [])
    suspicious_tlds = DEFAULT_DETECTION_THRESHOLDS.get("suspicious_tlds", [])

    # Shannon entropy
    df_feat["url_entropy"] = resources.apply(calculate_shannon_entropy)
    df_feat["url_length"] = resources.apply(len)

    # Endpoint sensitivity flag
    def check_sensitive(res: str) -> int:
        r_low = res.lower()
        return int(any(ep.lower() in r_low for ep in sensitive_endpoints))

    def check_keyword(res: str) -> int:
        r_low = res.lower()
        return int(any(kw.lower() in r_low for kw in suspicious_keywords))

    def check_tld(res: str) -> int:
        r_low = res.lower()
        return int(any(tld.lower() in r_low for tld in suspicious_tlds))

    df_feat["has_sensitive_endpoint"] = resources.apply(check_sensitive)
    df_feat["has_suspicious_keyword"] = resources.apply(check_keyword)
    df_feat["has_suspicious_tld"] = resources.apply(check_tld)

    # 5. Known IOC indicator match
    known_ips = set(KNOWN_MALICIOUS_INDICATORS.get("ips", []))
    src_ips = df["src_ip"].fillna("").astype(str)
    dst_ips = df["dst_ip"].fillna("").astype(str)
    df_feat["is_known_malicious_ip"] = (src_ips.isin(known_ips) | dst_ips.isin(known_ips)).astype(int)

    # Fill any remaining NaNs or Infs safely
    df_feat = df_feat.replace([np.inf, -np.inf], 0).fillna(0)

    return df_feat


def get_feature_names() -> List[str]:
    """Returns the ordered list of generated feature column names."""
    return [
        "duration_sec",
        "total_bytes",
        "total_packets",
        "bytes_sent",
        "bytes_received",
        "packet_rate",
        "byte_rate",
        "bytes_ratio",
        "packets_ratio",
        "bytes_per_packet",
        "dst_port",
        "is_well_known_port",
        "is_common_web_port",
        "is_auth_port",
        "proto_tcp",
        "proto_udp",
        "proto_other",
        "failed_login_count",
        "url_entropy",
        "url_length",
        "has_sensitive_endpoint",
        "has_suspicious_keyword",
        "has_suspicious_tld",
        "is_known_malicious_ip"
    ]
