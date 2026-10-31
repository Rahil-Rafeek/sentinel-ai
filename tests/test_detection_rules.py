"""
Tests for Rule-Based Threat Detection Engine
Validates detection for all five required threat scenarios.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detection_rules import RuleEngine


@pytest.fixture
def rule_engine():
    return RuleEngine()


def test_brute_force_detection(rule_engine):
    base_time = datetime(2026, 10, 26, 12, 0, 0)
    records = []
    # 7 failed logins within 60 seconds (threshold is 5)
    for i in range(7):
        records.append({
            "timestamp": (base_time + timedelta(seconds=i*5)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "src_port": 50000 + i,
            "dst_port": 22,
            "protocol": "TCP",
            "duration_sec": 0.2,
            "bytes_sent": 100,
            "bytes_received": 50,
            "packets_sent": 4,
            "packets_received": 3,
            "failed_login_count": 1,
            "requested_resource": "ssh-auth",
            "user_agent": "Hydra"
        })
    df = pd.DataFrame(records)
    matches = rule_engine.analyze_dataset(df)

    # Later events in the burst should trigger brute-force rule
    has_bf = any(
        any(m.category == "Brute-Force Login" for m in row_matches)
        for row_matches in matches
    )
    assert has_bf is True


def test_port_scanning_detection(rule_engine):
    base_time = datetime(2026, 10, 26, 13, 0, 0)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445]  # 11 distinct ports
    records = []
    for i, port in enumerate(ports):
        records.append({
            "timestamp": (base_time + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "192.168.1.200",
            "dst_ip": "10.0.0.10",
            "src_port": 40000 + i,
            "dst_port": port,
            "protocol": "TCP",
            "duration_sec": 0.01,
            "bytes_sent": 44,
            "bytes_received": 0,
            "packets_sent": 1,
            "packets_received": 0,
            "failed_login_count": 0,
            "requested_resource": "-",
            "user_agent": "Nmap"
        })
    df = pd.DataFrame(records)
    matches = rule_engine.analyze_dataset(df)

    has_portscan = any(
        any(m.category == "Port Scanning" for m in row_matches)
        for row_matches in matches
    )
    assert has_portscan is True


def test_abnormally_high_traffic_detection(rule_engine):
    df = pd.DataFrame([{
        "timestamp": "2026-10-26 14:00:00",
        "src_ip": "192.168.1.210",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "duration_sec": 1.0,
        "bytes_sent": 15_000_000,
        "bytes_received": 1000,
        "packets_sent": 8000,
        "packets_received": 10,
        "failed_login_count": 0,
        "requested_resource": "/flood",
        "user_agent": "curl"
    }])
    matches = rule_engine.analyze_dataset(df)
    assert len(matches[0]) > 0
    categories = [m.category for m in matches[0]]
    assert "Abnormally High Traffic" in categories


def test_suspicious_user_behaviour_exfiltration(rule_engine):
    df = pd.DataFrame([{
        "timestamp": "2026-10-26 15:00:00",
        "src_ip": "10.0.0.45",
        "dst_ip": "198.51.100.99",
        "src_port": 51234,
        "dst_port": 443,
        "protocol": "TCP",
        "duration_sec": 20.0,
        "bytes_sent": 45_000_000,  # 45 MB outbound
        "bytes_received": 5000,
        "packets_sent": 35000,
        "packets_received": 50,
        "failed_login_count": 0,
        "requested_resource": "/api/v1/dump",
        "user_agent": "PowerShell"
    }])
    matches = rule_engine.analyze_dataset(df)
    assert len(matches[0]) > 0
    categories = [m.category for m in matches[0]]
    assert "Suspicious User Behaviour" in categories


def test_malicious_url_and_indicators(rule_engine):
    df = pd.DataFrame([{
        "timestamp": "2026-10-26 16:00:00",
        "src_ip": "192.168.1.55",
        "dst_ip": "185.220.101.5",  # Known malicious IP
        "src_port": 49000,
        "dst_port": 80,
        "protocol": "TCP",
        "duration_sec": 0.5,
        "bytes_sent": 500,
        "bytes_received": 1200,
        "packets_sent": 5,
        "packets_received": 6,
        "failed_login_count": 0,
        "requested_resource": "http://paypal-security-update.xyz/login.php?token=d78f23",
        "user_agent": "Safari"
    }])
    matches = rule_engine.analyze_dataset(df)
    assert len(matches[0]) > 0
    categories = [m.category for m in matches[0]]
    assert "Malicious URL/Indicator" in categories
