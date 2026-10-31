import pandas as pd
import pytest
from backend.app.detectors.brute_force import detect_brute_force
from backend.app.detectors.port_scan import detect_port_scan
from backend.app.detectors.traffic_anomaly import detect_traffic_anomaly
from backend.app.detectors.user_behavior import detect_user_behavior
from backend.app.detectors.url_analysis import detect_malicious_urls, calculate_shannon_entropy

def test_detect_brute_force_failure_threshold():
    df = pd.DataFrame({
        "src_ip": ["192.168.1.10", "192.168.1.20"],
        "failed_logins": [25, 2],
        "user": ["root", "alice"]
    })
    mapping = {"src_ip": "src_ip", "login_failures": "failed_logins", "user": "user"}
    findings = detect_brute_force(df, mapping, threshold=5)

    assert len(findings) == 1
    assert findings[0]["category"] == "Brute-Force Login"
    assert findings[0]["severity"] == "Critical"
    assert "root" in findings[0]["evidence"]

def test_detect_port_scan_sweep():
    # 15 distinct ports probed by source 192.168.1.50
    df = pd.DataFrame({
        "src_ip": ["192.168.1.50"] * 15,
        "dst_port": list(range(20, 35)),
        "dst_ip": ["10.0.0.1"] * 15
    })
    mapping = {"src_ip": "src_ip", "dst_port": "dst_port", "dst_ip": "dst_ip"}
    findings = detect_port_scan(df, mapping, port_threshold=10)

    assert len(findings) > 0
    assert findings[0]["category"] == "Port Scanning"
    assert "T1046" in findings[0]["mitre_id"]

def test_detect_traffic_anomaly_zscore():
    # 20 normal packets, 1 massive flood of 500,000 packets
    normal_pkts = [10] * 20
    flood_pkts = [500000]
    df = pd.DataFrame({
        "packets": normal_pkts + flood_pkts,
        "src_ip": ["198.51.100.1"] * 21,
        "dst_ip": ["10.0.0.5"] * 21
    })
    mapping = {"packet_count": "packets", "src_ip": "src_ip", "dst_ip": "dst_ip"}
    findings = detect_traffic_anomaly(df, mapping, zscore_threshold=3.0)

    assert len(findings) == 1
    assert findings[0]["category"] == "Abnormally High Traffic"
    assert findings[0]["severity"] == "Critical"

def test_detect_user_behavior_exfiltration():
    df = pd.DataFrame({
        "bytes": [1024, 80 * 1024 * 1024],  # 80 MB
        "src_ip": ["10.0.0.5", "10.0.0.45"],
        "dst_ip": ["10.0.0.1", "198.51.100.99"]
    })
    mapping = {"byte_count": "bytes", "src_ip": "src_ip", "dst_ip": "dst_ip"}
    findings = detect_user_behavior(df, mapping, exfil_bytes_threshold=50 * 1024 * 1024)

    assert len(findings) == 1
    assert findings[0]["category"] == "Suspicious User Behaviour"
    assert "80.0 MB" in findings[0]["evidence"]

def test_detect_malicious_urls_and_entropy():
    # Test Shannon entropy calculation
    low_entropy = calculate_shannon_entropy("aaaaaaa")
    high_entropy = calculate_shannon_entropy("a8f9d0c1b7e3f2g5h6")
    assert high_entropy > low_entropy

    df = pd.DataFrame({
        "url": [
            "https://internal.corp.local/index.html",
            "https://login-vault-secure-sso.auth-verify.xyz/session-v3/auth?token=9x98a7sd6f51c"
        ],
        "src_ip": ["10.0.0.10", "192.168.1.105"]
    })
    mapping = {"url": "url", "src_ip": "src_ip"}
    findings = detect_malicious_urls(df, mapping, entropy_threshold=4.2, max_length_threshold=70)

    assert len(findings) == 1
    assert findings[0]["category"] == "Malicious URL/Indicator"
    assert findings[0]["severity"] == "Critical"
