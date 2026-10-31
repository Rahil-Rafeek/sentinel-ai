"""
Synthetic Dataset Generator for Sentinel AI
Generates reproducible, realistic network security events and traffic logs
covering Benign traffic and all five threat categories with deterministic random seeds.
"""

import random
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from pathlib import Path

# Deterministic random seed
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

def generate_synthetic_dataset(n_samples: int = 1500) -> pd.DataFrame:
    base_time = datetime(2026, 10, 26, 8, 0, 0)
    records = []

    # Distribution:
    # 65% Benign (~975)
    # 7% Brute Force (~105)
    # 8% Port Scan (~120)
    # 7% High Traffic Flood (~105)
    # 7% Suspicious User Behaviour (~105)
    # 6% Malicious URL / Indicators (~90)

    n_benign = int(n_samples * 0.65)
    n_brute = int(n_samples * 0.07)
    n_portscan = int(n_samples * 0.08)
    n_flood = int(n_samples * 0.07)
    n_behavior = int(n_samples * 0.07)
    n_url = n_samples - (n_benign + n_brute + n_portscan + n_flood + n_behavior)

    benign_urls = [
        "/api/v1/users",
        "/index.html",
        "/dashboard/analytics",
        "/static/css/theme.css",
        "/static/js/bundle.js",
        "/api/v1/products",
        "/search?q=security",
        "/contact-us",
        "/docs/api-guide",
        "/healthz",
        "/home",
        "/favicon.ico"
    ]

    benign_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15"
    ]

    # 1. Benign records
    current_time = base_time
    for i in range(n_benign):
        current_time += timedelta(seconds=random.randint(2, 45))
        src_octet = random.choice([10, 192, 172])
        if src_octet == 10:
            src_ip = f"10.0.{random.randint(1, 20)}.{random.randint(2, 250)}"
        elif src_octet == 192:
            src_ip = f"192.168.1.{random.randint(10, 90)}"
        else:
            src_ip = f"172.16.{random.randint(0, 5)}.{random.randint(2, 250)}"

        dst_ip = f"10.0.0.{random.choice([5, 8, 12, 15, 20])}"
        dst_port = random.choice([80, 443, 8080, 8443, 53])
        src_port = random.randint(10240, 65530)
        protocol = "TCP" if dst_port != 53 else "UDP"

        duration = round(random.uniform(0.05, 5.0), 3)
        pkts_sent = random.randint(5, 50)
        pkts_recv = random.randint(5, 60)
        bytes_sent = pkts_sent * random.randint(60, 400)
        bytes_recv = pkts_recv * random.randint(200, 1400)

        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "duration_sec": duration,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "packets_sent": pkts_sent,
            "packets_received": pkts_recv,
            "failed_login_count": 0,
            "requested_resource": random.choice(benign_urls),
            "user_agent": random.choice(benign_user_agents),
            "label": "Benign",
            "is_threat": 0
        })

    # 2. Brute-force Login Attempts
    # Multiple distinct attackers targeting auth ports with burst failed logins
    brute_ips = ["192.168.1.105", "192.168.1.199", "185.220.101.5"]
    attack_time = base_time + timedelta(hours=2)
    for i in range(n_brute):
        attacker = random.choice(brute_ips)
        target_ip = "10.0.0.12"
        target_port = random.choice([22, 443])
        attack_time += timedelta(seconds=random.randint(3, 12))
        
        pkts_sent = random.randint(4, 12)
        pkts_recv = random.randint(3, 10)
        bytes_sent = pkts_sent * random.randint(50, 120)
        bytes_recv = pkts_recv * random.randint(50, 150)

        records.append({
            "timestamp": attack_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker,
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 60000),
            "dst_port": target_port,
            "protocol": "TCP",
            "duration_sec": round(random.uniform(0.1, 1.2), 3),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "packets_sent": pkts_sent,
            "packets_received": pkts_recv,
            "failed_login_count": 1,
            "requested_resource": "/auth/login" if target_port == 443 else "ssh-2.0-OpenSSH",
            "user_agent": "Hydra/9.5" if random.random() > 0.4 else "python-requests/2.28.1",
            "label": "Brute Force",
            "is_threat": 1
        })

    # 3. Port Scanning
    # Attackers sweeping through many destination ports in very short succession
    scanner_ips = ["192.168.1.189", "198.51.100.45", "45.154.255.89"]
    target_ports_pool = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
    scan_time = base_time + timedelta(hours=4)
    for i in range(n_portscan):
        scanner = scanner_ips[i % len(scanner_ips)]
        scan_time += timedelta(milliseconds=random.randint(100, 1200))
        target_port = target_ports_pool[i % len(target_ports_pool)]
        
        # Characteristic port scan SYN packet: tiny duration, 1-2 packets, minimal bytes
        records.append({
            "timestamp": scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": scanner,
            "dst_ip": "10.0.0.15",
            "src_port": random.randint(30000, 65000),
            "dst_port": target_port,
            "protocol": "TCP",
            "duration_sec": round(random.uniform(0.001, 0.05), 4),
            "bytes_sent": random.randint(40, 64),
            "bytes_received": random.choice([0, 40]),
            "packets_sent": random.choice([1, 2]),
            "packets_received": random.choice([0, 1]),
            "failed_login_count": 0,
            "requested_resource": "-",
            "user_agent": "Nmap NSE" if random.random() > 0.5 else "Masscan/1.3.2",
            "label": "Port Scan",
            "is_threat": 1
        })

    # 4. Abnormally High Traffic (DoS / Traffic Flooding)
    # Huge packet rates, high bandwidth consumption in short bursts
    flood_ips = ["192.168.1.220", "203.0.113.195", "194.26.29.112"]
    flood_time = base_time + timedelta(hours=6)
    for i in range(n_flood):
        flood_src = random.choice(flood_ips)
        flood_time += timedelta(seconds=random.randint(1, 5))
        duration = round(random.uniform(0.5, 3.0), 3)
        pkts = random.randint(3000, 15000)
        bytes_sent = pkts * random.randint(500, 1400)

        records.append({
            "timestamp": flood_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": flood_src,
            "dst_ip": "10.0.0.5",
            "src_port": random.randint(10000, 60000),
            "dst_port": random.choice([80, 443, 8080]),
            "protocol": random.choice(["TCP", "UDP"]),
            "duration_sec": duration,
            "bytes_sent": bytes_sent,
            "bytes_received": random.randint(100, 1500),
            "packets_sent": pkts,
            "packets_received": random.randint(1, 20),
            "failed_login_count": 0,
            "requested_resource": "/search?q=" + ("A" * random.randint(50, 300)),
            "user_agent": "Golang-HTTP-Client/1.1" if random.random() > 0.5 else "curl/7.88.1",
            "label": "High Traffic Flood",
            "is_threat": 1
        })

    # 5. Suspicious User Behaviour (Data Exfiltration / Sensitive Endpoint Probing)
    suspicious_users = ["10.0.0.45", "10.0.0.99", "192.168.1.77"]
    sensitive_paths = [
        "/api/v1/dump",
        "/backup.tar.gz",
        "/.env",
        "/etc/passwd",
        "/db_export",
        "/actuator/env",
        "/wp-login.php"
    ]
    behavior_time = base_time + timedelta(hours=8)
    for i in range(n_behavior):
        usr_ip = random.choice(suspicious_users)
        behavior_time += timedelta(seconds=random.randint(10, 60))
        # Exfiltration: huge bytes sent outbound (25MB to 80MB)
        is_exfil = random.random() > 0.4
        bytes_out = random.randint(30_000_000, 95_000_000) if is_exfil else random.randint(500_000, 4_000_000)
        pkts_out = bytes_out // random.randint(1000, 1400)

        records.append({
            "timestamp": behavior_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": usr_ip,
            "dst_ip": "198.51.100.99",
            "src_port": random.randint(45000, 65000),
            "dst_port": 443,
            "protocol": "TCP",
            "duration_sec": round(random.uniform(5.0, 45.0), 2),
            "bytes_sent": bytes_out,
            "bytes_received": random.randint(2000, 25000),
            "packets_sent": pkts_out,
            "packets_received": random.randint(50, 500),
            "failed_login_count": 0,
            "requested_resource": random.choice(sensitive_paths),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.2",
            "label": "Suspicious User Behaviour",
            "is_threat": 1
        })

    # 6. Malicious URLs or Indicators
    suspicious_urls = [
        "http://paypal-security-update.xyz/login.php?token=0f72a44b89",
        "http://secure-auth-update.xyz/verify-account/auth.php",
        "http://login-appleid-verify.top/session?ref=reset",
        "http://c2-direct-beacon.ru/payload.bin?k=98fa",
        "http://crypto-bonus-drop.click/airdrop?address=0x83",
        "http://malware-command-relay.top/c2-beacon?id=4921",
        "http://185.220.101.5/exploit.sh",
        "http://45.154.255.89/agent.bin"
    ]
    url_time = base_time + timedelta(hours=10)
    for i in range(n_url):
        url_time += timedelta(seconds=random.randint(15, 80))
        target_url = random.choice(suspicious_urls)
        records.append({
            "timestamp": url_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f"192.168.1.{random.randint(100, 150)}",
            "dst_ip": random.choice(["198.51.100.45", "185.220.101.5", "45.154.255.89"]),
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice([80, 8080, 443]),
            "protocol": "TCP",
            "duration_sec": round(random.uniform(0.1, 2.5), 3),
            "bytes_sent": random.randint(300, 1500),
            "bytes_received": random.randint(500, 4500),
            "packets_sent": random.randint(4, 15),
            "packets_received": random.randint(4, 20),
            "failed_login_count": 0,
            "requested_resource": target_url,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36",
            "label": "Malicious URL/Indicator",
            "is_threat": 1
        })

    df = pd.DataFrame(records)
    # Sort chronologically
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    return df

if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "sample"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    df_data = generate_synthetic_dataset(1600)
    out_path = out_dir / "synthetic_network_logs.csv"
    df_data.to_csv(out_path, index=False)
    print(f"Generated {len(df_data)} records at {out_path}")
    print("Class distribution:")
    print(df_data["label"].value_counts())

    # Create a stratified mini-sample (250 rows) for quick testing containing all classes
    mini_dfs = []
    for lbl, group in df_data.groupby("label"):
        sample_n = max(20, int(len(group) * 0.18))
        mini_dfs.append(group.sample(n=min(sample_n, len(group)), random_state=42))
    df_mini = pd.concat(mini_dfs).sort_values("timestamp").reset_index(drop=True)
    mini_path = out_dir / "sample_security_events.csv"
    df_mini.to_csv(mini_path, index=False)
    print(f"Saved stratified mini-sample ({len(df_mini)} rows) at {mini_path}")
