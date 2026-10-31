"""
Sentinel AI — Rule-Based Threat Detection Engine
Implements deterministic, explainable, threshold-driven security rules for all 5 threat categories:
1. Brute-force Login Attempts
2. Port Scanning
3. Abnormally High Traffic
4. Suspicious User Behaviour / Exfiltration
5. Malicious URLs or Indicators
"""

from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np
from datetime import timedelta
import logging

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import DEFAULT_DETECTION_THRESHOLDS, KNOWN_MALICIOUS_INDICATORS
from src.feature_engineering import calculate_shannon_entropy

logger = logging.getLogger("sentinel.detection_rules")


class RuleMatch:
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: str,
        confidence: float,
        evidence: str,
        recommended_action: str
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.evidence = evidence
        self.recommended_action = recommended_action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action
        }


class RuleEngine:
    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = thresholds or DEFAULT_DETECTION_THRESHOLDS.copy()
        self.known_iocs = KNOWN_MALICIOUS_INDICATORS

    def update_thresholds(self, new_thresholds: Dict[str, Any]) -> None:
        self.thresholds.update(new_thresholds)

    def analyze_dataset(self, df: pd.DataFrame) -> List[List[RuleMatch]]:
        """
        Runs stateful window rules (brute-force & port scan grouping)
        and per-row stateless rules across the entire dataset.
        Returns a list of list of RuleMatch objects, one per row in df.
        """
        n_rows = len(df)
        all_matches: List[List[RuleMatch]] = [[] for _ in range(n_rows)]

        if n_rows == 0:
            return all_matches

        # Make sure timestamp is datetime for temporal rules
        temp_df = df.copy()
        if not pd.api.types.is_datetime64_any_dtype(temp_df["timestamp"]):
            temp_df["timestamp"] = pd.to_datetime(temp_df["timestamp"], errors="coerce").fillna(pd.Timestamp.now())

        # -------------------------------------------------------------
        # 1. STATEFUL RULE: Brute-Force Login Detection
        # -------------------------------------------------------------
        bf_threshold = self.thresholds.get("failed_login_threshold", 5)
        bf_window_sec = self.thresholds.get("failed_login_window_seconds", 300)

        # Filter events with failed_login_count > 0 or targeted auth ports
        auth_events = temp_df[
            (temp_df["failed_login_count"] > 0) | 
            (temp_df["dst_port"].isin([22, 3389, 21, 23, 1433, 3306])) |
            (temp_df["requested_resource"].str.contains("login|auth", case=False, na=False))
        ]

        if not auth_events.empty:
            for src_ip, group in auth_events.groupby("src_ip"):
                sorted_group = group.sort_values("timestamp")
                times = sorted_group["timestamp"].tolist()
                indices = sorted_group.index.tolist()
                fails = sorted_group["failed_login_count"].tolist()

                for i in range(len(sorted_group)):
                    # Count failed logins in trailing time window
                    window_start = times[i] - timedelta(seconds=bf_window_sec)
                    window_count = 0
                    for j in range(i, -1, -1):
                        if times[j] >= window_start:
                            window_count += max(fails[j], 1)
                        else:
                            break

                    if window_count >= bf_threshold:
                        target = sorted_group.iloc[i]["dst_ip"]
                        target_port = sorted_group.iloc[i]["dst_port"]
                        match = RuleMatch(
                            rule_id="RULE-BF-01",
                            rule_name="Brute-Force Authentication Spike",
                            category="Brute-Force Login",
                            severity="High" if window_count < 10 else "Critical",
                            confidence=min(0.70 + (window_count / 20.0) * 0.25, 0.98),
                            evidence=(
                                f"Observed {window_count} failed login attempts from source IP {src_ip} "
                                f"targeting host {target}:{target_port} within {bf_window_sec}s window "
                                f"(configured threshold is {bf_threshold})."
                            ),
                            recommended_action=(
                                f"Enforce temporary IP rate-limit/quarantine on firewall for {src_ip}. "
                                f"Inspect authentication service on {target}:{target_port} and verify credential lockout policies."
                            )
                        )
                        all_matches[indices[i]].append(match)

        # -------------------------------------------------------------
        # 2. STATEFUL RULE: Port Scanning Detection
        # -------------------------------------------------------------
        ps_threshold = self.thresholds.get("port_scan_port_threshold", 8)
        ps_window_sec = self.thresholds.get("port_scan_window_seconds", 60)

        for src_ip, group in temp_df.groupby("src_ip"):
            if len(group) < 3:
                continue
            sorted_group = group.sort_values("timestamp")
            times = sorted_group["timestamp"].tolist()
            indices = sorted_group.index.tolist()
            ports = sorted_group["dst_port"].tolist()

            for i in range(len(sorted_group)):
                window_start = times[i] - timedelta(seconds=ps_window_sec)
                recent_ports = set()
                for j in range(i, -1, -1):
                    if times[j] >= window_start:
                        recent_ports.add(ports[j])
                    else:
                        break

                if len(recent_ports) >= ps_threshold:
                    sample_ports = sorted(list(recent_ports))[:6]
                    match = RuleMatch(
                        rule_id="RULE-PS-01",
                        rule_name="Rapid Port Sweep / Reconnaissance",
                        category="Port Scanning",
                        severity="Medium" if len(recent_ports) < 15 else "High",
                        confidence=min(0.65 + (len(recent_ports) / 30.0) * 0.30, 0.95),
                        evidence=(
                            f"Host {src_ip} probed {len(recent_ports)} unique destination ports "
                            f"(sample: {sample_ports}) within {ps_window_sec}s. Exceeds reconnaissance threshold of {ps_threshold} ports."
                        ),
                        recommended_action=(
                            f"Block reconnaissance probes from {src_ip} at ingress edge router. "
                            f"Review exposed perimeter services and ensure non-standard management ports are firewalled."
                        )
                    )
                    all_matches[indices[i]].append(match)

        # -------------------------------------------------------------
        # STATISTICAL BASELINE FOR HIGH TRAFFIC SPIKES
        # -------------------------------------------------------------
        durations = temp_df["duration_sec"].fillna(0.1).clip(lower=0.001)
        pkt_rates = (temp_df["packets_sent"] + temp_df["packets_received"]) / durations
        byte_rates = (temp_df["bytes_sent"] + temp_df["bytes_received"]) / durations

        pkt_rate_threshold = self.thresholds.get("packet_rate_threshold", 2000.0)
        byte_rate_threshold = self.thresholds.get("byte_rate_threshold", 5_000_000.0)

        # -------------------------------------------------------------
        # 3, 4, 5. ROW-LEVEL RULES: High Traffic, Suspicious Behavior, URL Heuristics
        # -------------------------------------------------------------
        exfil_threshold = self.thresholds.get("exfiltration_bytes_threshold", 25_000_000)
        outbound_ratio_threshold = self.thresholds.get("outbound_ratio_threshold", 10.0)
        sensitive_endpoints = self.thresholds.get("sensitive_endpoints", [])
        entropy_threshold = self.thresholds.get("url_entropy_threshold", 4.1)
        suspicious_keywords = self.thresholds.get("suspicious_url_keywords", [])
        suspicious_tlds = self.thresholds.get("suspicious_tlds", [])

        known_ips = set(self.known_iocs.get("ips", []))
        known_domains = set(self.known_iocs.get("domains", []))

        for idx, row in temp_df.iterrows():
            # 3. High Traffic Flood Rule
            curr_pkt_rate = pkt_rates.iloc[idx]
            curr_byte_rate = byte_rates.iloc[idx]
            total_pkts = row["packets_sent"] + row["packets_received"]

            if curr_pkt_rate >= pkt_rate_threshold or curr_byte_rate >= byte_rate_threshold or total_pkts >= 3000:
                match = RuleMatch(
                    rule_id="RULE-TF-01",
                    rule_name="Abnormal Traffic Spike / Flood Anomaly",
                    category="Abnormally High Traffic",
                    severity="Critical" if curr_pkt_rate > 5000 or total_pkts > 8000 else "High",
                    confidence=0.92 if curr_pkt_rate >= pkt_rate_threshold else 0.82,
                    evidence=(
                        f"Abnormal traffic volume detected: {curr_pkt_rate:.0f} packets/sec and "
                        f"{curr_byte_rate / 1_000_000:.2f} MB/s throughput ({total_pkts} total packets in {row['duration_sec']}s). "
                        f"Configured limit: {pkt_rate_threshold} pkts/s."
                    ),
                    recommended_action=(
                        f"Engage upstream DDoS scrubbing or rate-limiting for ingress traffic from {row['src_ip']}. "
                        f"Inspect target server {row['dst_ip']}:{row['dst_port']} CPU/socket exhaustion."
                    )
                )
                all_matches[idx].append(match)

            # 4. Suspicious User Behaviour / Exfiltration Rule
            bytes_out = row["bytes_sent"]
            bytes_in = max(row["bytes_received"], 1)
            ratio = bytes_out / bytes_in
            resource = str(row.get("requested_resource", ""))

            is_sensitive_hit = any(ep.lower() in resource.lower() for ep in sensitive_endpoints)
            is_large_exfil = bytes_out >= exfil_threshold

            if is_large_exfil or (is_sensitive_hit and bytes_out > 500_000) or (ratio >= outbound_ratio_threshold and bytes_out > 10_000_000):
                ev_parts = []
                if is_large_exfil:
                    ev_parts.append(f"high-volume outbound transfer of {bytes_out / 1_000_000:.2f} MB (threshold: {exfil_threshold / 1_000_000:.0f} MB)")
                if is_sensitive_hit:
                    ev_parts.append(f"access to sensitive administrative/backup endpoint '{resource}'")
                if ratio >= outbound_ratio_threshold:
                    ev_parts.append(f"asymmetric upload ratio of {ratio:.1f}x sent vs received")

                match = RuleMatch(
                    rule_id="RULE-UB-01",
                    rule_name="Suspicious Outbound Exfiltration / Sensitive Access",
                    category="Suspicious User Behaviour",
                    severity="Critical" if is_large_exfil and is_sensitive_hit else ("High" if is_large_exfil else "Medium"),
                    confidence=0.88,
                    evidence=f"Suspicious behavior flagged: {'; '.join(ev_parts)} by host {row['src_ip']}.",
                    recommended_action=(
                        f"Immediately isolate host {row['src_ip']} to contain potential data exfiltration. "
                        f"Revoke active API/session tokens and review egress firewall logs for destination {row['dst_ip']}."
                    )
                )
                all_matches[idx].append(match)

            # 5. Malicious URL / Indicator Heuristics Rule
            ent = calculate_shannon_entropy(resource)
            kw_hits = [kw for kw in suspicious_keywords if kw.lower() in resource.lower()]
            tld_hits = [tld for tld in suspicious_tlds if tld.lower() in resource.lower()]
            ip_ioc = (row["src_ip"] in known_ips) or (row["dst_ip"] in known_ips)
            domain_ioc = any(d.lower() in resource.lower() for d in known_domains)

            if ip_ioc or domain_ioc or (ent >= entropy_threshold and len(resource) > 25) or kw_hits or tld_hits:
                indicators = []
                if ip_ioc:
                    indicators.append(f"Known malicious threat actor IP indicator match ({row['src_ip']} / {row['dst_ip']})")
                if domain_ioc:
                    indicators.append("Known malicious C2/phishing domain in resource URL")
                if ent >= entropy_threshold and len(resource) > 25:
                    indicators.append(f"High Shannon entropy ({ent:.2f} bits/char > {entropy_threshold}), indicating algorithmic obfuscation or packed payload")
                if kw_hits:
                    indicators.append(f"Suspicious indicator keywords detected: {kw_hits}")
                if tld_hits:
                    indicators.append(f"High-risk top-level domain extension: {tld_hits}")

                # Note: Transparent heuristic rule, not claiming binary malware disassembly
                match = RuleMatch(
                    rule_id="RULE-URL-01",
                    rule_name="Suspicious URL / Threat Intelligence Heuristic Match",
                    category="Malicious URL/Indicator",
                    severity="High" if (ip_ioc or domain_ioc) else "Medium",
                    confidence=0.94 if (ip_ioc or domain_ioc) else 0.81,
                    evidence=f"Heuristic indicator matches: {'; '.join(indicators)}. URL: '{resource[:100]}'.",
                    recommended_action=(
                        f"Add destination indicator to enterprise DNS and Web Application Firewall blocklist. "
                        f"Trigger endpoint EDR scan on {row['src_ip']} to inspect originating browser process."
                    )
                )
                all_matches[idx].append(match)

        return all_matches
