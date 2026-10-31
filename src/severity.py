"""
Sentinel AI — Severity & Priority Assessment Module
Computes composite risk and severity rankings using category baselines,
confidence scores, asset sensitivity, and multi-vector trigger factors.
"""

from typing import Dict, Any, Tuple

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_COLORS = {
    "Critical": "#EF4444",   # Red
    "High": "#F97316",       # Bright Orange
    "Medium": "#F59E0B",     # Amber
    "Low": "#10B981",        # Emerald Green
    "Info": "#06B6D4"        # Electric Cyan
}

SEVERITY_PRIORITY_MAP = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Info": 5
}

BASE_CATEGORY_SEVERITY = {
    "Brute-Force Login": "High",
    "Port Scanning": "Medium",
    "Abnormally High Traffic": "High",
    "Suspicious User Behaviour": "Critical",
    "Malicious URL/Indicator": "High",
    "Benign": "Info"
}


def calculate_severity(
    threat_category: str,
    confidence: float,
    rule_matches_count: int = 1,
    dst_port: int = 80,
    bytes_transferred: int = 0
) -> Tuple[str, int]:
    """
    Computes final severity level and priority rank (1 = highest, 5 = lowest).
    """
    if threat_category == "Benign" or threat_category is None:
        return "Info", 5

    base = BASE_CATEGORY_SEVERITY.get(threat_category, "Medium")
    score = 0

    # Base points
    base_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    score += base_scores.get(base, 2)

    # Confidence escalation
    if confidence >= 0.90:
        score += 1
    elif confidence < 0.60:
        score -= 1

    # Multiple rule matches or multi-vector triggers
    if rule_matches_count > 1:
        score += 1

    # Sensitive destination ports (SSH, RDP, Database)
    if dst_port in [22, 3389, 1433, 3306, 5432]:
        score += 1

    # Massive data volume factor
    if bytes_transferred > 50_000_000:
        score += 1

    # Clamp score
    if score >= 5:
        final_sev = "Critical"
    elif score == 4:
        final_sev = "High"
    elif score == 3:
        final_sev = "Medium"
    elif score == 2:
        final_sev = "Low"
    else:
        final_sev = "Info"

    priority = SEVERITY_PRIORITY_MAP[final_sev]
    return final_sev, priority


def get_severity_badge_html(severity: str) -> str:
    """Returns a styled HTML badge for SOC dashboards."""
    color = SEVERITY_COLORS.get(severity, "#9CA3AF")
    return (
        f'<span style="background-color: {color}20; color: {color}; '
        f'border: 1px solid {color}60; padding: 3px 8px; border-radius: 4px; '
        f'font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">'
        f'{severity}</span>'
    )
