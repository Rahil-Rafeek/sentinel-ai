"""
Sentinel AI — Advanced Cybersecurity Visualizations Module
Provides commercial-grade interactive Threat Radar and Network Attack Topology diagrams
using Plotly Graph Objects with dark-navy SOC aesthetics.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from src.severity import SEVERITY_COLORS

PLOTLY_DARK_LAYOUT = {
    "paper_bgcolor": "rgba(11, 17, 32, 0.7)",
    "plot_bgcolor": "rgba(8, 12, 22, 0.6)",
    "font": {"color": "#94A3B8", "family": "Plus Jakarta Sans"},
    "xaxis": {"gridcolor": "rgba(30, 41, 59, 0.6)", "zerolinecolor": "rgba(30, 41, 59, 0.6)"},
    "yaxis": {"gridcolor": "rgba(30, 41, 59, 0.6)", "zerolinecolor": "rgba(30, 41, 59, 0.6)"}
}

# Radar Vector Angular Offsets (Degrees)
CATEGORY_ANGLES = {
    "Brute-Force Login": 36.0,          # Sector 1: 0 - 72 deg
    "Port Scanning": 108.0,             # Sector 2: 72 - 144 deg
    "Abnormally High Traffic": 180.0,   # Sector 3: 144 - 216 deg
    "Suspicious User Behaviour": 252.0, # Sector 4: 216 - 288 deg
    "Malicious URL/Indicator": 324.0,   # Sector 5: 288 - 360 deg
    "Benign": 0.0
}

CATEGORY_SECTOR_LABELS = [
    "Auth Boundary<br>(Brute-Force)",
    "Perimeter Recon<br>(Port Sweep)",
    "Ingress Flood<br>(DoS / Volume)",
    "Lateral / Exfil<br>(User Behavior)",
    "Payload & Web<br>(Malicious URLs)"
]


def create_interactive_threat_radar(df: pd.DataFrame) -> go.Figure:
    """
    Renders a high-end 360-degree interactive polar threat radar.
    Threat events are positioned by vector sector (theta) and severity/confidence (r).
    Marker size maps to flow volume; marker color maps to severity.
    """
    fig = go.Figure()

    if df.empty:
        fig.add_annotation(
            text="No threat telemetry available to display on radar",
            showarrow=False,
            font=dict(color="#64748B", size=14)
        )
        fig.update_layout(**PLOTLY_DARK_LAYOUT, height=420)
        return fig

    # Filter to threats (or sample benign events for context)
    threats = df[df["is_threat"]].copy()
    if threats.empty:
        threats = df.head(20).copy()

    # Calculate polar coordinates
    np.random.seed(42)
    thetas = []
    radii = []
    hover_texts = []
    marker_sizes = []
    colors = []

    # Map severity to base radius: Critical (0.9 - 1.0), High (0.7 - 0.85), Medium (0.5 - 0.65), Low (0.25 - 0.45)
    sev_radius_base = {
        "Critical": 0.90,
        "High": 0.72,
        "Medium": 0.52,
        "Low": 0.35,
        "Info": 0.18
    }

    for idx, row in threats.iterrows():
        cat = row.get("threat_category", "Benign")
        base_angle = CATEGORY_ANGLES.get(cat, 0.0)
        # Jitter angle slightly (-18 to +18 degrees) to prevent overlapping in dense clusters
        jitter_deg = float(np.random.uniform(-18.0, 18.0))
        angle = (base_angle + jitter_deg) % 360.0
        thetas.append(angle)

        sev = row.get("severity", "Medium")
        base_r = sev_radius_base.get(sev, 0.5)
        conf = float(row.get("confidence", 0.8))
        r = float(np.clip(base_r * 0.7 + conf * 0.3 + np.random.uniform(-0.04, 0.04), 0.15, 0.99))
        radii.append(r)

        # Scale marker size by packets/bytes
        bytes_tot = int(row.get("bytes_sent", 100)) + int(row.get("bytes_received", 100))
        size = int(np.clip(np.log10(max(bytes_tot, 10)) * 2.8, 8, 22))
        marker_sizes.append(size)

        color = SEVERITY_COLORS.get(sev, "#00F2FE")
        colors.append(color)

        ev_id = row.get("event_id", f"EVT-{idx}")
        src = row.get("src_ip", "UNKNOWN")
        dst = f"{row.get('dst_ip', 'TARGET')}:{row.get('dst_port', '')}"
        method = row.get("detection_method", "Rule")
        evidence = str(row.get("evidence", ""))[:80] + "..."

        hover = (
            f"<b>{ev_id}</b><br>"
            f"Vector: <b>{cat}</b><br>"
            f"Severity: <b>{sev}</b> (Confidence: {conf:.1%})<br>"
            f"Flow: {src} &rarr; {dst}<br>"
            f"Method: {method}<br>"
            f"Evidence: {evidence}"
        )
        hover_texts.append(hover)

    # Plot Radar Points
    fig.add_trace(go.Scatterpolar(
        r=radii,
        theta=thetas,
        mode="markers",
        marker=dict(
            size=marker_sizes,
            color=colors,
            opacity=0.88,
            line=dict(color="#FFFFFF", width=1),
            symbol="circle"
        ),
        text=hover_texts,
        hoverinfo="text",
        name="Detected Incidents"
    ))

    # Add concentric perimeter zone rings
    fig.update_layout(
        polar=dict(
            bgcolor="rgba(8, 12, 22, 0.8)",
            radialaxis=dict(
                visible=True,
                range=[0, 1.05],
                tickvals=[0.25, 0.50, 0.75, 1.0],
                ticktext=["INFO", "MEDIUM", "HIGH", "CRITICAL"],
                tickfont=dict(size=9, color="#64748B", family="JetBrains Mono"),
                linecolor="rgba(0, 242, 254, 0.25)",
                gridcolor="rgba(30, 41, 59, 0.7)"
            ),
            angularaxis=dict(
                tickvals=[36, 108, 180, 252, 324],
                ticktext=CATEGORY_SECTOR_LABELS,
                tickfont=dict(size=10, color="#F8FAFC", family="Plus Jakarta Sans", weight=700),
                linecolor="rgba(0, 242, 254, 0.35)",
                gridcolor="rgba(0, 242, 254, 0.15)",
                direction="clockwise"
            )
        ),
        paper_bgcolor="rgba(11, 17, 32, 0.7)",
        showlegend=False,
        height=450,
        margin=dict(t=50, b=40, l=40, r=40)
    )

    return fig


def create_network_attack_topology(df: pd.DataFrame, max_links: int = 25) -> go.Figure:
    """
    Renders an interactive Sankey Attack Propagation Flow diagram:
    Source IP Subnets -> Ingress Gateway/Port -> Target Protected Infrastructure.
    Flow line colors correspond to threat severity.
    """
    fig = go.Figure()

    if df.empty:
        fig.add_annotation(
            text="No network telemetry available for attack topology",
            showarrow=False,
            font=dict(color="#64748B", size=14)
        )
        fig.update_layout(**PLOTLY_DARK_LAYOUT, height=380)
        return fig

    # Take threat events + sample benign events
    threats = df[df["is_threat"]].head(max_links).copy()
    if len(threats) < 5:
        threats = pd.concat([threats, df.head(15)]).drop_duplicates().head(max_links)

    # Build unique nodes:
    # Level 1: Source Actors (Grouped or Specific)
    # Level 2: Gateway / Ingress Port
    # Level 3: Target Protected Asset
    source_nodes = sorted(list(threats["src_ip"].astype(str).unique()))
    port_nodes = sorted(list(threats["dst_port"].astype(str).apply(lambda p: f"Port {p}").unique()))
    target_nodes = sorted(list(threats["dst_ip"].astype(str).unique()))

    all_nodes = source_nodes + port_nodes + target_nodes
    node_to_idx = {name: i for i, name in enumerate(all_nodes)}

    # Build links:
    # Source -> Port
    # Port -> Target
    links_src = []
    links_tgt = []
    links_val = []
    links_color = []
    links_customdata = []

    # Source -> Port links
    sp_grouped = threats.groupby(["src_ip", "dst_port", "severity", "threat_category"]).size().reset_index(name="count")
    for _, r in sp_grouped.iterrows():
        s_idx = node_to_idx[str(r["src_ip"])]
        p_idx = node_to_idx[f"Port {r['dst_port']}"]
        links_src.append(s_idx)
        links_tgt.append(p_idx)
        links_val.append(int(r["count"]))
        sev = r["severity"]
        hex_col = SEVERITY_COLORS.get(sev, "#06B6D4")
        # RGBA with transparency
        links_color.append(f"{hex_col}60")
        links_customdata.append(f"{r['threat_category']} ({sev})")

    # Port -> Target links
    pt_grouped = threats.groupby(["dst_port", "dst_ip", "severity", "threat_category"]).size().reset_index(name="count")
    for _, r in pt_grouped.iterrows():
        p_idx = node_to_idx[f"Port {r['dst_port']}"]
        t_idx = node_to_idx[str(r["dst_ip"])]
        links_src.append(p_idx)
        links_tgt.append(t_idx)
        links_val.append(int(r["count"]))
        sev = r["severity"]
        hex_col = SEVERITY_COLORS.get(sev, "#06B6D4")
        links_color.append(f"{hex_col}60")
        links_customdata.append(f"{r['threat_category']} ({sev})")

    # Node colors
    node_colors = []
    for node in all_nodes:
        if node.startswith("Port"):
            node_colors.append("#8B5CF6")
        elif node.startswith("10.0."):
            node_colors.append("#38BDF8")  # Internal enterprise host
        elif node.startswith("192.168.1.105") or node.startswith("185.220"):
            node_colors.append("#EF4444")  # Known attacker
        elif node.startswith("198.51.100"):
            node_colors.append("#F97316")  # External sink/scanner
        else:
            node_colors.append("#00F2FE")

    fig.add_trace(go.Sankey(
        node=dict(
            pad=15,
            thickness=16,
            line=dict(color="#1E293B", width=1),
            label=all_nodes,
            color=node_colors
        ),
        link=dict(
            source=links_src,
            target=links_tgt,
            value=links_val,
            color=links_color,
            customdata=links_customdata,
            hovertemplate="Attack Path: %{source.label} &rarr; %{target.label}<br>Flow Count: %{value}<br>Vector: %{customdata}<extra></extra>"
        )
    ))

    fig.update_layout(
        paper_bgcolor="rgba(11, 17, 32, 0.7)",
        plot_bgcolor="rgba(8, 12, 22, 0.6)",
        font=dict(color="#F8FAFC", family="Plus Jakarta Sans", size=11),
        height=380,
        margin=dict(t=30, b=20, l=20, r=20)
    )

    return fig
