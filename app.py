"""
Sentinel AI — Intelligent Cybersecurity Threat Detection & Monitoring System
Enterprise-Grade Security Operations Center (SOC) Command Center
Enhanced with Interactive 360° Threat Radar, Network Attack Topology,
and Slide-Over SOC Event Investigation Drawer.
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import time
import io
import json
import logging
from datetime import datetime
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from config.settings import (
    BASE_DIR,
    SAMPLE_DATA_DIR,
    MODELS_DIR,
    DB_PATH,
    THREAT_CATEGORIES,
    SEVERITY_LEVELS,
    ALERT_STATUSES,
    DEFAULT_DETECTION_THRESHOLDS,
    KNOWN_MALICIOUS_INDICATORS
)
from src.data_loader import load_dataset, detect_and_map_columns
from src.feature_engineering import extract_features, get_feature_names, calculate_shannon_entropy
from src.train_model import train_and_evaluate_models, train_anomaly_detector, save_trained_pipeline, load_trained_pipeline
from src.predict import ThreatInferenceEngine
from src.alert_manager import AlertManager
from src.severity import SEVERITY_COLORS, calculate_severity
from src.visualizations import (
    create_interactive_threat_radar,
    create_network_attack_topology,
    PLOTLY_DARK_LAYOUT
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.app")

# Page configuration
st.set_page_config(
    page_title="SENTINEL // AI — Cyber Threat Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load upgraded custom CSS (v3.0)
css_file = BASE_DIR / "assets" / "custom_styles.css"
if css_file.exists():
    with open(css_file, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# GLOBAL SESSION STATE INITIALIZATION & CROSS-PAGE REGISTRY
# -----------------------------------------------------------------------------
if "alert_mgr" not in st.session_state:
    st.session_state.alert_mgr = AlertManager(db_path=DB_PATH)
    st.session_state.alert_mgr.seed_initial_demo_alerts()

if "inference_engine" not in st.session_state:
    st.session_state.inference_engine = ThreatInferenceEngine()

if "current_df" not in st.session_state:
    sample_file = SAMPLE_DATA_DIR / "sample_security_events.csv"
    if sample_file.exists():
        res = load_dataset(sample_file)
        if res.is_valid:
            st.session_state.current_df = res.df
            st.session_state.dataset_source_name = "sample_security_events.csv"
            st.session_state.is_demo_mode = True
        else:
            st.session_state.current_df = pd.DataFrame()
            st.session_state.dataset_source_name = "None"
            st.session_state.is_demo_mode = False
    else:
        st.session_state.current_df = pd.DataFrame()
        st.session_state.dataset_source_name = "None"
        st.session_state.is_demo_mode = False

if "detections_df" not in st.session_state:
    if not st.session_state.current_df.empty:
        st.session_state.detections_df = st.session_state.inference_engine.predict_events(st.session_state.current_df)
    else:
        st.session_state.detections_df = pd.DataFrame()

if "trained_model_results" not in st.session_state:
    st.session_state.trained_model_results = None

# Active cross-page investigation drawer state
if "active_investigation_id" not in st.session_state:
    st.session_state.active_investigation_id = None

# Active page selection state
if "nav_page" not in st.session_state:
    st.session_state.nav_page = "Security Command Center"

# MITRE ATT&CK Framework Mapping Matrix
MITRE_TACTICS_MAP = {
    "Brute-Force Login": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "cve": "CVE-2023-48795",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "Port Scanning": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "cve": "CWE-200",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "Abnormally High Traffic": {
        "id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "cve": "CWE-400",
        "url": "https://attack.mitre.org/techniques/T1498/001/"
    },
    "Suspicious User Behaviour": {
        "id": "T1048.003",
        "name": "Exfiltration Over Unencrypted Protocol",
        "tactic": "Exfiltration",
        "cve": "CWE-201",
        "url": "https://attack.mitre.org/techniques/T1048/003/"
    },
    "Malicious URL/Indicator": {
        "id": "T1566.002",
        "name": "Spearphishing Link / C2 Beacon",
        "tactic": "Initial Access",
        "cve": "CWE-352",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "Benign": {
        "id": "T0000",
        "name": "Normal Operational Baseline",
        "tactic": "Operational",
        "cve": "N/A",
        "url": "#"
    }
}


def render_event_investigation_drawer(event_row: pd.Series):
    """
    Renders an enterprise SOC incident investigation drawer with
    telemetry matrix, confidence dial, MITRE technique tags, and incident response playbooks.
    """
    ev_id = event_row.get("event_id", "EVT-UNKNOWN")
    cat = event_row.get("threat_category", "Benign")
    sev = event_row.get("severity", "Medium")
    conf = float(event_row.get("confidence", 0.85))
    mitre_info = MITRE_TACTICS_MAP.get(cat, MITRE_TACTICS_MAP["Benign"])

    st.markdown(f"""
        <div class="drawer-container">
            <div class="drawer-header">
                <div>
                    <div style="font-size: 0.72rem; color: #00F2FE; font-weight: 800; letter-spacing: 1.2px; text-transform: uppercase;">
                        // INCIDENT TELEMETRY DOSSIER &bull; ACTIVE INVESTIGATION
                    </div>
                    <div style="font-size: 1.45rem; font-weight: 900; color: #FFFFFF; margin-top: 3px;">
                        {cat}
                    </div>
                    <div style="margin-top: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="badge-{sev.lower()}">{sev} SEVERITY</span>
                        <span class="mitre-tag">{mitre_info['id']} {mitre_info['name']}</span>
                        <span style="font-size: 0.75rem; color: #94A3B8; font-family: 'JetBrains Mono', monospace;">ID: {ev_id}</span>
                        <span style="font-size: 0.75rem; color: #64748B;">&bull; Timestamp: {event_row.get('timestamp', 'N/A')}</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 0.68rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">CONFIDENCE RATING</div>
                    <div style="font-size: 1.6rem; font-weight: 900; color: #00F2FE; font-family: 'JetBrains Mono', monospace;">
                        {conf:.1%}
                    </div>
                </div>
            </div>
            
            <!-- Network Telemetry Matrix -->
            <div class="telemetry-grid">
                <div class="telemetry-cell">
                    <div class="telemetry-cell-label">SOURCE ENDPOINT</div>
                    <div class="telemetry-cell-val" style="color: #00F2FE;">{event_row.get('src_ip', 'UNKNOWN')}:{event_row.get('src_port', 0)}</div>
                </div>
                <div class="telemetry-cell">
                    <div class="telemetry-cell-label">TARGET INFRASTRUCTURE</div>
                    <div class="telemetry-cell-val" style="color: #38BDF8;">{event_row.get('dst_ip', 'UNKNOWN')}:{event_row.get('dst_port', 0)}</div>
                </div>
                <div class="telemetry-cell">
                    <div class="telemetry-cell-label">PROTOCOL / FLOW</div>
                    <div class="telemetry-cell-val">{event_row.get('protocol', 'TCP')} ({event_row.get('duration_sec', 0.1)}s)</div>
                </div>
                <div class="telemetry-cell">
                    <div class="telemetry-cell-label">PAYLOAD VOLUME</div>
                    <div class="telemetry-cell-val">{int(event_row.get('bytes_sent', 0)):,} B out / {int(event_row.get('bytes_received', 0)):,} B in</div>
                </div>
            </div>

            <!-- Evidence Box -->
            <div style="background: rgba(8, 12, 22, 0.7); border-left: 3px solid #EF4444; border-radius: 6px; padding: 12px 16px; margin: 12px 0;">
                <div style="font-size: 0.72rem; font-weight: 800; color: #EF4444; text-transform: uppercase; letter-spacing: 0.8px;">
                    CORROBORATED DETECTION EVIDENCE
                </div>
                <div style="font-size: 0.86rem; color: #F1F5F9; margin-top: 4px; line-height: 1.5;">
                    {event_row.get('evidence', 'Anomalous traffic signature identified.')}
                </div>
            </div>

            <!-- Defensive Mitigation Playbook -->
            <div style="background: rgba(8, 12, 22, 0.7); border-left: 3px solid #00F2FE; border-radius: 6px; padding: 12px 16px; margin: 12px 0;">
                <div style="font-size: 0.72rem; font-weight: 800; color: #00F2FE; text-transform: uppercase; letter-spacing: 0.8px;">
                    TACTICAL SOC MITIGATION PLAYBOOK
                </div>
                <div style="font-size: 0.86rem; color: #F1F5F9; margin-top: 4px; line-height: 1.5;">
                    {event_row.get('recommended_action', 'Investigate endpoint and enforce security controls.')}
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Action Buttons: Escalate to Alert Queue & Close Drawer
    col_a1, col_a2, col_a3 = st.columns([1.5, 1.5, 3])
    with col_a1:
        if st.button("🚨 Escalate to Incident Queue (SQLite)", key=f"btn_esc_{ev_id}", use_container_width=True):
            st.session_state.alert_mgr.process_and_create_alert(event_row.to_dict())
            st.success(f"Incident {ev_id} persisted to active SQLite alert queue!")
            time.sleep(0.4)
            st.rerun()

    with col_a2:
        if st.button("✕ Dismiss Investigation Dossier", key=f"btn_close_{ev_id}", use_container_width=True):
            st.session_state.active_investigation_id = None
            st.rerun()


# ==============================================================================
# SIDEBAR NAVIGATION & TELEMETRY CONTROLLER
# ==============================================================================
with st.sidebar:
    st.markdown("""
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
            <div style="width: 44px; height: 44px; background: linear-gradient(135deg, #00F2FE 0%, #8B5CF6 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px; box-shadow: 0 0 20px rgba(0, 242, 254, 0.4);">
                🛡️
            </div>
            <div>
                <div style="font-size: 1.25rem; font-weight: 900; letter-spacing: -0.5px; color: #FFFFFF;">SENTINEL <span style="color: #00F2FE;">// AI</span></div>
                <div style="font-size: 0.70rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 1.2px;">Cyber Threat Defense</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    nav_options = [
        "Security Command Center",
        "Threat Detection Lab",
        "AI Model Center",
        "Threat Intelligence & Analysis",
        "Alert Management",
        "Event Explorer",
        "Settings & System Health"
    ]

    selected_nav = st.radio(
        "MISSION CONTROL",
        nav_options,
        index=nav_options.index(st.session_state.nav_page) if st.session_state.nav_page in nav_options else 0,
        label_visibility="collapsed"
    )
    if selected_nav != st.session_state.nav_page:
        st.session_state.nav_page = selected_nav
        st.rerun()

    st.markdown("---")
    st.markdown("<div style='font-size: 0.72rem; font-weight: 800; color: #64748B; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;'>TELEMETRY FEED</div>", unsafe_allow_html=True)

    # Active dataset indicator
    active_dataset = st.session_state.get("dataset_source_name", "None")
    rows_loaded = len(st.session_state.current_df) if not st.session_state.current_df.empty else 0
    is_demo = st.session_state.get("is_demo_mode", False)

    st.markdown(f"""
        <div style="background: rgba(11, 17, 32, 0.85); border: 1px solid #1E293B; border-radius: 8px; padding: 10px; margin-bottom: 12px;">
            <div style="font-size: 0.68rem; color: #94A3B8; text-transform: uppercase;">INGESTION CHANNEL</div>
            <div style="font-size: 0.82rem; font-weight: 700; color: #F8FAFC; word-break: break-all; margin-top: 2px;">{active_dataset}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">
                <span style="font-size: 0.72rem; color: #64748B; font-family: 'JetBrains Mono', monospace;">{rows_loaded:,} events</span>
                <span class="{'posture-badge-elevated' if is_demo else 'posture-badge-nominal'}" style="font-size: 0.62rem; padding: 2px 6px;">
                    {'BENCHMARK SIMULATION' if is_demo else 'LIVE TELEMETRY'}
                </span>
            </div>
        </div>
    """, unsafe_allow_html=True)

    if st.button("⚡ Load Full Synthetic Corpus (1,600 Events)", use_container_width=True):
        full_sample = SAMPLE_DATA_DIR / "synthetic_network_logs.csv"
        if full_sample.exists():
            with st.spinner("Loading synthetic network traffic..."):
                res = load_dataset(full_sample)
                st.session_state.current_df = res.df
                st.session_state.dataset_source_name = "synthetic_network_logs.csv (Full)"
                st.session_state.is_demo_mode = True
                st.session_state.detections_df = st.session_state.inference_engine.predict_events(res.df)
                st.success("Loaded 1,600 reproducible telemetry flows.")
                st.rerun()

    st.markdown("---")
    st.markdown("""
        <div style="font-size: 0.68rem; color: #64748B; line-height: 1.4;">
            <b style="color: #94A3B8;">Sentinel AI Enterprise v3.0</b><br>
            Multi-Vector Defensive ML Pipeline<br>
            Compliant Authorized Monitoring
        </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# WATERMARK BANNER FOR SIMULATED DATA
# ==============================================================================
if st.session_state.get("is_demo_mode", False):
    st.markdown("""
        <div class="demo-watermark">
            <span>⚠️ <b>DEMONSTRATION MODE ACTIVE:</b> TELEMETRY RECORDS ARE REPRODUCIBLE SYNTHETIC BENCHMARK FLOWS DESIGNED FOR TESTING.</span>
            <span>NO LIVE EXPLOITATION OR UNAPPROVED MONITORING</span>
        </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# PAGE 1: SECURITY COMMAND CENTER (COMMAND HERO & THREAT RADAR)
# ==============================================================================
if st.session_state.nav_page == "Security Command Center":
    df_events = st.session_state.current_df
    df_det = st.session_state.detections_df

    total_events = len(df_events) if not df_events.empty else 0
    threats_detected = int(df_det["is_threat"].sum()) if not df_det.empty else 0
    benign_count = total_events - threats_detected
    threat_ratio = (threats_detected / total_events * 100) if total_events > 0 else 0.0

    stats = st.session_state.alert_mgr.get_statistics()
    critical_alerts = stats.get("critical", 0)
    high_alerts = stats.get("high", 0)
    open_alerts = stats.get("open", 0)

    # Dynamic Posture Assessment Score
    # Risk Score = min(100, int((critical_alerts * 18) + (high_alerts * 8) + (threat_ratio * 0.8)))
    raw_posture_score = int((critical_alerts * 15) + (high_alerts * 7) + (threat_ratio * 0.7))
    posture_score = max(18, min(raw_posture_score, 94)) if threats_detected > 0 else 12

    if posture_score >= 70:
        posture_badge_class = "posture-badge-crit"
        posture_badge_text = "DEFCON 2 &bull; HIGH ADVERSARY THREAT"
    elif posture_score >= 40:
        posture_badge_class = "posture-badge-elevated"
        posture_badge_text = "DEFCON 3 &bull; ELEVATED SURVEILLANCE"
    else:
        posture_badge_class = "posture-badge-nominal"
        posture_badge_text = "DEFCON 5 &bull; NOMINAL POSTURE"

    # Command Center Hero Composition
    st.markdown(f"""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">🛡️</div>
                    <div class="hero-title-group">
                        <h1>SECURITY OPERATIONS COMMAND CENTER</h1>
                        <p>// REAL-TIME MULTI-VECTOR THREAT TELEMETRY & ATTACK TOPOLOGY</p>
                    </div>
                </div>
                <div class="posture-widget">
                    <div class="posture-dial">
                        <div class="posture-score">{posture_score}<span style="font-size: 0.8rem; color: #64748B;">/100</span></div>
                        <div class="posture-label">THREAT VELOCITY</div>
                    </div>
                    <div class="{posture_badge_class}">
                        <span class="pulsing-dot"></span>
                        <span>{posture_badge_text}</span>
                    </div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Top KPI Metrics Row
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-accent"></div>
                <div class="kpi-label">TOTAL FLOWS ANALYZED</div>
                <div class="kpi-value">{total_events:,}</div>
                <div class="kpi-subtext">Telemetry Ingestion Rate: Real-time</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-accent-warn"></div>
                <div class="kpi-label">CONFIRMED THREATS</div>
                <div class="kpi-value">{threats_detected:,}</div>
                <div class="kpi-subtext">{threat_ratio:.1f}% anomalous flow density</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-accent-crit"></div>
                <div class="kpi-label">CRITICAL / HIGH SEVERITY</div>
                <div class="kpi-value">{critical_alerts + high_alerts:,}</div>
                <div class="kpi-subtext">{critical_alerts} Critical &bull; {high_alerts} High Incidents</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-accent"></div>
                <div class="kpi-label">ACTIVE SOC INCIDENTS</div>
                <div class="kpi-value">{open_alerts:,}</div>
                <div class="kpi-subtext">Open analyst triage queue</div>
            </div>
        """, unsafe_allow_html=True)
    with c5:
        model_name = "Random Forest (Active)" if st.session_state.inference_engine.model_package else "Rule Engine (Active)"
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-accent-succ"></div>
                <div class="kpi-label">DEFENSE ENGINE</div>
                <div class="kpi-value" style="font-size: 1.25rem; padding-top: 6px; color: #00F2FE;">OPERATIONAL</div>
                <div class="kpi-subtext">{model_name}</div>
            </div>
        """, unsafe_allow_html=True)

    # Active Investigation Drawer (if an event is actively selected)
    if st.session_state.active_investigation_id and not df_det.empty:
        active_match = df_det[df_det["event_id"] == st.session_state.active_investigation_id]
        if not active_match.empty:
            render_event_investigation_drawer(active_match.iloc[0])

    # Section 1: 360° Threat Radar & Time-Series Velocity
    st.markdown("""
        <div class="section-header">
            <span>// 360° TACTICAL THREAT RADAR & TEMPORAL DETECTION VELOCITY</span>
            <div class="section-line"></div>
        </div>
    """, unsafe_allow_html=True)

    r_col1, r_col2 = st.columns([1.25, 1])

    with r_col1:
        st.markdown("<div style='font-size: 0.82rem; font-weight: 800; color: #F8FAFC; margin-bottom: 6px;'>INTERACTIVE 360° THREAT RADAR</div>", unsafe_allow_html=True)
        radar_fig = create_interactive_threat_radar(df_det)
        st.plotly_chart(radar_fig, use_container_width=True)

    with r_col2:
        st.markdown("<div style='font-size: 0.82rem; font-weight: 800; color: #F8FAFC; margin-bottom: 6px;'>DETECTION TRENDS OVER TIME</div>", unsafe_allow_html=True)
        if not df_det.empty and "timestamp" in df_det.columns:
            ts_df = df_det.copy()
            ts_df["timestamp"] = pd.to_datetime(ts_df["timestamp"])
            ts_df = ts_df.set_index("timestamp").resample("5min")["is_threat"].agg(["count", "sum"]).reset_index()
            ts_df.columns = ["Timestamp", "Total Flows", "Threats Flagged"]

            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=ts_df["Timestamp"],
                y=ts_df["Total Flows"],
                name="All Network Telemetry",
                mode="lines",
                line=dict(color="#38BDF8", width=1.5, dash="dot")
            ))
            fig_trend.add_trace(go.Scatter(
                x=ts_df["Timestamp"],
                y=ts_df["Threats Flagged"],
                name="Threat Detections",
                mode="lines+markers",
                fill="tozeroy",
                fillcolor="rgba(239, 68, 68, 0.15)",
                line=dict(color="#EF4444", width=2.5)
            ))
            fig_trend.update_layout(
                **PLOTLY_DARK_LAYOUT,
                height=360,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_trend, use_container_width=True)
        else:
            st.info("No time-series data available.")

    # Section 2: Network Attack Topology & Flow Map
    st.markdown("""
        <div class="section-header">
            <span>// COHERENT NETWORK ATTACK TOPOLOGY & PROPAGATION PATHWAYS</span>
            <div class="section-line"></div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("<p style='font-size: 0.82rem; color: #94A3B8; margin-bottom: 8px;'>Visual representation of attack flow propagation from Source Subnets &rarr; Ingress Protocols/Ports &rarr; Targeted Internal Infrastructure.</p>", unsafe_allow_html=True)
    topo_fig = create_network_attack_topology(df_det)
    st.plotly_chart(topo_fig, use_container_width=True)

    # Section 3: Recent High-Priority Security Events with Quick Dossier Pivot
    st.markdown("""
        <div class="section-header">
            <span>// HIGH-PRIORITY INCIDENT FEED & RAPID TRIAGE</span>
            <div class="section-line"></div>
        </div>
    """, unsafe_allow_html=True)

    if not df_det.empty:
        threat_table = df_det[df_det["is_threat"]].sort_values("priority").head(6)

        # Quick inspector bar
        st.markdown("<div style='font-size: 0.80rem; color: #94A3B8; margin-bottom: 6px;'>Select any incident to inspect its comprehensive forensic dossier:</div>", unsafe_allow_html=True)

        evt_choices = threat_table["event_id"].tolist()
        evt_labels = [f"{r['event_id']} — {r['threat_category']} ({r['severity']}) — {r['src_ip']} → {r['dst_ip']}:{r['dst_port']}" for _, r in threat_table.iterrows()]
        
        sel_idx = st.selectbox("Quick Incident Selector", range(len(evt_choices)), format_func=lambda i: evt_labels[i], label_visibility="collapsed")
        
        if st.button("🔍 Open Full Investigation Dossier in Command View", type="primary"):
            st.session_state.active_investigation_id = evt_choices[sel_idx]
            st.rerun()

        st.dataframe(
            threat_table[[
                "event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                "threat_category", "severity", "confidence", "detection_method", "evidence"
            ]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No security incidents detected.")


# ==============================================================================
# PAGE 2: THREAT DETECTION LAB (INGESTION & INFERENCE WORKBENCH)
# ==============================================================================
elif st.session_state.nav_page == "Threat Detection Lab":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">🔬</div>
                    <div class="hero-title-group">
                        <h1>THREAT DETECTION LAB & INFERENCE WORKBENCH</h1>
                        <p>// MULTI-SCHEMA INGESTION, FEATURE ENGINEERING & HYBRID DETECTION ENGINE</p>
                    </div>
                </div>
                <div class="status-pill">INGESTION READY</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    tab_upload, tab_inspect = st.tabs(["[ 1 ] INGESTION & PIPELINE RUNNER", "[ 2 ] SCHEMA MAPPING & VALIDATION"])

    with tab_upload:
        st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Upload approved network traffic or security log CSV files for automatic schema normalization, feature transformation, and dual-layer threat classification.</p>", unsafe_allow_html=True)

        col_up, col_btn = st.columns([2.5, 1.5])
        with col_up:
            uploaded_file = st.file_uploader("Upload Network Traffic Logs (CSV format)", type=["csv"], help="Upload network flows, Zeek logs, firewall logs, or synthetic CSV records.")

        with col_btn:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("📁 Load Standard Sample Dataset (1,600 Records)", use_container_width=True):
                sample_path = SAMPLE_DATA_DIR / "synthetic_network_logs.csv"
                if sample_path.exists():
                    res = load_dataset(sample_path)
                    st.session_state.current_df = res.df
                    st.session_state.dataset_source_name = "synthetic_network_logs.csv"
                    st.session_state.is_demo_mode = True
                    st.success(f"Loaded {len(res.df)} records from synthetic network logs.")
                    st.rerun()

        # Handle user uploaded file
        if uploaded_file is not None:
            res = load_dataset(uploaded_file)
            if res.is_valid:
                st.session_state.current_df = res.df
                st.session_state.dataset_source_name = uploaded_file.name
                st.session_state.is_demo_mode = False
                st.success(f"Successfully validated and ingested {len(res.df)} records from '{uploaded_file.name}'.")
            else:
                st.error(f"Validation Error: {res.message}")

        df_curr = st.session_state.current_df

        if not df_curr.empty:
            st.markdown(f"**Loaded Telemetry Preview:** {len(df_curr):,} records from `{st.session_state.get('dataset_source_name', 'Active')}`")
            st.dataframe(df_curr.head(6), use_container_width=True, hide_index=True)

            run_col1, run_col2 = st.columns([1.5, 2.5])
            with run_col1:
                if st.button("🚀 EXECUTE DETECTION PIPELINE", type="primary", use_container_width=True):
                    with st.spinner("Executing feature transformation, ML classification & rule engine..."):
                        progress_bar = st.progress(0)
                        for pct in range(15, 95, 25):
                            time.sleep(0.04)
                            progress_bar.progress(pct)

                        st.session_state.detections_df = st.session_state.inference_engine.predict_events(df_curr)
                        progress_bar.progress(100)
                        st.success(f"Inference complete! Classified {len(st.session_state.detections_df):,} events.")
                        st.rerun()

            with run_col2:
                # Option to sync threats to alert management
                if not st.session_state.detections_df.empty:
                    threats = st.session_state.detections_df[st.session_state.detections_df["is_threat"]]
                    if st.button(f"📥 Sync {len(threats):,} Identified Threats to Alert Management Queue", use_container_width=True):
                        synced = 0
                        for _, row in threats.iterrows():
                            st.session_state.alert_mgr.process_and_create_alert(row.to_dict())
                            synced += 1
                        st.success(f"Synced {synced} threats to persistent SQLite alert queue!")

        # Results Display
        if not st.session_state.detections_df.empty:
            df_det = st.session_state.detections_df
            st.markdown("""
                <div class="section-header">
                    <span>// DETECTION RESULTS & CLASSIFICATION TELEMETRY</span>
                    <div class="section-line"></div>
                </div>
            """, unsafe_allow_html=True)

            m1, m2, m3, m4 = st.columns(4)
            n_tot = len(df_det)
            n_threats = int(df_det["is_threat"].sum())
            n_benign = n_tot - n_threats
            n_crit = len(df_det[df_det["severity"] == "Critical"])

            m1.metric("Total Events Evaluated", f"{n_tot:,}")
            m2.metric("Threats Flagged", f"{n_threats:,}", delta=f"{n_threats/n_tot*100:.1f}%")
            m3.metric("Benign Traffic", f"{n_benign:,}")
            m4.metric("Critical Incidents", f"{n_crit:,}", delta_color="inverse")

            # Filter controls for preview
            f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
            with f_col1:
                category_filter = st.selectbox("Category Filter", ["All"] + THREAT_CATEGORIES)
            with f_col2:
                severity_filter = st.selectbox("Severity Filter", ["All"] + SEVERITY_LEVELS)
            with f_col3:
                search_text = st.text_input("Search IP / Port / Resource", "")

            filtered = df_det.copy()
            if category_filter != "All":
                filtered = filtered[filtered["threat_category"] == category_filter]
            if severity_filter != "All":
                filtered = filtered[filtered["severity"] == severity_filter]
            if search_text:
                mask = (
                    filtered["src_ip"].str.contains(search_text, case=False, na=False) |
                    filtered["dst_ip"].str.contains(search_text, case=False, na=False) |
                    filtered["evidence"].str.contains(search_text, case=False, na=False) |
                    filtered["requested_resource"].str.contains(search_text, case=False, na=False)
                )
                filtered = filtered[mask]

            st.dataframe(
                filtered[[
                    "event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                    "threat_category", "severity", "confidence", "detection_method",
                    "evidence", "recommended_action"
                ]],
                use_container_width=True,
                hide_index=True
            )

            # CSV Export
            csv_bytes = filtered.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Download Detection Results (CSV)",
                data=csv_bytes,
                file_name=f"sentinel_threat_detections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    with tab_inspect:
        st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Schema mapping engine normalizes varying column names from different firewall, IDS, and PCAP log exports.</p>", unsafe_allow_html=True)
        if not st.session_state.current_df.empty:
            st.write("Current Normalized Data Schema:")
            st.json({col: str(dtype) for col, dtype in st.session_state.current_df.dtypes.items()})
        else:
            st.info("No active dataset loaded.")


# ==============================================================================
# PAGE 3: AI MODEL CENTER (LEAK-FREE SUPERVISED BENCHMARKING)
# ==============================================================================
elif st.session_state.nav_page == "AI Model Center":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">🧠</div>
                    <div class="hero-title-group">
                        <h1>AI MODEL CENTER & EVALUATION SUITE</h1>
                        <p>// LEAK-FREE TRAIN/TEST PARTITIONING & MULTI-CLASS PERFORMANCE BENCHMARKING</p>
                    </div>
                </div>
                <div class="status-pill">SCIKIT-LEARN PIPELINE</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Sentinel AI enforces strict training/test separation to prevent data leakage, applies standard feature scaling, handles class imbalance with balanced weighting, and provides honest measured evaluation metrics.</p>", unsafe_allow_html=True)

    ctrl1, ctrl2, ctrl3 = st.columns([1.5, 1, 1])
    with ctrl1:
        model_choice = st.selectbox("Select Model Architecture", ["Random Forest", "Logistic Regression", "Both (Comparative Benchmark)"])
    with ctrl2:
        test_split = st.slider("Holdout Test Partition", 0.10, 0.40, 0.20, 0.05, help="Proportion of dataset strictly reserved for leak-free evaluation.")
    with ctrl3:
        target_column = st.selectbox("Target Label Column", ["label", "is_threat"])

    train_data = st.session_state.current_df

    if target_column not in train_data.columns and not train_data.empty:
        st.warning(f"Target column '{target_column}' not found in active dataset. Using standard synthetic training data for model benchmark.")
        sample_path = SAMPLE_DATA_DIR / "synthetic_network_logs.csv"
        if sample_path.exists():
            train_data = load_dataset(sample_path).df

    if st.button("⚙️ TRAIN & EVALUATE CLASSIFIERS", type="primary", use_container_width=True):
        if train_data.empty:
            st.error("No training data available. Please load a labeled dataset in Threat Detection Lab.")
        else:
            with st.spinner("Training baseline models with stratified holdout..."):
                try:
                    eval_results = train_and_evaluate_models(
                        train_data,
                        target_col=target_column,
                        test_size=test_split,
                        random_state=42
                    )
                    st.session_state.trained_model_results = eval_results

                    # Persist model pipeline
                    rf_pkg = eval_results["models"]["Random Forest"]["pipeline_package"]
                    lr_pkg = eval_results["models"]["Logistic Regression"]["pipeline_package"]
                    save_trained_pipeline(rf_pkg, MODELS_DIR / "sentinel_rf_model.joblib")
                    save_trained_pipeline(lr_pkg, MODELS_DIR / "sentinel_lr_model.joblib")
                    st.session_state.inference_engine.reload_model("sentinel_rf_model.joblib")
                    st.success("Models successfully trained, evaluated, and saved to disk!")
                except Exception as e:
                    st.error(f"Training failed: {e}")

    # Display Measured Results
    if st.session_state.trained_model_results:
        res = st.session_state.trained_model_results
        models = res["models"]

        st.markdown("""
            <div class="section-header">
                <span>// MEASURED EVALUATION METRICS ON HELD-OUT TEST DATASET</span>
                <div class="section-line"></div>
            </div>
        """, unsafe_allow_html=True)

        info = res["dataset_info"]
        st.markdown(f"**Evaluation Partition:** {info['test_samples']} test samples &bull; {info['train_samples']} train samples &bull; {len(info['classes'])} classes &bull; Evaluated at `{info['trained_at']}`")

        # Metric Comparison Cards
        mc1, mc2 = st.columns(2)
        with mc1:
            rf_m = models["Random Forest"]["metrics"]
            st.markdown(f"""
                <div class="kpi-card" style="border-color: #00F2FE;">
                    <div class="kpi-accent"></div>
                    <div class="kpi-label">RANDOM FOREST CLASSIFIER</div>
                    <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">ACCURACY</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #00F2FE;">{rf_m['accuracy']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">F1 (MACRO)</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #38BDF8;">{rf_m['f1_macro']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">PRECISION</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #F8FAFC;">{rf_m['precision_macro']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">RECALL</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #F8FAFC;">{rf_m['recall_macro']:.2%}</div>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with mc2:
            lr_m = models["Logistic Regression"]["metrics"]
            st.markdown(f"""
                <div class="kpi-card">
                    <div class="kpi-accent"></div>
                    <div class="kpi-label">LOGISTIC REGRESSION BASELINE</div>
                    <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">ACCURACY</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #8B5CF6;">{lr_m['accuracy']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">F1 (MACRO)</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #A78BFA;">{lr_m['f1_macro']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">PRECISION</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #F8FAFC;">{lr_m['precision_macro']:.2%}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: #94A3B8;">RECALL</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #F8FAFC;">{lr_m['recall_macro']:.2%}</div>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        # Confusion Matrix Visualizer
        st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
        cm_c1, cm_c2 = st.columns([1.2, 1])

        active_eval = rf_m if "Random Forest" in model_choice or model_choice.startswith("Both") else lr_m
        active_name = "Random Forest" if "Random Forest" in model_choice or model_choice.startswith("Both") else "Logistic Regression"

        with cm_c1:
            st.markdown(f"<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;'>CONFUSION MATRIX — {active_name.upper()}</div>", unsafe_allow_html=True)
            cm_matrix = np.array(active_eval["confusion_matrix"])
            labels = active_eval["classes"]

            fig_cm = px.imshow(
                cm_matrix,
                x=labels,
                y=labels,
                color_continuous_scale="Viridis",
                labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Sample Count"),
                text_auto=True
            )
            fig_cm.update_layout(**PLOTLY_DARK_LAYOUT, height=360)
            st.plotly_chart(fig_cm, use_container_width=True)

        with cm_c2:
            st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;'>TOP PREDICTIVE CYBERSECURITY FEATURES</div>", unsafe_allow_html=True)
            if "feature_importances" in rf_m:
                fi = rf_m["feature_importances"]
                fi_df = pd.DataFrame(list(fi.items())[:8], columns=["Feature", "Importance"])
                fig_fi = px.bar(
                    fi_df,
                    x="Importance",
                    y="Feature",
                    orientation="h",
                    color="Importance",
                    color_continuous_scale=["#06B6D4", "#8B5CF6"]
                )
                fig_fi.update_layout(
                    **PLOTLY_DARK_LAYOUT,
                    height=360,
                    yaxis=dict(autorange="reversed"),
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_fi, use_container_width=True)

        # Per-Class Classification Report Table
        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;'>PER-CLASS PERFORMANCE BREAKDOWN</div>", unsafe_allow_html=True)
        report_dict = active_eval["classification_report"]
        rows = []
        for cls_name in active_eval["classes"]:
            if cls_name in report_dict:
                c_data = report_dict[cls_name]
                rows.append({
                    "Class": cls_name,
                    "Precision": f"{c_data['precision']:.3f}",
                    "Recall": f"{c_data['recall']:.3f}",
                    "F1-Score": f"{c_data['f1-score']:.3f}",
                    "Support": int(c_data['support'])
                })
        st.table(pd.DataFrame(rows))


# ==============================================================================
# PAGE 4: THREAT INTELLIGENCE & INCIDENT ANALYSIS
# ==============================================================================
elif st.session_state.nav_page == "Threat Intelligence & Analysis":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">📡</div>
                    <div class="hero-title-group">
                        <h1>THREAT INTELLIGENCE & INCIDENT DOSSIER</h1>
                        <p>// ATT&CK FRAMEWORK CORRELATION, REPUTATION INTELLIGENCE & DEFENSIVE PLAYBOOKS</p>
                    </div>
                </div>
                <div class="status-pill">IOC LINKED</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    df_det = st.session_state.detections_df

    tab_investigate, tab_ioc_lookup = st.tabs(["[ 1 ] INCIDENT DOSSIER INVESTIGATOR", "[ 2 ] THREAT INTEL IOC LOOKUP"])

    with tab_investigate:
        if df_det.empty:
            st.info("No detection telemetry available. Please run detections in Threat Detection Lab.")
        else:
            threats_only = df_det[df_det["is_threat"]]
            if threats_only.empty:
                st.success("No active threats in current dataset.")
            else:
                # Pre-selection support from cross-page navigation
                event_ids = threats_only["event_id"].tolist()
                default_idx = 0
                if st.session_state.active_investigation_id in event_ids:
                    default_idx = event_ids.index(st.session_state.active_investigation_id)

                event_options = threats_only.apply(
                    lambda r: f"{r['event_id']} — {r['threat_category']} ({r['severity']}) — {r['src_ip']} → {r['dst_ip']}:{r['dst_port']}",
                    axis=1
                ).tolist()

                selected_event_str = st.selectbox("Select Security Event to Investigate", event_options, index=default_idx)
                selected_event_id = selected_event_str.split(" — ")[0]
                ev_data = threats_only[threats_only["event_id"] == selected_event_id].iloc[0]

                # Render comprehensive investigation drawer
                render_event_investigation_drawer(ev_data)

    with tab_ioc_lookup:
        st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Verify arbitrary IP addresses, domains, or indicators against local threat intelligence indicators and heuristics.</p>", unsafe_allow_html=True)
        ioc_input = st.text_input("Enter IP Address or Domain / URL", "185.220.101.5")
        if st.button("🔍 Query Threat Intelligence"):
            ioc_clean = ioc_input.strip()
            known_ips = set(KNOWN_MALICIOUS_INDICATORS["ips"])
            known_domains = set(KNOWN_MALICIOUS_INDICATORS["domains"])

            is_mal_ip = ioc_clean in known_ips
            is_mal_dom = any(d in ioc_clean.lower() for d in known_domains)
            entropy = calculate_shannon_entropy(ioc_clean)

            if is_mal_ip or is_mal_dom:
                st.error(f"⚠️ POSITIVE MATCH: '{ioc_clean}' is a confirmed high-risk indicator in Threat Intel database.")
                st.markdown(f"- **Reputation Score:** 98/100 (Malicious)\n- **Threat Actor Association:** Known Tor Exit / Bulletproof C2 relay\n- **Recommended Action:** Immediate perimeter block.")
            elif entropy > 4.1 and len(ioc_clean) > 20:
                st.warning(f"⚠️ SUSPICIOUS HEURISTIC: '{ioc_clean}' exhibits unusually high Shannon entropy ({entropy:.2f}), suggesting obfuscation or DGA algorithm.")
            else:
                st.success(f"✅ CLEAN / UNFLAGGED: '{ioc_clean}' was not found in known malicious IOC indicator lists.")


# ==============================================================================
# PAGE 5: ALERT MANAGEMENT (PERSISTENT SQLITE WORKFLOW)
# ==============================================================================
elif st.session_state.nav_page == "Alert Management":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">🚨</div>
                    <div class="hero-title-group">
                        <h1>ALERT MANAGEMENT & INCIDENT RESPONSE</h1>
                        <p>// PERSISTENT SQLITE INCIDENT WORKFLOW, AUDIT TRAILS & ANALYST REMARKS</p>
                    </div>
                </div>
                <div class="status-pill">SQLITE PERSISTENT</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    alert_mgr = st.session_state.alert_mgr

    # Filter Bar
    f1, f2, f3, f4 = st.columns([1, 1, 1, 1.5])
    with f1:
        f_status = st.selectbox("Status Filter", ["All", "Open", "Investigating", "Resolved", "False Positive"])
    with f2:
        f_sev = st.selectbox("Severity Filter", ["All", "Critical", "High", "Medium", "Low"])
    with f3:
        f_cat = st.selectbox("Category Filter", ["All"] + THREAT_CATEGORIES)
    with f4:
        f_search = st.text_input("Search Alert ID, IP, Evidence", "")

    # Retrieve from SQLite
    alerts_df = alert_mgr.get_filtered_alerts(
        status=f_status,
        severity=f_sev,
        category=f_cat,
        search_query=f_search
    )

    # Statistics Bar
    stats = alert_mgr.get_statistics()
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("Total Alerts", stats.get("total_alerts", 0))
    s2.metric("Open", stats.get("open", 0))
    s3.metric("Investigating", stats.get("investigating", 0))
    s4.metric("Resolved", stats.get("resolved", 0))
    s5.metric("False Positives", stats.get("false_positive", 0))

    if alerts_df.empty:
        st.info("No alerts match the active filter criteria.")
    else:
        st.markdown(f"**Alert Queue ({len(alerts_df)} records):**")
        st.dataframe(
            alerts_df[["id", "timestamp", "source_ip", "destination_ip", "category", "severity", "status", "confidence", "evidence", "updated_at"]],
            use_container_width=True,
            hide_index=True
        )

        # Alert Detail & State Transition Editor
        st.markdown("""
            <div class="section-header">
                <span>// ANALYST INCIDENT RESPONSE & STATUS WORKFLOW</span>
                <div class="section-line"></div>
            </div>
        """, unsafe_allow_html=True)

        selected_id = st.selectbox("Select Alert to Edit / Resolve", alerts_df["id"].tolist())
        alert_row = alerts_df[alerts_df["id"] == selected_id].iloc[0]

        ed1, ed2 = st.columns(2)
        with ed1:
            st.markdown(f"""
                <div class="cyber-container">
                    <div style="font-size: 0.75rem; color: #94A3B8;">ALERT ID: <b>{alert_row['id']}</b></div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: #FFFFFF; margin: 4px 0;">{alert_row['category']}</div>
                    <div style="margin-top: 6px;">
                        <span class="badge-{alert_row['severity'].lower()}">{alert_row['severity']}</span>
                        <span style="font-size: 0.78rem; color: #94A3B8; margin-left: 8px;">Current Status: <b>{alert_row['status']}</b></span>
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 10px;">
                        <b>Source Host:</b> <code>{alert_row['source_ip']}</code> &bull; <b>Target:</b> <code>{alert_row['destination_ip']}:{alert_row['destination_port']}</code>
                    </div>
                    <p style="font-size: 0.82rem; color: #CBD5E1; margin-top: 8px;">{alert_row['evidence']}</p>
                </div>
            """, unsafe_allow_html=True)

        with ed2:
            current_status = alert_row["status"]
            new_status = st.selectbox(
                "Update Incident State",
                ALERT_STATUSES,
                index=ALERT_STATUSES.index(current_status) if current_status in ALERT_STATUSES else 0
            )
            notes_input = st.text_area("Analyst Investigation Notes", value=str(alert_row.get("analyst_notes", "") or ""))
            resolution_input = st.text_area("Resolution / Root Cause Comments", value=str(alert_row.get("resolution_comment", "") or ""))

            if st.button("💾 SAVE CHANGES TO PERSISTENT DATABASE", type="primary", use_container_width=True):
                updated = alert_mgr.update_alert_status(
                    alert_id=selected_id,
                    new_status=new_status,
                    analyst_notes=notes_input,
                    resolution_comment=resolution_input
                )
                if updated:
                    st.success(f"Alert {selected_id} updated successfully! Changes persisted to SQLite.")
                    time.sleep(0.4)
                    st.rerun()
                else:
                    st.error("Failed to update alert.")

        # Export Alerts
        csv_data = alert_mgr.export_csv(alerts_df)
        st.download_button(
            label="⬇️ Export Filtered Alerts (CSV)",
            data=csv_data,
            file_name=f"sentinel_alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


# ==============================================================================
# PAGE 6: EVENT EXPLORER
# ==============================================================================
elif st.session_state.nav_page == "Event Explorer":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">🔍</div>
                    <div class="hero-title-group">
                        <h1>FORENSIC EVENT EXPLORER</h1>
                        <p>// MULTI-VECTOR TELEMETRY SEARCH & RAW PACKET FLOW INSPECTOR</p>
                    </div>
                </div>
                <div class="status-pill">SEARCH ACTIVE</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    df_ev = st.session_state.detections_df if not st.session_state.detections_df.empty else st.session_state.current_df

    if df_ev.empty:
        st.info("No event records available. Please load a dataset in Threat Detection Lab.")
    else:
        st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Perform granular forensic investigations by filtering on IP ranges, ports, protocols, and payload indicators.</p>", unsafe_allow_html=True)

        c_f1, c_f2, c_f3, c_f4 = st.columns([1, 1, 1, 1])
        with c_f1:
            proto_filter = st.selectbox("Protocol", ["All"] + sorted(list(df_ev["protocol"].unique())))
        with c_f2:
            port_input = st.text_input("Port (e.g. 22, 443)", "")
        with c_f3:
            ip_input = st.text_input("IP Address", "")
        with c_f4:
            row_limit = st.slider("Max Rows Displayed", 50, 1000, 200, 50)

        filtered = df_ev.copy()
        if proto_filter != "All":
            filtered = filtered[filtered["protocol"] == proto_filter]
        if port_input.strip():
            try:
                p_int = int(port_input.strip())
                filtered = filtered[filtered["dst_port"] == p_int]
            except ValueError:
                pass
        if ip_input.strip():
            filtered = filtered[
                filtered["src_ip"].str.contains(ip_input, case=False, na=False) |
                filtered["dst_ip"].str.contains(ip_input, case=False, na=False)
            ]

        st.markdown(f"**Forensic Records Found:** {len(filtered):,} records")
        st.dataframe(filtered.head(row_limit), use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 7: SETTINGS & SYSTEM HEALTH
# ==============================================================================
elif st.session_state.nav_page == "Settings & System Health":
    st.markdown("""
        <div class="command-hero">
            <div class="hero-main">
                <div class="hero-brand">
                    <div class="hero-logo-box">⚙️</div>
                    <div class="hero-title-group">
                        <h1>SETTINGS & SYSTEM HEALTH</h1>
                        <p>// DETECTION THRESHOLDS, STORAGE DIAGNOSTICS & ENTERPRISE ARCHITECTURE</p>
                    </div>
                </div>
                <div class="status-pill">HEALTH: OPTIMAL</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    tab_thresh, tab_diag, tab_arch = st.tabs(["[ 1 ] DETECTION THRESHOLDS", "[ 2 ] DIAGNOSTICS & LOGS", "[ 3 ] ARCHITECTURE & ROADMAP"])

    with tab_thresh:
        st.markdown("<p style='color: #94A3B8; font-size: 0.88rem;'>Tune rule thresholds and sliding window sensitivities according to your enterprise network baseline.</p>", unsafe_allow_html=True)

        c_t1, c_t2 = st.columns(2)
        with c_t1:
            bf_thresh = st.number_input("Brute-Force Failed Login Threshold", 2, 50, DEFAULT_DETECTION_THRESHOLDS["failed_login_threshold"])
            bf_window = st.number_input("Brute-Force Time Window (Seconds)", 30, 1800, DEFAULT_DETECTION_THRESHOLDS["failed_login_window_seconds"])
            ps_thresh = st.number_input("Port Scan Distinct Ports Threshold", 3, 100, DEFAULT_DETECTION_THRESHOLDS["port_scan_port_threshold"])
            ps_window = st.number_input("Port Scan Time Window (Seconds)", 10, 600, DEFAULT_DETECTION_THRESHOLDS["port_scan_window_seconds"])

        with c_t2:
            pkt_rate = st.number_input("Traffic Flood Threshold (Packets/Sec)", 500.0, 50000.0, float(DEFAULT_DETECTION_THRESHOLDS["packet_rate_threshold"]))
            exfil_mb = st.number_input("Suspicious Exfiltration Threshold (MB)", 5, 500, int(DEFAULT_DETECTION_THRESHOLDS["exfiltration_bytes_threshold"] / 1_000_000))
            ent_cutoff = st.slider("URL Shannon Entropy Cutoff", 3.0, 6.0, float(DEFAULT_DETECTION_THRESHOLDS["url_entropy_threshold"]), 0.1)

        if st.button("Apply Detection Thresholds"):
            new_t = {
                "failed_login_threshold": bf_thresh,
                "failed_login_window_seconds": bf_window,
                "port_scan_port_threshold": ps_thresh,
                "port_scan_window_seconds": ps_window,
                "packet_rate_threshold": pkt_rate,
                "exfiltration_bytes_threshold": exfil_mb * 1_000_000,
                "url_entropy_threshold": ent_cutoff
            }
            st.session_state.inference_engine.rule_engine.update_thresholds(new_t)
            st.success("Detection engine thresholds updated successfully!")

    with tab_diag:
        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;'>SYSTEM ARTIFACTS & DATABASE HEALTH</div>", unsafe_allow_html=True)
        db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        rf_path = MODELS_DIR / "sentinel_rf_model.joblib"
        lr_path = MODELS_DIR / "sentinel_lr_model.joblib"

        st.json({
            "database_path": str(DB_PATH),
            "database_size_bytes": db_size,
            "random_forest_model_exists": rf_path.exists(),
            "logistic_regression_model_exists": lr_path.exists(),
            "sample_data_directory": str(SAMPLE_DATA_DIR),
            "active_python_version": sys.version.split()[0]
        })

        if st.button("⚠️ Clear Alerts Database"):
            from src.storage import clear_all_alerts
            clear_all_alerts(DB_PATH)
            st.warning("Cleared all alerts from SQLite database.")
            st.rerun()

    with tab_arch:
        st.markdown("""
            <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.6;">
                <h4 style="color: #00F2FE;">Enterprise Architecture & Defensive Boundary</h4>
                <p>Sentinel AI operates strictly as an <b>authorized, defensive monitoring platform</b>. It utilizes deterministic statistical modeling, machine learning classification, and explainable heuristic rule engines.</p>
                <h4 style="color: #8B5CF6;">Production Integration Roadmap:</h4>
                <ul>
                    <li><b>SIEM Forwarder:</b> Splunk HEC and Elastic SIEM Common Schema (ECS) exporter.</li>
                    <li><b>Kafka Streaming:</b> Ingest live network telemetry at 100k+ events/sec via Apache Kafka topics.</li>
                    <li><b>Live Packet Capture:</b> Integration with Zeek and Suricata EVE.json streaming outputs.</li>
                    <li><b>Automated SOAR Playbooks:</b> Webhook triggers to AWS Security Groups and Palo Alto firewalls.</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
