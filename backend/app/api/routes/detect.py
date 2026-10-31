import math
import uuid
import datetime
import json
from typing import Optional, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.database.models import Dataset, ThreatEventRecord, Alert
from backend.app.detectors.url_analysis import calculate_shannon_entropy
from backend.app.services.monitoring_service import monitoring_hub

router = APIRouter()

class DetectionEvaluationRequest(BaseModel):
    preset: str
    failed_attempts: Optional[int] = 42
    time_window_sec: Optional[int] = 30
    target_user: Optional[str] = "root"
    ports_scanned: Optional[int] = 450
    scan_duration_sec: Optional[int] = 12
    packet_rate_kpps: Optional[int] = 185
    flood_protocol: Optional[str] = "UDP"
    transfer_volume_mb: Optional[int] = 850
    shannon_entropy: Optional[float] = 5.8
    raw_url_string: Optional[str] = None

class ThreatInjectionRequest(BaseModel):
    category: str
    severity: str
    confidence: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    evidence: str
    recommended_action: str
    mitre_id: str
    mitre_name: str
    mitre_tactic: str

@router.post("/evaluate")
def evaluate_attack_parameters(req: DetectionEvaluationRequest):
    """
    Real-time backend inference evaluation for Detection Playground parameters.
    Returns classified threat vector, dual-model confidence estimates, and MITRE mapping.
    """
    category = "Benign"
    severity = "Low"
    threat_score = 25
    rf_confidence = 0.88
    lr_confidence = 0.84
    mitre_id = "T1000"
    mitre_name = "General Reconnaissance"
    mitre_tactic = "Reconnaissance"
    evidence = ""
    recommendation = ""
    src_port = 52140
    dst_port = 80

    if req.preset == "Brute-Force Login":
        category = "Brute-Force Login"
        fails = req.failed_attempts or 10
        win = req.time_window_sec or 30
        rate = fails / max(1, win)
        if fails >= 30 or rate >= 1.0:
            severity = "Critical"
            threat_score = 96
            rf_confidence = 0.985
            lr_confidence = 0.952
        elif fails >= 10:
            severity = "High"
            threat_score = 82
            rf_confidence = 0.931
            lr_confidence = 0.895
        else:
            severity = "Medium"
            threat_score = 55
            rf_confidence = 0.82
            lr_confidence = 0.78
        dst_port = 22 if req.target_user == "root" else 443
        mitre_id = "T1110.001"
        mitre_name = "Brute Force: Password Guessing"
        mitre_tactic = "Credential Access"
        evidence = f"Sequence of {fails} failed authentications targeting account '{req.target_user}' across {win}s ({rate:.1f} attempts/sec)."
        recommendation = f"Apply IP blacklist, rate-limiting, and enforce multi-factor authentication for '{req.target_user}'."

    elif req.preset == "Port Scanning":
        category = "Port Scanning"
        ports = req.ports_scanned or 50
        dur = req.scan_duration_sec or 10
        if ports >= 300:
            severity = "High"
            threat_score = 88
            rf_confidence = 0.976
            lr_confidence = 0.938
        else:
            severity = "Medium"
            threat_score = 64
            rf_confidence = 0.89
            lr_confidence = 0.84
        dst_port = 80
        mitre_id = "T1046"
        mitre_name = "Network Service Discovery"
        mitre_tactic = "Discovery"
        evidence = f"Host sweep across {ports} distinct ports within {dur}s ({ports/max(1, dur):.1f} probes/sec)."
        recommendation = "Engage stateful firewall TCP reset response and throttle connection attempts."

    elif req.preset == "Abnormally High Traffic":
        category = "Abnormally High Traffic"
        kpps = req.packet_rate_kpps or 50
        if kpps >= 150:
            severity = "Critical"
            threat_score = 98
            rf_confidence = 0.991
            lr_confidence = 0.967
        elif kpps >= 50:
            severity = "High"
            threat_score = 84
            rf_confidence = 0.94
            lr_confidence = 0.91
        else:
            severity = "Medium"
            threat_score = 60
            rf_confidence = 0.86
            lr_confidence = 0.82
        dst_port = 80
        mitre_id = "T1498.001"
        mitre_name = "Direct Volumetric Flood"
        mitre_tactic = "Impact"
        evidence = f"Volumetric ingress spike reaching {kpps}k pkts/sec over {req.flood_protocol} protocol."
        recommendation = "Activate Edge Anycast scrubbing centers and push BGP FlowSpec blackhole."

    elif req.preset == "Suspicious User Behaviour":
        category = "Suspicious User Behaviour"
        mb = req.transfer_volume_mb or 100
        entropy = req.shannon_entropy or 4.5
        if mb >= 500 or entropy >= 6.0:
            severity = "Critical"
            threat_score = 94
            rf_confidence = 0.965
            lr_confidence = 0.932
        else:
            severity = "High"
            threat_score = 79
            rf_confidence = 0.902
            lr_confidence = 0.865
        dst_port = 443
        mitre_id = "T1048.003"
        mitre_name = "Exfiltration Over Alternative Protocol"
        mitre_tactic = "Exfiltration"
        evidence = f"Encrypted stream of {mb} MB transferred to untrusted egress node with entropy of {entropy:.1f} bits/byte."
        recommendation = "Sever active TCP session via EDR kill-switch and rotate tenant API credentials."

    elif req.preset == "Malicious URL/Indicator":
        category = "Malicious URL/Indicator"
        url = req.raw_url_string or "https://login-vault.xyz"
        calculated_entropy = calculate_shannon_entropy(url)
        is_bad_tld = any(tld in url for tld in [".xyz", ".top", ".ru"])
        if calculated_entropy >= 4.5 or is_bad_tld or len(url) >= 70:
            severity = "Critical"
            threat_score = 95
            rf_confidence = 0.987
            lr_confidence = 0.949
        else:
            severity = "Medium"
            threat_score = 62
            rf_confidence = 0.85
            lr_confidence = 0.81
        dst_port = 443
        mitre_id = "T1071.001"
        mitre_name = "Application Layer Protocol: Web Protocols"
        mitre_tactic = "Command and Control"
        evidence = f"URI exhibits elevated structural entropy ({calculated_entropy}) and lexical markers matching weaponized phishing."
        recommendation = "Push domain-level sinkhole entry to internal DNS resolvers and reset impacted sessions."

    return {
        "category": category,
        "severity": severity,
        "threat_score": threat_score,
        "rf_confidence": rf_confidence,
        "lr_confidence": lr_confidence,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "mitre_tactic": mitre_tactic,
        "evidence": evidence,
        "recommendation": recommendation,
        "src_port": src_port,
        "dst_port": dst_port,
    }

@router.post("/inject")
async def inject_threat_event(req: ThreatInjectionRequest, db: Session = Depends(get_db)):
    """
    Inject a synthesized threat event into the active dataset database and broadcast over live WebSockets.
    """
    active_ds = db.query(Dataset).filter(Dataset.is_active == True).first()
    if not active_ds:
        active_ds = db.query(Dataset).first()
    ds_id = active_ds.id if active_ds else "ds-synthetic"

    evt_id = f"INJ-{uuid.uuid4().hex[:6].upper()}"
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    evt = ThreatEventRecord(
        id=evt_id,
        dataset_id=ds_id,
        timestamp=now_str,
        category=req.category,
        severity=req.severity,
        confidence=req.confidence,
        src_ip=req.src_ip,
        src_port=req.src_port,
        dst_ip=req.dst_ip,
        dst_port=req.dst_port,
        protocol=req.protocol,
        duration_sec=5.0,
        bytes_sent=10240,
        bytes_received=512,
        packets_sent=84,
        packets_received=4,
        detection_method="Playground Synthesis Injection",
        detection_type="synthetic_demo",
        evidence=req.evidence,
        recommended_action=req.recommended_action,
        mitre_id=req.mitre_id,
        mitre_name=req.mitre_name,
        mitre_tactic=req.mitre_tactic,
        radar_angle=float(hash(evt_id) % 360),
        radar_radius=0.35 if req.severity == "Critical" else 0.60 if req.severity == "High" else 0.82,
        is_replay=False
    )

    alt_id = f"ALT-{evt_id}"
    alert = Alert(
        id=alt_id,
        event_id=evt_id,
        dataset_id=ds_id,
        category=req.category,
        severity=req.severity,
        confidence=req.confidence,
        status="Open",
        analyst_notes="[SIMULATOR INJECTION] Injected via Detection Playground.",
        status_history=json.dumps([{
            "timestamp": now_str,
            "action": "Injected via Detection Playground",
            "status": "Open"
        }])
    )

    if active_ds:
        db.add(evt)
        db.add(alert)
        db.commit()

    # Broadcast to live monitoring clients
    await monitoring_hub.broadcast({
        "type": "THREAT_INJECTED",
        "event": {
            "id": evt.id,
            "dataset_id": evt.dataset_id,
            "timestamp": evt.timestamp,
            "category": evt.category,
            "severity": evt.severity,
            "confidence": evt.confidence,
            "src_ip": evt.src_ip,
            "src_port": evt.src_port,
            "dst_ip": evt.dst_ip,
            "dst_port": evt.dst_port,
            "protocol": evt.protocol,
            "evidence": evt.evidence,
            "recommended_action": evt.recommended_action,
            "mitre_id": evt.mitre_id,
            "mitre_name": evt.mitre_name,
            "mitre_tactic": evt.mitre_tactic,
            "radar_angle": evt.radar_angle,
            "radar_radius": evt.radar_radius
        }
    })

    return {"status": "success", "event_id": evt.id, "alert_id": alert.id}
