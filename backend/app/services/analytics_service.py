import json
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database.models import Dataset, ThreatEventRecord, Alert, AnalysisJob

CATEGORY_COLORS = {
    "Brute-Force Login": "#EF4444",
    "Port Scanning": "#F97316",
    "Abnormally High Traffic": "#F59E0B",
    "Suspicious User Behaviour": "#8B5CF6",
    "Malicious URL/Indicator": "#EC4899",
    "Statistical Anomaly": "#06B6D4",
    "Benign": "#10B981"
}

PORT_SERVICES = {
    21: "FTP Control",
    22: "SSH Secure Shell",
    23: "Telnet",
    25: "SMTP Mail",
    53: "DNS Resolver",
    80: "HTTP Web",
    443: "HTTPS SSL/TLS",
    1433: "Microsoft SQL Server",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    8080: "HTTP Alternate Proxy",
    8443: "HTTPS Alternate",
}

def get_summary_metrics(db: Session, dataset_id: str | None = None) -> dict:
    """Compute top-level security posture KPIs from active database records."""
    if not dataset_id:
        active_ds = db.query(Dataset).filter(Dataset.is_active == True).first()
        if not active_ds:
            active_ds = db.query(Dataset).order_by(Dataset.created_at.desc()).first()
        dataset_id = active_ds.id if active_ds else None

    if not dataset_id:
        return {
            "total_events": 0,
            "threats_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "benign_count": 0,
            "threat_score": 15,
            "posture_level": "DEFCON 5",
            "active_dataset_id": None,
            "active_dataset_name": "No Dataset Selected",
            "dataset_compatibility": "pending"
        }

    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    events_query = db.query(ThreatEventRecord).filter(ThreatEventRecord.dataset_id == dataset_id)
    total_events = events_query.count()

    critical_count = events_query.filter(ThreatEventRecord.severity == "Critical").count()
    high_count = events_query.filter(ThreatEventRecord.severity == "High").count()
    medium_count = events_query.filter(ThreatEventRecord.severity == "Medium").count()
    low_count = events_query.filter(ThreatEventRecord.severity == "Low").count()
    benign_count = events_query.filter(ThreatEventRecord.category == "Benign").count()

    threats_count = critical_count + high_count + medium_count + low_count

    # Threat Score calculation (0 - 100)
    score = min(99, 15 + (critical_count * 5) + (high_count * 2) + (medium_count * 1))
    
    # DEFCON calculation
    if critical_count >= 10 or score >= 85:
        posture = "DEFCON 1"
    elif critical_count >= 3 or score >= 70:
        posture = "DEFCON 2"
    elif threats_count > 0:
        posture = "DEFCON 3"
    else:
        posture = "DEFCON 4"

    return {
        "total_events": total_events,
        "threats_count": threats_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "benign_count": benign_count,
        "threat_score": int(score),
        "posture_level": posture,
        "active_dataset_id": dataset.id if dataset else None,
        "active_dataset_name": dataset.filename if dataset else "Unknown",
        "dataset_compatibility": dataset.compatibility_status if dataset else "pending"
    }

def get_category_distribution(db: Session, dataset_id: str | None = None) -> list[dict]:
    """Compute threat category breakdown and percentages."""
    query = db.query(ThreatEventRecord.category, func.count(ThreatEventRecord.id))
    if dataset_id:
        query = query.filter(ThreatEventRecord.dataset_id == dataset_id)
    results = query.group_by(ThreatEventRecord.category).all()

    total = sum(cnt for _, cnt in results) or 1
    items = []
    for cat, cnt in results:
        items.append({
            "name": cat,
            "count": cnt,
            "percentage": round((cnt / total) * 100, 1),
            "color": CATEGORY_COLORS.get(cat, "#06B6D4")
        })
    return sorted(items, key=lambda x: x["count"], reverse=True)

def get_severity_distribution(db: Session, dataset_id: str | None = None) -> list[dict]:
    """Compute severity breakdown and percentages."""
    query = db.query(ThreatEventRecord.severity, func.count(ThreatEventRecord.id))
    if dataset_id:
        query = query.filter(ThreatEventRecord.dataset_id == dataset_id)
    results = query.group_by(ThreatEventRecord.severity).all()

    total = sum(cnt for _, cnt in results) or 1
    items = []
    for sev, cnt in results:
        items.append({
            "name": sev,
            "count": cnt,
            "percentage": round((cnt / total) * 100, 1),
            "color": "#EF4444" if sev == "Critical" else "#F59E0B" if sev == "High" else "#EAB308" if sev == "Medium" else "#10B981"
        })
    return items

def get_time_series_metrics(db: Session, dataset_id: str | None = None) -> list[dict]:
    """Extract chronological sequence for ingress packet rate and threat spikes."""
    query = db.query(ThreatEventRecord).order_by(ThreatEventRecord.timestamp.asc())
    if dataset_id:
        query = query.filter(ThreatEventRecord.dataset_id == dataset_id)
    events = query.limit(50).all()

    if not events:
        # Provide clean structured empty baseline
        return []

    points = []
    for i, e in enumerate(events):
        ts_label = e.timestamp.split(" ")[-1] if " " in e.timestamp else f"T+{i*5}s"
        points.append({
            "timestamp": ts_label,
            "packet_rate": e.packets_sent * 120 + 2400,
            "threat_count": 1 if e.severity in ["Critical", "High", "Medium"] else 0,
            "critical_count": 1 if e.severity == "Critical" else 0
        })
    return points

def get_top_ports(db: Session, dataset_id: str | None = None) -> list[dict]:
    """Compute top targeted destination ports from real records."""
    query = db.query(ThreatEventRecord.dst_port, func.count(ThreatEventRecord.id))
    if dataset_id:
        query = query.filter(ThreatEventRecord.dataset_id == dataset_id)
    results = query.filter(ThreatEventRecord.dst_port != None).group_by(ThreatEventRecord.dst_port).order_by(func.count(ThreatEventRecord.id).desc()).limit(8).all()

    items = []
    total = sum(c for _, c in results) or 1
    for port, cnt in results:
        items.append({
            "port": int(port),
            "count": cnt,
            "service": PORT_SERVICES.get(int(port), f"Port {port}"),
            "threat_ratio": round(cnt / total, 3)
        })
    return items

def get_ml_metrics_summary(db: Session, dataset_id: str | None = None) -> dict:
    """Retrieve saved machine-learning evaluation metrics from the latest analysis job."""
    query = db.query(AnalysisJob).order_by(AnalysisJob.completed_at.desc())
    if dataset_id:
        query = query.filter(AnalysisJob.dataset_id == dataset_id)
    latest_job = query.first()

    if not latest_job or not latest_job.ml_metrics:
        return {
            "is_available": False,
            "is_supervised": False,
            "model_name": "No Model Trained Yet",
            "notes": "Select and analyze a dataset to view model validation metrics."
        }

    try:
        metrics = json.loads(latest_job.ml_metrics)
        return metrics
    except Exception:
        return {"is_available": False, "is_supervised": False, "model_name": "Invalid Metrics JSON"}
