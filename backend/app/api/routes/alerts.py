import csv
import json
import io
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.database.models import Dataset, Alert, ThreatEventRecord
from backend.app.schemas.alert import AlertResponse, UpdateAlertStatusRequest, UpdateAlertNotesRequest

router = APIRouter()

@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    dataset_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List security incident alerts with lifecycle state and severity filters."""
    if not dataset_id:
        active_ds = db.query(Dataset).filter(Dataset.is_active == True).first()
        if not active_ds:
            active_ds = db.query(Dataset).order_by(Dataset.created_at.desc()).first()
        dataset_id = active_ds.id if active_ds else None

    if not dataset_id:
        return []

    query = db.query(Alert).filter(Alert.dataset_id == dataset_id)

    if status and status != "All":
        query = query.filter(Alert.status == status)
    if severity and severity != "All":
        query = query.filter(Alert.severity == severity)
    if category and category != "All":
        query = query.filter(Alert.category == category)

    alerts = query.order_by(Alert.created_at.desc()).all()
    results = []
    for a in alerts:
        results.append({
            "id": a.id,
            "event_id": a.event_id,
            "dataset_id": a.dataset_id,
            "category": a.category,
            "severity": a.severity,
            "confidence": a.confidence,
            "status": a.status,
            "analyst_notes": a.analyst_notes,
            "status_history": json.loads(a.status_history or "[]"),
            "created_at": a.created_at,
            "updated_at": a.updated_at,
            "event": a.event
        })
    return results

@router.get("/export/csv")
def export_alerts_csv(
    dataset_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Export real analyzed alerts to CSV format."""
    query = db.query(Alert)
    if dataset_id:
        query = query.filter(Alert.dataset_id == dataset_id)
    if status and status != "All":
        query = query.filter(Alert.status == status)
    if severity and severity != "All":
        query = query.filter(Alert.severity == severity)

    alerts = query.order_by(Alert.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert_ID", "Event_ID", "Category", "Severity", "Confidence", "Status", "Source_IP", "Target_IP", "Analyst_Notes", "Timestamp"])

    for a in alerts:
        src = a.event.src_ip if a.event else ""
        dst = a.event.dst_ip if a.event else ""
        ts = a.event.timestamp if a.event else str(a.created_at)
        writer.writerow([a.id, a.event_id, a.category, a.severity, f"{a.confidence*100:.1f}%", a.status, src, dst, a.analyst_notes, ts])

    output.seek(0)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel_alerts_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
    )

@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: str, req: UpdateAlertStatusRequest, db: Session = Depends(get_db)):
    """Update incident lifecycle status and persist audit trail entry."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    old_status = alert.status
    alert.status = req.status
    if req.notes is not None:
        alert.analyst_notes = req.notes

    # Append to status history audit trail
    history = json.loads(alert.status_history or "[]")
    history.append({
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "action": f"Status updated from '{old_status}' to '{req.status}'",
        "status": req.status,
        "notes": req.notes or ""
    })
    alert.status_history = json.dumps(history)
    db.commit()

    return {"status": "success", "alert_id": alert.id, "new_status": alert.status}

@router.patch("/{alert_id}/notes")
def update_alert_notes(alert_id: str, req: UpdateAlertNotesRequest, db: Session = Depends(get_db)):
    """Update analyst forensic notes on an active incident."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.analyst_notes = req.notes
    db.commit()
    return {"status": "success", "alert_id": alert.id, "notes": alert.analyst_notes}
