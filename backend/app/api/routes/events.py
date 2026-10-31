import math
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.app.database.session import get_db
from backend.app.database.models import Dataset, ThreatEventRecord
from backend.app.schemas.event import PaginatedEventsResponse, ThreatEventResponse

router = APIRouter()

@router.get("/", response_model=PaginatedEventsResponse)
def list_events(
    dataset_id: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = Query("timestamp", pattern="^(timestamp|confidence|severity)$"),
    sort_desc: bool = True,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """
    Retrieve paginated security events from the database with filtering and keyword search.
    """
    if not dataset_id:
        active_ds = db.query(Dataset).filter(Dataset.is_active == True).first()
        if not active_ds:
            active_ds = db.query(Dataset).order_by(Dataset.created_at.desc()).first()
        dataset_id = active_ds.id if active_ds else None

    if not dataset_id:
        return {"total": 0, "page": page, "page_size": page_size, "total_pages": 0, "events": []}

    query = db.query(ThreatEventRecord).filter(
        ThreatEventRecord.dataset_id == dataset_id,
        ThreatEventRecord.is_replay == False
    )

    if category and category != "All":
        query = query.filter(ThreatEventRecord.category == category)
    if severity and severity != "All":
        query = query.filter(ThreatEventRecord.severity == severity)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ThreatEventRecord.id.ilike(term),
                ThreatEventRecord.category.ilike(term),
                ThreatEventRecord.src_ip.ilike(term),
                ThreatEventRecord.dst_ip.ilike(term),
                ThreatEventRecord.mitre_id.ilike(term),
                ThreatEventRecord.mitre_name.ilike(term),
                ThreatEventRecord.evidence.ilike(term)
            )
        )

    # Sorting
    if sort_by == "confidence":
        order_col = ThreatEventRecord.confidence.desc() if sort_desc else ThreatEventRecord.confidence.asc()
    elif sort_by == "severity":
        # Approximate severity sorting
        order_col = ThreatEventRecord.severity.asc() if sort_desc else ThreatEventRecord.severity.desc()
    else:
        order_col = ThreatEventRecord.timestamp.desc() if sort_desc else ThreatEventRecord.timestamp.asc()

    query = query.order_by(order_col)

    total = query.count()
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    records = query.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "events": records
    }

@router.get("/{event_id}", response_model=ThreatEventResponse)
def get_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieve full forensic telemetry for an individual threat event."""
    event = db.query(ThreatEventRecord).filter(ThreatEventRecord.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found.")
    return event
