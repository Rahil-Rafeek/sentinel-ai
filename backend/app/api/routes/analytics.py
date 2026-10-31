from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.schemas.analytics import (
    SummaryMetricsResponse, DistributionItem, TimeSeriesPoint, TopPortItem, MLMetricsResponse
)
from backend.app.services.analytics_service import (
    get_summary_metrics, get_category_distribution, get_severity_distribution,
    get_time_series_metrics, get_top_ports, get_ml_metrics_summary
)

router = APIRouter()

@router.get("/summary", response_model=SummaryMetricsResponse)
def get_summary(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve top-level cybersecurity posture KPIs calculated from active database records."""
    return get_summary_metrics(db, dataset_id)

@router.get("/categories", response_model=list[DistributionItem])
def get_categories(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve threat vector distribution percentages and counts."""
    return get_category_distribution(db, dataset_id)

@router.get("/severities", response_model=list[DistributionItem])
def get_severities(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve severity level breakdown."""
    return get_severity_distribution(db, dataset_id)

@router.get("/time-series", response_model=list[TimeSeriesPoint])
def get_time_series(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve chronological packet rate and threat detection sequences."""
    return get_time_series_metrics(db, dataset_id)

@router.get("/top-ports", response_model=list[TopPortItem])
def get_top_targeted_ports(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve most frequently probed destination ports."""
    return get_top_ports(db, dataset_id)

@router.get("/model-metrics", response_model=MLMetricsResponse)
def get_ml_metrics(dataset_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve machine-learning precision, recall, F1-score, and confusion matrix."""
    return get_ml_metrics_summary(db, dataset_id)
