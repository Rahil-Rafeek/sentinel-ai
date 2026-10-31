from typing import Optional, Any
from pydantic import BaseModel

class SummaryMetricsResponse(BaseModel):
    total_events: int
    threats_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    benign_count: int
    threat_score: int
    posture_level: str
    active_dataset_id: Optional[str] = None
    active_dataset_name: Optional[str] = None
    dataset_compatibility: Optional[str] = None

class DistributionItem(BaseModel):
    name: str
    count: int
    percentage: float
    color: Optional[str] = None

class TimeSeriesPoint(BaseModel):
    timestamp: str
    packet_rate: int
    threat_count: int
    critical_count: int

class TopPortItem(BaseModel):
    port: int
    count: int
    service: str
    threat_ratio: float

class MLMetricsResponse(BaseModel):
    is_available: bool
    is_supervised: bool
    model_name: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    roc_auc: Optional[float] = None
    confusion_matrix: Optional[list[list[int]]] = None
    class_labels: Optional[list[str]] = None
    anomaly_count: Optional[int] = None
    anomaly_ratio: Optional[float] = None
    notes: Optional[str] = None
