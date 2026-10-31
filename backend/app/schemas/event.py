from typing import Optional, Any
from pydantic import BaseModel, ConfigDict

class ThreatEventResponse(BaseModel):
    id: str
    dataset_id: str
    analysis_job_id: Optional[str] = None
    timestamp: str
    category: str
    severity: str
    confidence: float
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    duration_sec: Optional[float] = 0.0
    bytes_sent: Optional[int] = 0
    bytes_received: Optional[int] = 0
    packets_sent: Optional[int] = 0
    packets_received: Optional[int] = 0
    detection_method: str
    detection_type: str
    evidence: str
    recommended_action: str
    mitre_id: Optional[str] = ""
    mitre_name: Optional[str] = ""
    mitre_tactic: Optional[str] = ""
    radar_angle: float
    radar_radius: float
    is_replay: bool = False

    model_config = ConfigDict(from_attributes=True)

class PaginatedEventsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    events: list[ThreatEventResponse]
