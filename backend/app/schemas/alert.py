from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from backend.app.schemas.event import ThreatEventResponse

class AlertResponse(BaseModel):
    id: str
    event_id: str
    dataset_id: str
    category: str
    severity: str
    confidence: float
    status: str
    analyst_notes: str
    status_history: list[dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime
    event: Optional[ThreatEventResponse] = None

    model_config = ConfigDict(from_attributes=True)

class UpdateAlertStatusRequest(BaseModel):
    status: str
    notes: Optional[str] = None

class UpdateAlertNotesRequest(BaseModel):
    notes: str
