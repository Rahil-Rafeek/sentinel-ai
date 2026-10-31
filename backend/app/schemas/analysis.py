from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from datetime import datetime

class StartAnalysisRequest(BaseModel):
    dataset_id: str
    run_ml: bool = True

class AnalysisJobResponse(BaseModel):
    id: str
    dataset_id: str
    status: str
    progress_pct: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    detector_results_summary: dict[str, Any] = {}
    ml_metrics: dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)
