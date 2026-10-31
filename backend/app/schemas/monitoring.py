from typing import Optional, Any
from pydantic import BaseModel
from datetime import datetime

class MonitoringStatusResponse(BaseModel):
    is_live: bool
    active_mode: str  # 'telemetry', 'replay', 'synthetic_demo', 'idle'
    connected_clients: int
    active_replay_session: Optional[dict[str, Any]] = None
    telemetry_source: Optional[str] = None
    event_rate_sec: int
    total_events_streamed: int

class ReplayControlRequest(BaseModel):
    action: str  # 'start', 'pause', 'resume', 'stop'
    speed: Optional[float] = 1.0

class LiveTelemetryIngestRequest(BaseModel):
    timestamp: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    packets: Optional[int] = 1
    bytes: Optional[int] = 64
    duration: Optional[float] = 0.1
    failed_logins: Optional[int] = 0
    url: Optional[str] = None
    user: Optional[str] = None
    payload_entropy: Optional[float] = None
