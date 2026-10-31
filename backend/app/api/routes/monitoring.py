from typing import Optional
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.database.models import Dataset
from backend.app.schemas.monitoring import (
    MonitoringStatusResponse, ReplayControlRequest, LiveTelemetryIngestRequest
)
from backend.app.services.monitoring_service import monitoring_hub

router = APIRouter()

@router.get("/status", response_model=MonitoringStatusResponse)
def get_monitoring_status():
    """Retrieve operational status of the live monitoring and replay engine."""
    return {
        "is_live": len(monitoring_hub.active_connections) > 0 or monitoring_hub.active_mode != "idle",
        "active_mode": monitoring_hub.active_mode,
        "connected_clients": len(monitoring_hub.active_connections),
        "active_replay_session": monitoring_hub.replay_state if monitoring_hub.replay_state["status"] != "stopped" else None,
        "telemetry_source": "Authorized Ingest Port / WebSocket Bus",
        "event_rate_sec": monitoring_hub.event_rate_sec,
        "total_events_streamed": monitoring_hub.total_streamed
    }

@router.post("/replay/start")
async def start_dataset_replay(
    req: ReplayControlRequest,
    dataset_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Start time-series playback of analyzed dataset records."""
    if not dataset_id:
        active_ds = db.query(Dataset).filter(Dataset.is_active == True).first()
        if not active_ds:
            active_ds = db.query(Dataset).order_by(Dataset.created_at.desc()).first()
        if not active_ds:
            raise HTTPException(status_code=400, detail="No dataset available to replay. Please upload a dataset first.")
        dataset_id = active_ds.id

    await monitoring_hub.start_replay(dataset_id, req.speed or 1.0)
    return {"status": "started", "session": monitoring_hub.replay_state}

@router.post("/replay/pause")
async def pause_dataset_replay():
    """Pause current dataset replay playback."""
    await monitoring_hub.pause_replay()
    return {"status": "paused", "session": monitoring_hub.replay_state}

@router.post("/replay/resume")
async def resume_dataset_replay():
    """Resume paused dataset replay playback."""
    await monitoring_hub.resume_replay()
    return {"status": "resumed", "session": monitoring_hub.replay_state}

@router.post("/replay/stop")
async def stop_dataset_replay():
    """Stop dataset replay and reset playback index."""
    await monitoring_hub.stop_replay()
    return {"status": "stopped", "session": monitoring_hub.replay_state}

@router.post("/replay/speed")
def update_replay_speed(speed: float):
    """Update replay multiplier speed (e.g., 0.5x, 1x, 2x, 5x, 10x)."""
    monitoring_hub.set_speed(speed)
    return {"status": "updated", "speed": monitoring_hub.replay_state["speed"]}

@router.post("/telemetry/ingest")
async def ingest_live_telemetry(payload: LiveTelemetryIngestRequest):
    """Ingest and analyze a live authorized network or server telemetry record."""
    result = await monitoring_hub.ingest_telemetry_event(payload.dict())
    return {"status": "ingested", "event": result}

@router.websocket("/ws")
async def websocket_event_stream(websocket: WebSocket):
    """WebSocket endpoint delivering real-time threat events, replay ticks, and alert notifications."""
    await monitoring_hub.connect(websocket)
    try:
        while True:
            # Keepalive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        monitoring_hub.disconnect(websocket)
    except Exception:
        monitoring_hub.disconnect(websocket)
