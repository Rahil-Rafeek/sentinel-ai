import asyncio
import json
import uuid
import datetime
from typing import Any
from fastapi import WebSocket
from sqlalchemy.orm import Session
from backend.app.database.session import SessionLocal
from backend.app.database.models import Dataset, ThreatEventRecord, Alert, ReplaySession
from backend.app.detectors.brute_force import detect_brute_force
from backend.app.detectors.port_scan import detect_port_scan
from backend.app.detectors.traffic_anomaly import detect_traffic_anomaly
from backend.app.detectors.url_analysis import detect_malicious_urls

class MonitoringHub:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()
        self.active_mode: str = "idle"  # 'telemetry', 'replay', 'synthetic_demo', 'idle'
        self.replay_task: asyncio.Task | None = None
        self.replay_state: dict[str, Any] = {
            "session_id": None,
            "dataset_id": None,
            "status": "stopped",
            "speed": 1.0,
            "current_index": 0,
            "total_events": 0,
            "findings_count": 0
        }
        self.total_streamed: int = 0
        self.event_rate_sec: int = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send initial status
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "mode": self.active_mode,
            "replay": self.replay_state,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]):
        """Safely broadcast JSON payload to all connected WebSocket clients."""
        dead_connections = set()
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead_connections.add(conn)
        for dead in dead_connections:
            self.active_connections.discard(dead)

    async def ingest_telemetry_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Process incoming authorized live telemetry event from network or server logs,
        run real-time heuristics, and broadcast to live clients.
        """
        self.active_mode = "telemetry"
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        src_ip = payload.get("src_ip", "192.168.1.100")
        dst_ip = payload.get("dst_ip", "10.0.0.12")
        dst_port = payload.get("dst_port", 80)
        proto = payload.get("protocol", "TCP")
        packets = payload.get("packets", 1)
        bytes_val = payload.get("bytes", 64)
        failed_logins = payload.get("failed_logins", 0)
        url = payload.get("url")

        # Heuristic evaluation
        sev = "Info"
        cat = "Benign Telemetry"
        conf = 0.99
        evidence = f"Standard authorized {proto} packet flow ({packets} pkts, {bytes_val}B)."
        action = "Log and route flow normally."
        mitre_id = ""
        mitre_name = ""
        mitre_tactic = ""

        if failed_logins >= 5:
            cat = "Brute-Force Login"
            sev = "Critical" if failed_logins >= 20 else "High"
            conf = 0.96
            evidence = f"Repeated authentication challenges ({failed_logins} failures) detected from {src_ip}."
            action = f"Apply immediate firewall drop on {src_ip}."
            mitre_id = "T1110.001"
            mitre_name = "Password Guessing"
            mitre_tactic = "Credential Access"
        elif dst_port in [22, 23, 1433, 3389] and packets > 10:
            cat = "Port Scanning"
            sev = "High"
            conf = 0.92
            evidence = f"Targeted probe of administrative port {dst_port} by {src_ip}."
            action = "Verify host authorization and monitor session."
            mitre_id = "T1046"
            mitre_name = "Network Service Discovery"
            mitre_tactic = "Discovery"
        elif packets > 10000:
            cat = "Abnormally High Traffic"
            sev = "Critical"
            conf = 0.97
            evidence = f"Volumetric flow burst of {packets:,} packets saturating line buffers."
            action = "Deploy upstream scrubbing filter."
            mitre_id = "T1498.001"
            mitre_name = "Direct Volumetric Flood"
            mitre_tactic = "Impact"

        evt_id = f"LIVE-{uuid.uuid4().hex[:6].upper()}"
        event_dict = {
            "id": evt_id,
            "timestamp": now_str,
            "category": cat,
            "severity": sev,
            "confidence": conf,
            "src_ip": src_ip,
            "src_port": payload.get("src_port", 54321),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "duration_sec": payload.get("duration", 0.1),
            "bytes_sent": bytes_val,
            "bytes_received": 128,
            "packets_sent": packets,
            "packets_received": 2,
            "detection_method": "Real-Time Telemetry Pipeline",
            "detection_type": "live_telemetry",
            "evidence": evidence,
            "recommended_action": action,
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "mitre_tactic": mitre_tactic,
            "radar_angle": float(hash(src_ip) % 360),
            "radar_radius": 0.35 if sev == "Critical" else 0.60 if sev == "High" else 0.82,
            "is_replay": False
        }

        self.total_streamed += 1

        # Broadcast over WebSocket
        await self.broadcast({
            "type": "TELEMETRY_EVENT",
            "event": event_dict,
            "is_threat": sev in ["Critical", "High", "Medium"]
        })

        return event_dict

    async def start_replay(self, dataset_id: str, speed: float = 1.0):
        """Start or restart replay of analyzed events from a dataset."""
        await self.stop_replay()

        db = SessionLocal()
        try:
            events = db.query(ThreatEventRecord).filter(
                ThreatEventRecord.dataset_id == dataset_id,
                ThreatEventRecord.is_replay == False
            ).order_by(ThreatEventRecord.timestamp.asc()).all()

            if not events:
                # If no records exist in DB for this dataset, fallback to general events
                events = db.query(ThreatEventRecord).filter(ThreatEventRecord.is_replay == False).limit(50).all()

            event_dicts = []
            for e in events:
                event_dicts.append({
                    "id": f"RPLY-{e.id}",
                    "dataset_id": dataset_id,
                    "timestamp": e.timestamp,
                    "category": e.category,
                    "severity": e.severity,
                    "confidence": e.confidence,
                    "src_ip": e.src_ip,
                    "src_port": e.src_port,
                    "dst_ip": e.dst_ip,
                    "dst_port": e.dst_port,
                    "protocol": e.protocol,
                    "duration_sec": e.duration_sec,
                    "bytes_sent": e.bytes_sent,
                    "bytes_received": e.bytes_received,
                    "packets_sent": e.packets_sent,
                    "packets_received": e.packets_received,
                    "detection_method": f"Replay: {e.detection_method}",
                    "detection_type": "replay",
                    "evidence": e.evidence,
                    "recommended_action": e.recommended_action,
                    "mitre_id": e.mitre_id,
                    "mitre_name": e.mitre_name,
                    "mitre_tactic": e.mitre_tactic,
                    "radar_angle": e.radar_angle,
                    "radar_radius": e.radar_radius,
                    "is_replay": True
                })
        finally:
            db.close()

        self.active_mode = "replay"
        session_id = f"SES-{uuid.uuid4().hex[:8]}"
        self.replay_state = {
            "session_id": session_id,
            "dataset_id": dataset_id,
            "status": "playing",
            "speed": max(0.1, min(10.0, speed)),
            "current_index": 0,
            "total_events": len(event_dicts),
            "findings_count": 0
        }

        await self.broadcast({
            "type": "REPLAY_STATE_CHANGE",
            "state": self.replay_state
        })

        self.replay_task = asyncio.create_task(self._replay_loop(event_dicts))

    async def _replay_loop(self, events: list[dict]):
        try:
            while self.replay_state["current_index"] < len(events):
                if self.replay_state["status"] == "paused":
                    await asyncio.sleep(0.3)
                    continue
                if self.replay_state["status"] == "stopped":
                    break

                curr_idx = self.replay_state["current_index"]
                evt = events[curr_idx]
                self.replay_state["current_index"] += 1
                if evt.get("severity") in ["Critical", "High", "Medium"]:
                    self.replay_state["findings_count"] += 1
                self.total_streamed += 1

                await self.broadcast({
                    "type": "REPLAY_EVENT",
                    "event": evt,
                    "progress": {
                        "current": self.replay_state["current_index"],
                        "total": len(events),
                        "percentage": round((self.replay_state["current_index"] / len(events)) * 100, 1)
                    }
                })

                # Delay inversely proportional to speed
                delay = max(0.05, 1.0 / self.replay_state["speed"])
                await asyncio.sleep(delay)

            self.replay_state["status"] = "completed"
            await self.broadcast({
                "type": "REPLAY_COMPLETED",
                "state": self.replay_state
            })
        except asyncio.CancelledError:
            self.replay_state["status"] = "stopped"
        except Exception as ex:
            self.replay_state["status"] = "error"
            self.replay_state["error"] = str(ex)

    async def pause_replay(self):
        if self.replay_state["status"] == "playing":
            self.replay_state["status"] = "paused"
            await self.broadcast({"type": "REPLAY_STATE_CHANGE", "state": self.replay_state})

    async def resume_replay(self):
        if self.replay_state["status"] == "paused":
            self.replay_state["status"] = "playing"
            await self.broadcast({"type": "REPLAY_STATE_CHANGE", "state": self.replay_state})

    async def stop_replay(self):
        if self.replay_task and not self.replay_task.done():
            self.replay_task.cancel()
            try:
                await self.replay_task
            except Exception:
                pass
        self.replay_state["status"] = "stopped"
        self.replay_state["current_index"] = 0
        self.active_mode = "idle"
        await self.broadcast({"type": "REPLAY_STATE_CHANGE", "state": self.replay_state})

    def set_speed(self, speed: float):
        self.replay_state["speed"] = max(0.1, min(10.0, speed))

monitoring_hub = MonitoringHub()
