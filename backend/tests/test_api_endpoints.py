import io
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import init_db

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()

client = TestClient(app)

def test_root_and_health():
    res = client.get("/")
    assert res.status_code == 200
    assert "Sentinel AI" in res.json()["system"]

    res_h = client.get("/health")
    assert res_h.status_code == 200
    assert res_h.json()["status"] == "healthy"

def test_system_health_and_metrics():
    res = client.get("/api/v1/system/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "api_engine" in data["subsystems"]

    res_m = client.get("/api/v1/system/metrics")
    assert res_m.status_code == 200
    assert res_m.json()["events_per_sec"] > 0

def test_dataset_upload_workflow():
    csv_content = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,label\n"
        "2026-10-26 12:00:00,192.168.1.105,10.0.0.12,52140,22,TCP,20,1500,Brute-Force\n"
        "2026-10-26 12:00:05,192.168.1.189,10.0.0.15,60124,1433,TCP,2,120,Port-Scan\n"
    )

    files = {"file": ("test_upload.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    res = client.post("/api/v1/datasets/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "dataset_id" in data
    assert data["compatibility_status"] == "cybersecurity_compatible"
    dataset_id = data["dataset_id"]

    # List datasets
    res_list = client.get("/api/v1/datasets/")
    assert res_list.status_code == 200
    assert any(d["id"] == dataset_id for d in res_list.json())

    # Activate dataset
    res_act = client.post(f"/api/v1/datasets/{dataset_id}/activate")
    assert res_act.status_code == 200

    # Start analysis
    res_job = client.post("/api/v1/analysis/start", json={"dataset_id": dataset_id})
    assert res_job.status_code == 200
    job_id = res_job.json()["id"]

    # Check status
    res_status = client.get(f"/api/v1/analysis/{job_id}/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] in ["queued", "processing", "completed"]

def test_alerts_and_export():
    res_alerts = client.get("/api/v1/alerts/")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()

    if len(alerts) > 0:
        alert_id = alerts[0]["id"]
        # Update status
        res_patch = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "Investigating", "notes": "Automated test note"}
        )
        assert res_patch.status_code == 200
        assert res_patch.json()["new_status"] == "Investigating"

    # Export CSV
    res_csv = client.get("/api/v1/alerts/export/csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "Alert_ID" in res_csv.text

def test_analytics_endpoints():
    res_sum = client.get("/api/v1/analytics/summary")
    assert res_sum.status_code == 200
    assert "threat_score" in res_sum.json()

    res_cat = client.get("/api/v1/analytics/categories")
    assert res_cat.status_code == 200
    assert isinstance(res_cat.json(), list)

    res_sev = client.get("/api/v1/analytics/severities")
    assert res_sev.status_code == 200

    res_ts = client.get("/api/v1/analytics/time-series")
    assert res_ts.status_code == 200

def test_monitoring_status_and_replay():
    res = client.get("/api/v1/monitoring/status")
    assert res.status_code == 200
    assert "active_mode" in res.json()

    # Replay controls
    res_speed = client.post("/api/v1/monitoring/replay/speed?speed=2.0")
    assert res_speed.status_code == 200
    assert res_speed.json()["speed"] == 2.0
