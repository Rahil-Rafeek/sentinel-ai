"""
Tests for Alert Persistence, Lifecycle Transitions, and Storage
"""

import pytest
import tempfile
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.storage import (
    init_database,
    insert_alert,
    get_alerts,
    get_alert_by_id,
    update_alert,
    get_alert_stats
)
from src.alert_manager import AlertManager


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    init_database(db_path)
    yield db_path
    if db_path.exists():
        db_path.unlink()


def test_insert_and_get_alert(temp_db):
    alert_data = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "protocol": "TCP",
        "category": "Brute-Force Login",
        "severity": "Critical",
        "priority": 1,
        "detection_method": "Rule-Based Engine",
        "confidence": 0.95,
        "status": "Open",
        "evidence": "Repeated failed SSH logins detected.",
        "recommended_action": "Block source IP."
    }
    alert_id = insert_alert(alert_data, db_path=temp_db)
    assert alert_id.startswith("ALT-")

    retrieved = get_alert_by_id(alert_id, db_path=temp_db)
    assert retrieved is not None
    assert retrieved["source_ip"] == "192.168.1.100"
    assert retrieved["severity"] == "Critical"
    assert retrieved["status"] == "Open"


def test_status_update_and_audit(temp_db):
    alert_data = {
        "source_ip": "192.168.1.100",
        "category": "Port Scanning",
        "severity": "High",
        "confidence": 0.88
    }
    alert_id = insert_alert(alert_data, db_path=temp_db)

    # Transition to Investigating
    success = update_alert(
        alert_id,
        new_status="Investigating",
        analyst_notes="SOC Analyst investigating firewall logs.",
        db_path=temp_db
    )
    assert success is True

    updated = get_alert_by_id(alert_id, db_path=temp_db)
    assert updated["status"] == "Investigating"
    assert "SOC Analyst investigating" in updated["analyst_notes"]


def test_alert_manager_filtering_and_stats(temp_db):
    mgr = AlertManager(db_path=temp_db)
    mgr.process_and_create_alert({
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "category": "Abnormally High Traffic",
        "confidence": 0.92,
        "is_threat": True,
        "bytes_sent": 5000000,
        "evidence": "Flood anomaly",
        "recommended_action": "Scrub traffic"
    })
    stats = mgr.get_statistics()
    assert stats["total_alerts"] >= 1
    assert stats["open"] >= 1

    df_filtered = mgr.get_filtered_alerts(status="Open")
    assert len(df_filtered) >= 1
    assert df_filtered.iloc[0]["category"] == "Abnormally High Traffic"
