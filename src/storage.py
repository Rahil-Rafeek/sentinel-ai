"""
Sentinel AI — SQLite Storage Layer
Provides persistent, thread-safe SQLite storage for security alerts,
analyst audit trails, and detection histories across application restarts.
"""

import sqlite3
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import DB_PATH

logger = logging.getLogger("sentinel.storage")


def get_db_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Creates a connection to SQLite database with row factory."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: Path = DB_PATH) -> None:
    """Initializes tables and indexes if they do not exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            priority INTEGER DEFAULT 3,
            detection_method TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            evidence TEXT,
            recommended_action TEXT,
            analyst_notes TEXT DEFAULT '',
            resolution_comment TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Audit Trail Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            action TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT,
            notes TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)

    # Indexes for fast querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {db_path}")


def insert_alert(alert_dict: Dict[str, Any], db_path: Path = DB_PATH) -> str:
    """Inserts a new alert into SQLite and logs creation audit."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    alert_id = alert_dict.get("id") or f"ALT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO alerts (
            id, timestamp, source_ip, destination_ip, destination_port, protocol,
            category, severity, priority, detection_method, confidence,
            status, evidence, recommended_action, analyst_notes, resolution_comment,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        alert_dict.get("timestamp", now_str),
        alert_dict.get("source_ip", "UNKNOWN"),
        alert_dict.get("destination_ip", "UNKNOWN"),
        alert_dict.get("destination_port", 0),
        alert_dict.get("protocol", "TCP"),
        alert_dict.get("category", "General Threat"),
        alert_dict.get("severity", "Medium"),
        alert_dict.get("priority", 3),
        alert_dict.get("detection_method", "Rule-Based Engine"),
        float(alert_dict.get("confidence", 0.85)),
        alert_dict.get("status", "Open"),
        alert_dict.get("evidence", ""),
        alert_dict.get("recommended_action", ""),
        alert_dict.get("analyst_notes", ""),
        alert_dict.get("resolution_comment", ""),
        now_str,
        now_str
    ))

    # Audit log
    cursor.execute("""
        INSERT INTO alert_audit (alert_id, action, old_status, new_status, notes, timestamp)
        VALUES (?, 'CREATED', NULL, ?, 'Alert triggered by detection engine', ?)
    """, (alert_id, alert_dict.get("status", "Open"), now_str))

    conn.commit()
    conn.close()
    return alert_id


def get_alerts(
    db_path: Path = DB_PATH,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    limit: int = 500
) -> List[Dict[str, Any]]:
    """Retrieves alerts with filtering and sorting."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if status_filter and status_filter != "All":
        query += " AND status = ?"
        params.append(status_filter)

    if severity_filter and severity_filter != "All":
        query += " AND severity = ?"
        params.append(severity_filter)

    if category_filter and category_filter != "All":
        query += " AND category = ?"
        params.append(category_filter)

    if search_query:
        query += " AND (id LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR evidence LIKE ? OR category LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])

    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results


def get_alert_by_id(alert_id: str, db_path: Path = DB_PATH) -> Optional[Dict[str, Any]]:
    """Fetches single alert by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_alert(
    alert_id: str,
    new_status: Optional[str] = None,
    analyst_notes: Optional[str] = None,
    resolution_comment: Optional[str] = None,
    db_path: Path = DB_PATH
) -> bool:
    """Updates status, analyst notes, and resolution comments with audit trail."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT status, analyst_notes, resolution_comment FROM alerts WHERE id = ?", (alert_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return False

    old_status = existing["status"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    updates = ["updated_at = ?"]
    params = [now_str]

    if new_status and new_status != old_status:
        updates.append("status = ?")
        params.append(new_status)

    if analyst_notes is not None:
        updates.append("analyst_notes = ?")
        params.append(analyst_notes)

    if resolution_comment is not None:
        updates.append("resolution_comment = ?")
        params.append(resolution_comment)

    params.append(alert_id)
    update_sql = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(update_sql, params)

    # Record audit if status or note changed
    if new_status and new_status != old_status:
        cursor.execute("""
            INSERT INTO alert_audit (alert_id, action, old_status, new_status, notes, timestamp)
            VALUES (?, 'STATUS_UPDATE', ?, ?, ?, ?)
        """, (alert_id, old_status, new_status, analyst_notes or "", now_str))

    conn.commit()
    conn.close()
    return True


def get_alert_stats(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Returns aggregated summary metrics for SOC dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
    status_counts = dict(cursor.fetchall())

    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_counts = dict(cursor.fetchall())

    cursor.execute("SELECT category, COUNT(*) FROM alerts GROUP BY category")
    category_counts = dict(cursor.fetchall())

    conn.close()

    return {
        "total_alerts": total,
        "open": status_counts.get("Open", 0),
        "investigating": status_counts.get("Investigating", 0),
        "resolved": status_counts.get("Resolved", 0),
        "false_positive": status_counts.get("False Positive", 0),
        "critical": severity_counts.get("Critical", 0),
        "high": severity_counts.get("High", 0),
        "medium": severity_counts.get("Medium", 0),
        "low": severity_counts.get("Low", 0),
        "info": severity_counts.get("Info", 0),
        "categories": category_counts
    }


def clear_all_alerts(db_path: Path = DB_PATH) -> None:
    """Clears alerts for reset / test purposes."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alert_audit")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
