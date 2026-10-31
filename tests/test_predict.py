"""
Tests for Unified Inference Engine and Hybrid Detection
"""

import pytest
import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.predict import ThreatInferenceEngine
from src.data_loader import load_dataset
from config.settings import SAMPLE_DATA_DIR


def test_predict_events_flow():
    engine = ThreatInferenceEngine()
    sample_file = SAMPLE_DATA_DIR / "sample_security_events.csv"
    res = load_dataset(sample_file)
    assert res.is_valid is True

    predictions_df = engine.predict_events(res.df)
    assert not predictions_df.empty
    assert len(predictions_df) == len(res.df)

    # Check key columns
    expected_cols = [
        "event_id", "timestamp", "src_ip", "dst_ip", "dst_port",
        "threat_category", "is_threat", "severity", "priority",
        "confidence", "detection_method", "evidence", "recommended_action"
    ]
    for col in expected_cols:
        assert col in predictions_df.columns

    # Verify both benign and threats were detected
    threats_count = predictions_df["is_threat"].sum()
    assert threats_count > 0
    assert len(predictions_df[~predictions_df["is_threat"]]) > 0

    # Ensure severities are valid
    valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
    assert set(predictions_df["severity"].unique()).issubset(valid_severities)
