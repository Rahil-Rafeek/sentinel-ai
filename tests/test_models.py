"""
Tests for ML Model Pipeline and Anomaly Detection
"""

import pytest
import pandas as pd
import numpy as np
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.train_model import train_and_evaluate_models, train_anomaly_detector
from src.feature_engineering import extract_features, calculate_shannon_entropy
from src.data_loader import load_dataset
from config.settings import SAMPLE_DATA_DIR


def test_shannon_entropy():
    # Constant string has 0 entropy
    assert calculate_shannon_entropy("aaaaa") == 0.0
    # Random characters have higher entropy
    h1 = calculate_shannon_entropy("abcde12345!@#$%")
    assert h1 > 3.0


def test_feature_extraction():
    df = pd.DataFrame([{
        "timestamp": "2026-10-26 12:00:00",
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "duration_sec": 1.5,
        "bytes_sent": 5000,
        "bytes_received": 10000,
        "packets_sent": 20,
        "packets_received": 40,
        "failed_login_count": 0,
        "requested_resource": "/api/v1/auth",
        "user_agent": "Mozilla"
    }])
    feat = extract_features(df)
    assert "packet_rate" in feat.columns
    assert "byte_rate" in feat.columns
    assert "url_entropy" in feat.columns
    assert not feat.isnull().any().any()


def test_supervised_training_and_metrics():
    sample_csv = SAMPLE_DATA_DIR / "sample_security_events.csv"
    if not sample_csv.exists():
        pytest.skip("Sample CSV does not exist")
    res = load_dataset(sample_csv)
    eval_results = train_and_evaluate_models(res.df, target_col="label")

    assert "Random Forest" in eval_results["models"]
    assert "Logistic Regression" in eval_results["models"]

    rf_metrics = eval_results["models"]["Random Forest"]["metrics"]
    assert "accuracy" in rf_metrics
    assert "f1_macro" in rf_metrics
    assert "confusion_matrix" in rf_metrics
    assert rf_metrics["accuracy"] >= 0.70  # Solid performance on synthetic data


def test_anomaly_detection_fallback():
    df = pd.DataFrame([{
        "duration_sec": 1.0,
        "bytes_sent": 100,
        "bytes_received": 100,
        "packets_sent": 2,
        "packets_received": 2,
        "dst_port": 80,
        "protocol": "TCP",
        "failed_login_count": 0,
        "requested_resource": "/",
        "user_agent": "test",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2"
    }] * 20)
    res = train_anomaly_detector(df, contamination=0.1)
    assert "anomaly_count" in res
    assert "anomaly_scores" in res
