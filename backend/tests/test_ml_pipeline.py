import pandas as pd
import numpy as np
import pytest
from backend.app.services.ml_service import train_or_evaluate_ml

def test_supervised_ml_pipeline_with_labels():
    # 40 benign records, 40 attack records
    df = pd.DataFrame({
        "packets": list(np.random.randint(5, 50, 40)) + list(np.random.randint(500, 2000, 40)),
        "bytes": list(np.random.randint(100, 5000, 40)) + list(np.random.randint(50000, 200000, 40)),
        "duration": list(np.random.uniform(0.1, 1.0, 40)) + list(np.random.uniform(5.0, 30.0, 40)),
        "label": ["Benign"] * 40 + ["Attack"] * 40
    })
    mapping = {
        "packet_count": "packets",
        "byte_count": "bytes",
        "duration": "duration",
        "label": "label"
    }

    results = train_or_evaluate_ml(df, mapping, dataset_id="test_supervised")

    assert results["is_available"] is True
    assert results["is_supervised"] is True
    assert "Random Forest" in results["model_name"]
    assert 0.0 <= results["accuracy"] <= 1.0
    assert 0.0 <= results["f1_score"] <= 1.0
    assert results["confusion_matrix"] is not None

def test_unsupervised_ml_pipeline_without_labels():
    # Unlabeled data
    df = pd.DataFrame({
        "packets": list(np.random.randint(10, 50, 50)) + [10000, 25000],
        "bytes": list(np.random.randint(500, 2000, 50)) + [5000000, 9000000]
    })
    mapping = {
        "packet_count": "packets",
        "byte_count": "bytes",
        "label": None
    }

    results = train_or_evaluate_ml(df, mapping, dataset_id="test_unsupervised")

    assert results["is_available"] is True
    assert results["is_supervised"] is False
    assert "Isolation Forest" in results["model_name"]
    assert results["anomaly_count"] > 0
    assert "NOT claimed as confirmed cyberattacks" in results["notes"]
