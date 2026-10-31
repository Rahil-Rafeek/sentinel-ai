"""
Tests for Advanced Visualizations (Radar and Attack Topology)
"""

import pytest
import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.visualizations import create_interactive_threat_radar, create_network_attack_topology
from src.predict import ThreatInferenceEngine
from src.data_loader import load_dataset
from config.settings import SAMPLE_DATA_DIR


@pytest.fixture
def sample_detections():
    sample_file = SAMPLE_DATA_DIR / "sample_security_events.csv"
    res = load_dataset(sample_file)
    engine = ThreatInferenceEngine()
    return engine.predict_events(res.df)


def test_threat_radar_rendering(sample_detections):
    fig = create_interactive_threat_radar(sample_detections)
    assert fig is not None
    assert hasattr(fig, "data")
    assert len(fig.data) > 0
    # Should contain polar scatter data trace
    assert fig.data[0].type == "scatterpolar"


def test_threat_radar_empty():
    empty_df = pd.DataFrame()
    fig = create_interactive_threat_radar(empty_df)
    assert fig is not None
    # Empty check returns annotation
    assert len(fig.layout.annotations) > 0


def test_network_topology_rendering(sample_detections):
    fig = create_network_attack_topology(sample_detections)
    assert fig is not None
    assert hasattr(fig, "data")
    assert len(fig.data) > 0
    assert fig.data[0].type == "sankey"
    assert "node" in fig.data[0]
    assert "link" in fig.data[0]
