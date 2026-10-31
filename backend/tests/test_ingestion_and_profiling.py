import tempfile
from pathlib import Path
import pandas as pd
import pytest
from backend.app.ingestion.csv_ingestion import inspect_and_read_csv
from backend.app.services.profiling_service import infer_column_mappings, assess_compatibility, generate_data_profile

def test_safe_csv_ingestion_valid():
    with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
        f.write("timestamp,src_ip,dst_ip,dst_port,packets,label\n")
        f.write("2026-10-26 10:00:00,192.168.1.5,10.0.0.1,80,15,Benign\n")
        f.write("2026-10-26 10:00:05,192.168.1.6,10.0.0.1,22,50,Brute-Force\n")
        temp_path = Path(f.name)

    try:
        df, meta = inspect_and_read_csv(temp_path)
        assert len(df) == 2
        assert "src_ip" in df.columns
        assert meta["raw_row_count"] == 2
    finally:
        temp_path.unlink()

def test_infer_column_mappings_with_alternative_names():
    cols = ["Time", "client_ip", "target_ip", "dport", "tot_pkts", "attack_class"]
    suggested, details = infer_column_mappings(cols)

    assert suggested["timestamp"] == "Time"
    assert suggested["src_ip"] == "client_ip"
    assert suggested["dst_ip"] == "target_ip"
    assert suggested["dst_port"] == "dport"
    assert suggested["packet_count"] == "tot_pkts"
    assert suggested["label"] == "attack_class"

def test_compatibility_assessment_cybersecurity():
    df = pd.DataFrame({
        "src_ip": ["1.1.1.1"],
        "dst_ip": ["2.2.2.2"],
        "dst_port": [80],
        "packet_count": [100]
    })
    mapping = {"src_ip": "src_ip", "dst_ip": "dst_ip", "dst_port": "dst_port", "packet_count": "packet_count"}
    status, reasons = assess_compatibility(mapping, df)
    assert status == "cybersecurity_compatible"
    assert len(reasons) > 0

def test_compatibility_assessment_general_tabular():
    df = pd.DataFrame({
        "temperature": [22.4, 23.1],
        "humidity": [60.0, 58.5]
    })
    mapping = {"timestamp": None, "src_ip": None, "dst_ip": None}
    status, reasons = assess_compatibility(mapping, df)
    assert status == "general_tabular"
    assert any("statistical anomaly" in r.lower() for r in reasons)

def test_generate_data_profile():
    df = pd.DataFrame({
        "A": [1, 2, None, 4],
        "B": ["apple", "banana", "cherry", "apple"]
    })
    profile = generate_data_profile(df)
    assert profile["total_rows"] == 4
    assert profile["total_columns"] == 2
    assert profile["missing_values"]["A"] == 1
    assert profile["missing_values"]["B"] == 0
    assert len(profile["sample_rows"]) == 4
