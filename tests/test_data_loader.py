"""
Tests for Data Loader & Schema Ingestion
"""

import pytest
import pandas as pd
import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.data_loader import load_dataset, detect_and_map_columns


def test_valid_csv_loading():
    csv_data = """timestamp,src_ip,dst_ip,dst_port,protocol,bytes_sent,bytes_received,packets_sent,packets_received
2026-10-26 10:00:00,192.168.1.10,10.0.0.1,80,TCP,500,1200,5,8
2026-10-26 10:00:05,192.168.1.11,10.0.0.1,443,TCP,800,2400,8,12
"""
    result = load_dataset(io.StringIO(csv_data))
    assert result.is_valid is True
    assert len(result.df) == 2
    assert "src_ip" in result.df.columns
    assert "dst_port" in result.df.columns
    assert result.df.iloc[0]["dst_port"] == 80


def test_column_synonyms_mapping():
    csv_data = """Source IP,Destination IP,Destination Port,Protocol,Tot Bytes Out
192.168.1.50,10.0.0.2,22,TCP,150
"""
    result = load_dataset(io.StringIO(csv_data))
    assert result.is_valid is True
    assert "src_ip" in result.df.columns
    assert "dst_ip" in result.df.columns
    assert "dst_port" in result.df.columns
    assert "bytes_sent" in result.df.columns
    assert result.df.iloc[0]["src_ip"] == "192.168.1.50"


def test_missing_and_corrupt_values():
    csv_data = """timestamp,src_ip,dst_ip,dst_port,bytes_sent
2026-10-26 10:00:00,192.168.1.10,,80,corrupted_num
2026-10-26 10:00:05,192.168.1.11,10.0.0.1,invalid_port,100
"""
    result = load_dataset(io.StringIO(csv_data))
    assert result.is_valid is True
    assert len(result.df) == 2
    # Check fallback values
    assert result.df.iloc[0]["bytes_sent"] == 0
    assert result.df.iloc[1]["dst_port"] == 80  # Default port fallback


def test_empty_csv():
    result = load_dataset(io.StringIO(""))
    assert result.is_valid is False
    assert "empty" in result.message.lower() or "failed" in result.message.lower()


def test_deduplication():
    csv_data = """timestamp,src_ip,dst_ip,dst_port,bytes_sent
2026-10-26 10:00:00,192.168.1.10,10.0.0.1,80,500
2026-10-26 10:00:00,192.168.1.10,10.0.0.1,80,500
"""
    result = load_dataset(io.StringIO(csv_data))
    assert result.is_valid is True
    assert len(result.df) == 1
    assert result.report["duplicates_removed"] == 1
