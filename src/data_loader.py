"""
Sentinel AI — Data Ingestion & Validation Module
Handles robust CSV loading, schema validation, synonym-based column normalization,
missing-value imputation, duplicate handling, and file size guardrails.
"""

import io
from typing import Union, Tuple, Dict, Any, Optional
import pandas as pd
import numpy as np
import sys
from pathlib import Path
import logging

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import STANDARD_COLUMNS, COLUMN_SYNONYMS

logger = logging.getLogger("sentinel.data_loader")

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB safety limit

class DataLoaderResult:
    def __init__(self, df: pd.DataFrame, report: Dict[str, Any]):
        self.df = df
        self.report = report

    @property
    def is_valid(self) -> bool:
        return self.report.get("is_valid", False)

    @property
    def message(self) -> str:
        return self.report.get("message", "")


def detect_and_map_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Scans dataframe headers and maps them to standard schema names
    using synonym dictionaries.
    """
    mapped_columns = {}
    rename_dict = {}

    lower_cols = {col.strip().lower(): col for col in df.columns}

    for std_col, synonyms in COLUMN_SYNONYMS.items():
        matched = False
        for syn in synonyms:
            syn_lower = syn.strip().lower()
            if syn_lower in lower_cols:
                original_col = lower_cols[syn_lower]
                rename_dict[original_col] = std_col
                mapped_columns[std_col] = original_col
                matched = True
                break
        if not matched and std_col in df.columns:
            mapped_columns[std_col] = std_col

    df_renamed = df.rename(columns=rename_dict)
    return df_renamed, mapped_columns


def load_dataset(
    source: Union[str, Path, io.BytesIO, io.StringIO, Any],
    custom_mapping: Optional[Dict[str, str]] = None
) -> DataLoaderResult:
    """
    Loads, validates, and cleans security logs or network traffic datasets.
    Can accept a filepath, file-like object, or Streamlit UploadedFile.
    """
    report: Dict[str, Any] = {
        "is_valid": False,
        "message": "",
        "total_rows_raw": 0,
        "rows_cleaned": 0,
        "duplicates_removed": 0,
        "missing_imputed": 0,
        "mapped_columns": {},
        "missing_standard_columns": [],
        "warnings": []
    }

    # 1. Validation: file size / stream type
    try:
        if hasattr(source, "size") and source.size is not None:
            if source.size > MAX_FILE_SIZE_BYTES:
                report["message"] = f"File size ({source.size / (1024*1024):.1f}MB) exceeds 50MB safety limit."
                return DataLoaderResult(pd.DataFrame(), report)

        # Read CSV
        if isinstance(source, (str, Path)):
            p = Path(source)
            if not p.exists():
                report["message"] = f"File not found: {p}"
                return DataLoaderResult(pd.DataFrame(), report)
            df = pd.read_csv(p)
        else:
            df = pd.read_csv(source)

    except Exception as e:
        report["message"] = f"Failed to parse CSV file: {str(e)}"
        logger.error(f"Error reading CSV: {e}")
        return DataLoaderResult(pd.DataFrame(), report)

    report["total_rows_raw"] = len(df)

    if len(df) == 0:
        report["message"] = "Uploaded CSV file is empty."
        return DataLoaderResult(df, report)

    # 2. Column Mapping
    if custom_mapping:
        inv_map = {v: k for k, v in custom_mapping.items() if v in df.columns}
        df = df.rename(columns=inv_map)
        report["mapped_columns"] = {k: v for k, v in custom_mapping.items() if v in df.columns}
    else:
        df, mapped = detect_and_map_columns(df)
        report["mapped_columns"] = mapped

    # Check for missing essential columns
    essential_columns = ["src_ip", "dst_ip", "dst_port"]
    missing_essentials = [col for col in essential_columns if col not in df.columns]
    if missing_essentials:
        report["warnings"].append(
            f"Missing essential network columns: {missing_essentials}. Some detection rules may have degraded accuracy."
        )

    # Fill default values for missing standard columns
    defaults = {
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 0,
        "dst_port": 80,
        "protocol": "TCP",
        "duration_sec": 0.1,
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_sent": 1,
        "packets_received": 1,
        "failed_login_count": 0,
        "requested_resource": "/",
        "user_agent": "UNKNOWN"
    }

    missing_standard = []
    for col, default_val in defaults.items():
        if col not in df.columns:
            df[col] = default_val
            missing_standard.append(col)
    report["missing_standard_columns"] = missing_standard

    # 3. Deduplication
    initial_count = len(df)
    # Check deduplication on subset if possible
    dedup_subset = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "bytes_sent"] if c in df.columns]
    if dedup_subset:
        df = df.drop_duplicates(subset=dedup_subset, keep="first")
    else:
        df = df.drop_duplicates()
    report["duplicates_removed"] = initial_count - len(df)

    # 4. Impute Missing Values in Existing Columns
    missing_cells_count = df.isnull().sum().sum()
    report["missing_imputed"] = int(missing_cells_count)

    numeric_cols = ["src_port", "dst_port", "duration_sec", "bytes_sent", "bytes_received", "packets_sent", "packets_received", "failed_login_count"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(defaults.get(col, 0))

    str_cols = ["src_ip", "dst_ip", "protocol", "requested_resource", "user_agent"]
    for col in str_cols:
        if col in df.columns:
            df[col] = df[col].fillna(defaults.get(col, "UNKNOWN")).astype(str)

    # Clean protocols
    df["protocol"] = df["protocol"].str.upper().str.strip()

    # Cast integer columns safely
    int_cols = ["src_port", "dst_port", "bytes_sent", "bytes_received", "packets_sent", "packets_received", "failed_login_count"]
    for col in int_cols:
        if col in df.columns:
            df[col] = df[col].astype(int)

    # 5. Timestamp validation & parsing
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        # Fill any invalid timestamps with forward-fill or now
        if df["timestamp"].isnull().any():
            df["timestamp"] = df["timestamp"].bfill().ffill().fillna(pd.Timestamp.now())
        # Sort by timestamp
        df = df.sort_values("timestamp").reset_index(drop=True)
        # Format consistently as string for serializability
        df["timestamp_str"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    report["rows_cleaned"] = len(df)
    report["is_valid"] = True
    report["message"] = f"Successfully loaded and validated {len(df)} records."

    return DataLoaderResult(df, report)
