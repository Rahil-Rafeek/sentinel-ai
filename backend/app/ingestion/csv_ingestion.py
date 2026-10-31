import os
import csv
from pathlib import Path
import pandas as pd
from fastapi import HTTPException
from backend.app.core.config import settings

def inspect_and_read_csv(
    file_path: Path,
    max_rows: int = settings.MAX_PROCESSED_ROWS
) -> tuple[pd.DataFrame, dict]:
    """
    Safely inspect, validate, and parse an uploaded CSV file with encoding fallbacks
    and bounded memory limits.
    """
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Uploaded file not found on disk.")

    file_size = file_path.stat().st_size
    if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES / (1024*1024):.1f} MB."
        )

    encodings_to_try = ["utf-8", "utf-8-sig", "latin1", "iso-8859-1", "cp1252"]
    df = None
    used_encoding = None

    for enc in encodings_to_try:
        try:
            # Sniff separator
            with open(file_path, "r", encoding=enc, errors="replace") as f:
                sample_snippet = "".join([f.readline() for _ in range(15)])
                if not sample_snippet.strip():
                    raise HTTPException(status_code=400, detail="Uploaded CSV file is empty.")
                try:
                    dialect = csv.Sniffer().sniff(sample_snippet, delimiters=",\t;|")
                    delimiter = dialect.delimiter
                except Exception:
                    delimiter = ","

            df = pd.read_csv(
                file_path,
                sep=delimiter,
                encoding=enc,
                nrows=max_rows,
                on_bad_lines="skip"
            )
            used_encoding = enc
            break
        except Exception:
            continue

    if df is None or df.empty:
        raise HTTPException(status_code=400, detail="Failed to parse CSV file or file is empty.")

    # Strip column names of whitespace and quotes
    df.columns = [str(c).strip().strip('"').strip("'") for c in df.columns]

    meta = {
        "encoding": used_encoding,
        "delimiter": delimiter,
        "raw_row_count": len(df),
        "raw_col_count": len(df.columns),
        "file_size_bytes": file_size,
    }

    return df, meta
