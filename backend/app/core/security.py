import re
import os
from pathlib import Path
from fastapi import HTTPException

SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded filename to prevent directory traversal and invalid characters.
    """
    clean_name = os.path.basename(filename).strip()
    clean_name = re.sub(r"[^\w\.\-]", "_", clean_name)
    if not clean_name or clean_name.startswith("."):
        clean_name = f"dataset_{clean_name.lstrip('.')}"
    return clean_name

def validate_filepath_safe(base_dir: Path, target_path: Path) -> Path:
    """
    Ensure target_path resides safely within base_dir (preventing path traversal).
    """
    resolved_base = base_dir.resolve()
    resolved_target = target_path.resolve()
    try:
        resolved_target.relative_to(resolved_base)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid file path detected (path traversal attempt).")
    return resolved_target
