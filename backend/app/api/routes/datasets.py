import os
import json
import uuid
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.security import sanitize_filename, validate_filepath_safe
from backend.app.database.session import get_db
from backend.app.database.models import Dataset, ThreatEventRecord, Alert, AnalysisJob
from backend.app.ingestion.csv_ingestion import inspect_and_read_csv
from backend.app.services.profiling_service import infer_column_mappings, assess_compatibility, generate_data_profile
from backend.app.schemas.dataset import (
    DatasetUploadResponse, DatasetConfirmMappingRequest, DatasetItem, DatasetDetailResponse
)

router = APIRouter()

@router.post("/upload", response_model=DatasetUploadResponse)
async def upload_dataset(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload a CSV dataset, validate it, infer column mapping roles, profile data quality,
    and assess cybersecurity compatibility.
    """
    clean_filename = sanitize_filename(file.filename or "uploaded_dataset.csv")
    ext = os.path.splitext(clean_filename)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Supported formats: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    dataset_id = f"ds-{uuid.uuid4().hex[:8]}"
    saved_filename = f"{dataset_id}_{clean_filename}"
    target_path = settings.UPLOADS_DIR / saved_filename
    validate_filepath_safe(settings.UPLOADS_DIR, target_path)

    # Stream file to disk
    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Inspect & parse CSV
    df, meta = inspect_and_read_csv(target_path)

    # Infer column roles & mapping
    suggested_mapping, mapping_details = infer_column_mappings(list(df.columns))

    # Assess dataset compatibility
    compat_status, compat_reasons = assess_compatibility(suggested_mapping, df)

    # Profile data quality
    data_profile = generate_data_profile(df)

    # Persist dataset record
    dataset = Dataset(
        id=dataset_id,
        filename=clean_filename,
        filepath=str(target_path),
        file_size_bytes=meta["file_size_bytes"],
        row_count=meta["raw_row_count"],
        column_count=meta["raw_col_count"],
        compatibility_status=compat_status,
        compatibility_reasons=json.dumps(compat_reasons),
        is_active=False,
        column_mapping=json.dumps(suggested_mapping),
        data_profile=json.dumps(data_profile)
    )

    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    return {
        "dataset_id": dataset.id,
        "filename": dataset.filename,
        "row_count": dataset.row_count,
        "column_count": dataset.column_count,
        "compatibility_status": dataset.compatibility_status,
        "compatibility_reasons": compat_reasons,
        "suggested_mapping": suggested_mapping,
        "mapping_details": mapping_details,
        "data_profile": data_profile
    }

@router.get("/", response_model=list[DatasetItem])
def list_datasets(db: Session = Depends(get_db)):
    """List all uploaded datasets with metadata and active state."""
    datasets = db.query(Dataset).order_by(Dataset.created_at.desc()).all()
    results = []
    for d in datasets:
        results.append({
            "id": d.id,
            "filename": d.filename,
            "file_size_bytes": d.file_size_bytes,
            "row_count": d.row_count,
            "column_count": d.column_count,
            "compatibility_status": d.compatibility_status,
            "compatibility_reasons": json.loads(d.compatibility_reasons or "[]"),
            "is_active": d.is_active,
            "created_at": d.created_at
        })
    return results

@router.get("/active", response_model=DatasetDetailResponse)
def get_active_dataset(db: Session = Depends(get_db)):
    """Retrieve the globally active dataset."""
    dataset = db.query(Dataset).filter(Dataset.is_active == True).first()
    if not dataset:
        dataset = db.query(Dataset).order_by(Dataset.created_at.desc()).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="No active dataset found. Please upload a dataset.")

    return {
        "id": dataset.id,
        "filename": dataset.filename,
        "file_size_bytes": dataset.file_size_bytes,
        "row_count": dataset.row_count,
        "column_count": dataset.column_count,
        "compatibility_status": dataset.compatibility_status,
        "compatibility_reasons": json.loads(dataset.compatibility_reasons or "[]"),
        "is_active": dataset.is_active,
        "created_at": dataset.created_at,
        "column_mapping": json.loads(dataset.column_mapping or "{}"),
        "data_profile": json.loads(dataset.data_profile or "{}")
    }

@router.get("/{dataset_id}", response_model=DatasetDetailResponse)
def get_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Retrieve detailed dataset profile and confirmed column mappings."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    return {
        "id": dataset.id,
        "filename": dataset.filename,
        "file_size_bytes": dataset.file_size_bytes,
        "row_count": dataset.row_count,
        "column_count": dataset.column_count,
        "compatibility_status": dataset.compatibility_status,
        "compatibility_reasons": json.loads(dataset.compatibility_reasons or "[]"),
        "is_active": dataset.is_active,
        "created_at": dataset.created_at,
        "column_mapping": json.loads(dataset.column_mapping or "{}"),
        "data_profile": json.loads(dataset.data_profile or "{}")
    }

@router.post("/{dataset_id}/mapping")
def confirm_column_mapping(dataset_id: str, req: DatasetConfirmMappingRequest, db: Session = Depends(get_db)):
    """Update and confirm column mappings for a dataset before running detection."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    dataset.column_mapping = json.dumps(req.mapping)
    db.commit()
    return {"status": "success", "message": "Column mapping confirmed."}

@router.post("/{dataset_id}/activate")
def set_active_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Set the active dataset controlling application-wide telemetry and views."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    db.query(Dataset).update({Dataset.is_active: False})
    dataset.is_active = True
    db.commit()

    return {"status": "success", "active_dataset_id": dataset.id, "filename": dataset.filename}

@router.delete("/{dataset_id}")
def delete_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Cascade delete a dataset, stored files, analysis jobs, events, and alerts."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    # Remove file on disk if exists
    try:
        fpath = Path(dataset.filepath)
        if fpath.exists():
            fpath.unlink()
    except Exception:
        pass

    db.delete(dataset)
    db.commit()

    # Re-elect next dataset as active if available
    remaining = db.query(Dataset).first()
    if remaining:
        remaining.is_active = True
        db.commit()

    return {"status": "success", "message": f"Dataset {dataset_id} deleted."}
