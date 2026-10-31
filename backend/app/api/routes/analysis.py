import json
import uuid
import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from backend.app.database.session import get_db, SessionLocal
from backend.app.database.models import Dataset, AnalysisJob
from backend.app.schemas.analysis import StartAnalysisRequest, AnalysisJobResponse
from backend.app.services.detection_service import run_analysis_pipeline

router = APIRouter()

def execute_job_in_background(job_id: str):
    db = SessionLocal()
    try:
        run_analysis_pipeline(db, job_id)
    finally:
        db.close()

@router.post("/start", response_model=AnalysisJobResponse)
def start_analysis(
    req: StartAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start an end-to-end detection and ML classification job for a dataset."""
    dataset = db.query(Dataset).filter(Dataset.id == req.dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    job_id = f"job-{uuid.uuid4().hex[:8]}"
    job = AnalysisJob(
        id=job_id,
        dataset_id=dataset.id,
        status="queued",
        progress_pct=5.0,
        started_at=datetime.datetime.utcnow()
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Launch pipeline
    background_tasks.add_task(execute_job_in_background, job.id)

    return {
        "id": job.id,
        "dataset_id": job.dataset_id,
        "status": job.status,
        "progress_pct": job.progress_pct,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
        "detector_results_summary": {},
        "ml_metrics": {}
    }

@router.get("/{job_id}/status", response_model=AnalysisJobResponse)
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Retrieve progress percentage and status of an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    return {
        "id": job.id,
        "dataset_id": job.dataset_id,
        "status": job.status,
        "progress_pct": job.progress_pct,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
        "detector_results_summary": json.loads(job.detector_results_summary or "{}"),
        "ml_metrics": json.loads(job.ml_metrics or "{}")
    }

@router.post("/{job_id}/cancel")
def cancel_job(job_id: str, db: Session = Depends(get_db)):
    """Cancel a running analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    if job.status in ["completed", "failed"]:
        return {"status": job.status, "message": "Job has already finished."}

    job.status = "cancelled"
    job.completed_at = datetime.datetime.utcnow()
    db.commit()
    return {"status": "cancelled", "message": f"Job {job_id} cancelled."}

@router.get("/{job_id}/results")
def get_job_results(job_id: str, db: Session = Depends(get_db)):
    """Retrieve detection summaries and machine learning evaluation metrics."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    return {
        "job_id": job.id,
        "dataset_id": job.dataset_id,
        "status": job.status,
        "detector_results_summary": json.loads(job.detector_results_summary or "{}"),
        "ml_metrics": json.loads(job.ml_metrics or "{}")
    }
