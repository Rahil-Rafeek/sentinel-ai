import os
import sys
import json
import uuid
import shutil
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# Add project root to sys.path so 'backend.app' imports resolve cleanly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import settings
from backend.app.database.session import init_db, SessionLocal
from backend.app.database.models import Dataset, AnalysisJob
from backend.app.ingestion.csv_ingestion import inspect_and_read_csv
from backend.app.services.profiling_service import infer_column_mappings, assess_compatibility, generate_data_profile
from backend.app.services.detection_service import run_analysis_pipeline

from backend.app.api.routes import (
    datasets, analysis, events, alerts, analytics, detect, monitoring, system
)

def seed_initial_benchmark_dataset():
    """Seed initial sample dataset on first launch if database is empty."""
    db = SessionLocal()
    try:
        count = db.query(Dataset).count()
        if count == 0:
            sample_src = PROJECT_ROOT / "data" / "sample" / "sample_security_events.csv"
            if sample_src.exists():
                ds_id = "ds-benchmark"
                target_path = settings.UPLOADS_DIR / f"{ds_id}_sample_security_events.csv"
                shutil.copyfile(sample_src, target_path)

                df, meta = inspect_and_read_csv(target_path)
                suggested_mapping, _ = infer_column_mappings(list(df.columns))
                compat_status, compat_reasons = assess_compatibility(suggested_mapping, df)
                data_profile = generate_data_profile(df)

                benchmark_ds = Dataset(
                    id=ds_id,
                    filename="CIC-Benchmark-Telemetry.csv",
                    filepath=str(target_path),
                    file_size_bytes=meta["file_size_bytes"],
                    row_count=meta["raw_row_count"],
                    column_count=meta["raw_col_count"],
                    compatibility_status=compat_status,
                    compatibility_reasons=json.dumps(compat_reasons),
                    is_active=True,
                    column_mapping=json.dumps(suggested_mapping),
                    data_profile=json.dumps(data_profile)
                )
                db.add(benchmark_ds)
                db.commit()

                # Run initial analysis job
                job_id = "job-initial-benchmark"
                job = AnalysisJob(
                    id=job_id,
                    dataset_id=benchmark_ds.id,
                    status="queued",
                    progress_pct=10.0
                )
                db.add(job)
                db.commit()

                # Execute synchronously during initial cold start
                run_analysis_pipeline(db, job_id)
                print(f"[SENTINEL AI] Seeded and analyzed initial benchmark dataset '{benchmark_ds.filename}'.")
    except Exception as ex:
        print(f"[SENTINEL AI] Warning during initial seed: {ex}")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables and seed benchmark data
    init_db()
    seed_initial_benchmark_dataset()
    yield
    # Shutdown

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Intelligent Cybersecurity Threat Detection & Monitoring System REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS (Supports localhost, LAN IPs 192.168.x.x, iOS, Windows, and remote tunnels)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Routers
app.include_router(datasets.router, prefix=f"{settings.API_V1_STR}/datasets", tags=["Datasets"])
app.include_router(analysis.router, prefix=f"{settings.API_V1_STR}/analysis", tags=["Analysis"])
app.include_router(events.router, prefix=f"{settings.API_V1_STR}/events", tags=["Events"])
app.include_router(alerts.router, prefix=f"{settings.API_V1_STR}/alerts", tags=["Alerts"])
app.include_router(analytics.router, prefix=f"{settings.API_V1_STR}/analytics", tags=["Analytics"])
app.include_router(detect.router, prefix=f"{settings.API_V1_STR}/detect", tags=["Detection"])
app.include_router(monitoring.router, prefix=f"{settings.API_V1_STR}/monitoring", tags=["Monitoring"])
app.include_router(system.router, prefix=f"{settings.API_V1_STR}/system", tags=["System"])

@app.api_route("/health", methods=["GET", "HEAD"], tags=["Health"])
def health():
    return {"status": "healthy"}

DIST_DIR = PROJECT_ROOT / "frontend" / "dist"
if DIST_DIR.exists() and (DIST_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="assets")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"], tags=["Frontend"])
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("redoc") or full_path == "openapi.json":
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        
        file_path = DIST_DIR / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(DIST_DIR / "index.html")
else:
    @app.get("/", tags=["Health"])
    def root():
        return {
            "system": settings.PROJECT_NAME,
            "version": "1.0.0",
            "status": "operational",
            "api_documentation": "/docs"
        }

