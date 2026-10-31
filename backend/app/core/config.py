import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
MODELS_DIR = DATA_DIR / "models"
EXPORTS_DIR = DATA_DIR / "exports"

# Ensure runtime directories exist
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    model_config = ConfigDict(case_sensitive=True, arbitrary_types_allowed=True)

    PROJECT_NAME: str = "Sentinel AI"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = True
    
    # Directories
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    UPLOADS_DIR: Path = UPLOADS_DIR
    MODELS_DIR: Path = MODELS_DIR
    EXPORTS_DIR: Path = EXPORTS_DIR

    # Database
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'sentinel_main.db'}"
    
    # Ingestion & Upload limits
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    MAX_PROCESSED_ROWS: int = 50000                 # Max rows to process for responsive local analysis
    ALLOWED_EXTENSIONS: list[str] = [".csv", ".txt"]
    
    # Detection Thresholds
    BRUTE_FORCE_FAIL_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SEC: int = 60
    PORT_SCAN_PORT_THRESHOLD: int = 10
    PORT_SCAN_WINDOW_SEC: int = 60
    TRAFFIC_ANOMALY_ZSCORE_THRESHOLD: float = 3.0
    EXFILTRATION_BYTES_THRESHOLD: int = 50 * 1024 * 1024  # 50 MB
    URL_ENTROPY_THRESHOLD: float = 4.2
    URL_MAX_LENGTH_THRESHOLD: int = 70
    
    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8501",
        "*"
    ]

settings = Settings()
