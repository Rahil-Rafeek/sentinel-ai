import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(512), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    row_count = Column(Integer, default=0)
    column_count = Column(Integer, default=0)
    compatibility_status = Column(String(64), default="pending")  # cybersecurity_compatible, partially_compatible, general_tabular, invalid
    compatibility_reasons = Column(Text, default="[]")           # JSON list of explanation notes
    is_active = Column(Boolean, default=False, index=True)
    column_mapping = Column(Text, default="{}")                   # Inferred / confirmed field mappings
    data_profile = Column(Text, default="{}")                     # Missing values, distinct types, sample preview
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    analysis_jobs = relationship("AnalysisJob", back_populates="dataset", cascade="all, delete-orphan")
    events = relationship("ThreatEventRecord", back_populates="dataset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="dataset", cascade="all, delete-orphan")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(64), primary_key=True, index=True)
    dataset_id = Column(String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="queued", index=True)      # queued, processing, completed, failed, cancelled
    progress_pct = Column(Float, default=0.0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    detector_results_summary = Column(Text, default="{}")         # JSON breakdown of detections
    ml_metrics = Column(Text, default="{}")                       # JSON evaluation stats or unsupervised scores

    # Relationships
    dataset = relationship("Dataset", back_populates="analysis_jobs")
    events = relationship("ThreatEventRecord", back_populates="analysis_job", cascade="all, delete-orphan")


class ThreatEventRecord(Base):
    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True, index=True)
    dataset_id = Column(String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    analysis_job_id = Column(String(64), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=True, index=True)
    timestamp = Column(String(64), index=True)
    category = Column(String(64), index=True)                     # Brute-Force Login, Port Scanning, etc.
    severity = Column(String(32), index=True)                     # Critical, High, Medium, Low, Info
    confidence = Column(Float, default=0.0)
    src_ip = Column(String(64), nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    duration_sec = Column(Float, default=0.0)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    detection_method = Column(String(128), default="Rule-Based")
    detection_type = Column(String(32), default="rule")           # rule, ml_supervised, ml_unsupervised, synthetic_demo, live_telemetry
    evidence = Column(Text, default="")
    recommended_action = Column(Text, default="")
    mitre_id = Column(String(32), default="")
    mitre_name = Column(String(128), default="")
    mitre_tactic = Column(String(64), default="")
    radar_angle = Column(Float, default=0.0)
    radar_radius = Column(Float, default=0.5)
    raw_data = Column(Text, default="{}")
    is_replay = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    dataset = relationship("Dataset", back_populates="events")
    analysis_job = relationship("AnalysisJob", back_populates="events")
    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_threat_events_cat_sev", "category", "severity"),
        Index("idx_threat_events_dataset_sev", "dataset_id", "severity"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False, index=True)
    dataset_id = Column(String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(64), index=True)
    severity = Column(String(32), index=True)
    confidence = Column(Float, default=0.0)
    status = Column(String(32), default="Open", index=True)       # Open, Investigating, Resolved, False Positive
    analyst_notes = Column(Text, default="")
    status_history = Column(Text, default="[]")                   # JSON list of state transitions
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    event = relationship("ThreatEventRecord", back_populates="alerts")
    dataset = relationship("Dataset", back_populates="alerts")


class ReplaySession(Base):
    __tablename__ = "replay_sessions"

    id = Column(String(64), primary_key=True, index=True)
    dataset_id = Column(String(64), nullable=False)
    status = Column(String(32), default="stopped")                # stopped, playing, paused, completed
    speed = Column(Float, default=1.0)
    current_index = Column(Integer, default=0)
    total_events = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(128), primary_key=True, index=True)
    value = Column(Text, default="{}")
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
