"""
SQLAlchemy Database Models for RDRS
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class FileEventDB(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().isoformat())
    event_type = Column(String, nullable=False)  # created, modified, deleted, renamed
    file_path = Column(String, nullable=False)
    dest_path = Column(String, nullable=True)
    extension = Column(String, nullable=False)
    entropy = Column(Float, default=0.0)
    process_id = Column(Integer, nullable=True)


class ProcessLogDB(Base):
    __tablename__ = "process_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().isoformat())
    pid = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    num_threads = Column(Integer, default=1)
    status = Column(String, default="running")
    is_suspicious = Column(Boolean, default=False)


class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().isoformat())
    severity = Column(String, nullable=False)  # Normal, Warning, Critical
    threat_score = Column(Integer, nullable=False)
    message = Column(Text, nullable=False)
    detection_signals = Column(Text, nullable=False)  # JSON formatted string
    affected_files = Column(Text, nullable=False)     # JSON formatted string


class IncidentDB(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(String, index=True, default=lambda: datetime.now().isoformat())
    threat_score = Column(Integer, nullable=False)
    severity = Column(String, nullable=False)
    affected_files_count = Column(Integer, nullable=False)
    affected_files = Column(Text, nullable=False)  # JSON string
    process_name = Column(String, nullable=True)
    process_pid = Column(Integer, nullable=True)
    detection_signals = Column(Text, nullable=False)  # JSON string
    status = Column(String, default="Contained (Simulation)")
    quarantine_paths = Column(Text, nullable=True)     # JSON string
