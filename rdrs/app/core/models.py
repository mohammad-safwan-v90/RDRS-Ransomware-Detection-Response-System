"""
Pydantic Data Models for RDRS
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class FileEventModel(BaseModel):
    id: Optional[int] = None
    timestamp: str
    event_type: str  # created, modified, deleted, renamed
    file_path: str
    dest_path: Optional[str] = None
    extension: str
    entropy: float = 0.0
    process_id: Optional[int] = None

class ProcessMetadataModel(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    num_threads: int
    status: str
    cmdline: List[str] = []
    is_suspicious: bool = False

class AlertModel(BaseModel):
    id: Optional[int] = None
    timestamp: str
    severity: str  # Normal, Warning, Critical
    threat_score: int
    message: str
    detection_signals: List[str]
    affected_files: List[str]

class IncidentModel(BaseModel):
    incident_id: str
    timestamp: str
    threat_score: int
    severity: str
    affected_files_count: int
    affected_files: List[str]
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    detection_signals: List[str]
    status: str = "Contained (Simulation)"
    quarantine_paths: List[str] = []
    response_actions: List[str] = []

class SystemStatusModel(BaseModel):
    threat_level: str
    threat_score: int
    active_alerts_count: int
    total_events_count: int
    is_monitoring: bool
    simulation_mode: bool
    cpu_usage: float
    avg_entropy: float
