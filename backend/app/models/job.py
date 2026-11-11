"""
Job Lifecycle Data Models for SecureScan.
Tracks asynchronous scanning job states, progress, and execution metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from pydantic import Field

from app.models.report import BaseSchema, ScanReport


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class JobStage(str, Enum):
    QUEUED = "queued"
    EXTRACTING = "extracting"
    SCANNING = "scanning"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"


class JobRecord(BaseSchema):
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    stage: JobStage = JobStage.QUEUED
    progress: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    zip_path: Optional[str] = None
    temp_dir: Optional[str] = None
    report: Optional[Union[dict[str, Any], ScanReport]] = None
    error: Optional[str] = None
    poll_url: str = ""
    report_url: Optional[str] = None
    target_name: Optional[str] = None
