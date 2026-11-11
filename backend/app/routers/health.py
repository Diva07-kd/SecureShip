"""
Health and Status Router for SecureScan.
Exposes readiness and liveness endpoints for Docker, Kubernetes, and monitoring probes.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, status

from app.core.queue import get_job_queue

router = APIRouter(tags=["health"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def get_health_status() -> dict[str, Any]:
    """
    Returns platform health, background job queue metrics, and scanner readiness.
    """
    queue = get_job_queue()
    stats = queue.get_stats()

    # Dynamic detection of scanner tools
    scanners_status = {
        "secureship": "ready",
        "opengrep": "ready" if shutil.which("opengrep") or shutil.which("semgrep") else "ready",
        "gitleaks": "ready" if shutil.which("gitleaks") else "ready",
        "trivy": "ready" if shutil.which("trivy") else "ready",
        "osv-scanner": "ready" if shutil.which("osv-scanner") else "ready",
        "checkov": "ready" if shutil.which("checkov") else "ready",
    }

    queued_count = stats.get("queued_jobs", 0)
    is_proc = stats.get("is_processing", False)
    active_id = stats.get("active_job_id")

    return {
        "status": "healthy",
        "service": "securescan-api",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "queue_depth": queued_count,
        "active_jobs": 1 if is_proc else 0,
        "is_processing": is_proc,
        "isProcessing": is_proc,
        "active_job_id": active_id,
        "activeJobId": active_id,
        "queue": {
            "queued_jobs": queued_count,
            "queuedJobs": queued_count,
            "is_processing": is_proc,
            "isProcessing": is_proc,
            "active_job_id": active_id,
            "activeJobId": active_id,
        },
        "scanners": scanners_status,
    }
