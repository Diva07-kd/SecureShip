"""
Report Export Router for SecureScan.
Exports scan reports in JSON, SARIF 2.1.0, standalone HTML, and binary PDF formats.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.core.queue import get_job_queue
from app.exporters import SUPPORTED_FORMATS, export_report
from app.models.job import JobStatus

logger = logging.getLogger("securescan.routers.reports")

router = APIRouter(tags=["reports"])


@router.get("/reports/{job_id}/export")
@router.get("/reports/{job_id}/export/")
async def export_scan_report(
    job_id: str,
    format: str = Query("json", description="Export format: json, sarif, html, pdf"),
) -> Response:
    """
    Exports a completed scan report to the requested file format:
    json, sarif, html, or pdf.
    Fails closed with 400 for invalid format, 404 for missing jobs,
    409 for in-progress scans, and 422 for failed scans.
    """
    export_format = format.lower().strip() if (format and format.strip()) else "json"
    if export_format not in SUPPORTED_FORMATS:
        valid_formats = ", ".join(SUPPORTED_FORMATS.keys())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{format}'. Valid formats are: {valid_formats}.",
        )

    queue = get_job_queue()
    job = queue.get_job(job_id)
    if not job and job_id in ("scan-report", "latest", "default"):
        completed = [j for j in queue.list_jobs() if j.status == JobStatus.DONE and j.report]
        if completed:
            job = completed[-1]

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan report not ready (status: {job.status.value}, progress: {job.progress}%).",
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scan failed: {job.error or 'Execution failed'}",
        )

    if job.status != JobStatus.DONE or not job.report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report payload not available for job '{job_id}'.",
        )

    try:
        content_bytes, content_type, ext = export_report(job.report, export_format)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Export generation failed for job %s (format %s): %s", job_id, export_format, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed generating {export_format.upper()} export: {exc}",
        )

    filename = f"securescan-report-{job_id}.{ext}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": content_type,
    }

    return Response(
        content=content_bytes,
        media_type=content_type,
        headers=headers,
    )
