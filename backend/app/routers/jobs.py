"""
Jobs and Reports Router for SecureScan.
Exposes endpoints for polling job status and retrieving completed scan reports.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.core.queue import get_job_queue
from app.exporters.json_exporter import normalize_report_dict
from app.models.job import JobStatus

router = APIRouter(tags=["jobs"])


@router.get("/jobs/{job_id}", status_code=status.HTTP_200_OK)
async def get_job_status(job_id: str) -> dict[str, Any]:
    """
    Returns current execution status and progress for a scan job.
    """
    queue = get_job_queue()
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    return {
        "job_id": job.job_id,
        "jobId": job.job_id,
        "status": job.status.value,
        "stage": job.stage.value,
        "progress": job.progress,
        "poll_url": job.poll_url or f"/api/jobs/{job.job_id}",
        "pollUrl": job.poll_url or f"/api/jobs/{job.job_id}",
        "report_url": job.report_url or f"/api/reports/{job.job_id}",
        "reportUrl": job.report_url or f"/api/reports/{job.job_id}",
        "error": job.error,
        "target_name": job.target_name,
        "targetName": job.target_name,
        "created_at": job.created_at,
        "createdAt": job.created_at,
        "started_at": job.started_at,
        "startedAt": job.started_at,
        "completed_at": job.completed_at,
        "completedAt": job.completed_at,
        "finished_at": job.completed_at,
        "finishedAt": job.completed_at,
    }


@router.get("/reports/{job_id}", status_code=status.HTTP_200_OK)
async def get_scan_report(job_id: str) -> dict[str, Any]:
    """
    Returns the complete unified security scan report for a finished job.
    Fails closed with 404 if not found, 409 if still in progress, 422 if failed.
    """
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
            detail=f"Scan failed: {job.error or 'Internal scanner failure'}",
        )

    if job.status != JobStatus.DONE or not job.report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report payload not available for job '{job_id}'.",
        )

    normalized = normalize_report_dict(job.report)
    normalized["id"] = job.job_id
    normalized["job_id"] = job.job_id
    normalized["jobId"] = job.job_id
    if job.target_name and not normalized.get("target_name"):
        normalized["target_name"] = job.target_name
        normalized["targetName"] = job.target_name
    elif not normalized.get("targetName") and normalized.get("target_name"):
        normalized["targetName"] = normalized.get("target_name")

    return normalized
