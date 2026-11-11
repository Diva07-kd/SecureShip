"""
Upload Router for SecureScan.
Accepts .zip file uploads, enforces 600MB file size ceiling, validates zip signatures,
enforces 10 uploads/hour/IP rate limiting, and enqueues scan jobs.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.core.queue import get_job_queue

router = APIRouter(tags=["scan"])
limiter = Limiter(key_func=get_remote_address)

MAX_UPLOAD_BYTES = 600 * 1024 * 1024  # 600 MB limit
ZIP_MAGIC_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@router.post("/scan", status_code=status.HTTP_200_OK)
@limiter.limit("10/hour")
async def upload_scan_archive(
    request: Request,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """
    Accepts .zip archive uploads, validates file type, signature, and size, and queues a scan job.
    Rate limited to 10 uploads per hour per client IP.
    """
    filename = file.filename or "archive.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type for '{filename}'. Only .zip archives are supported.",
        )

    job_id = str(uuid.uuid4())

    # Stream file to disk while enforcing max upload size and checking magic bytes
    temp_zip = tempfile.NamedTemporaryFile(prefix=f"upload_{job_id}_", suffix=".zip", delete=False)
    temp_zip_path = Path(temp_zip.name)

    total_uploaded = 0
    chunk_size = 64 * 1024
    first_chunk = True

    try:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break

            if first_chunk:
                first_chunk = False
                if not any(chunk.startswith(magic) for magic in ZIP_MAGIC_HEADERS):
                    temp_zip.close()
                    temp_zip_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="File is not a valid zip archive (missing PK magic header).",
                    )

            total_uploaded += len(chunk)
            if total_uploaded > MAX_UPLOAD_BYTES:
                temp_zip.close()
                temp_zip_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Uploaded archive exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit (received {total_uploaded} bytes).",
                )
            temp_zip.write(chunk)

        if total_uploaded == 0:
            temp_zip.close()
            temp_zip_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes).",
            )
    except HTTPException:
        temp_zip.close()
        temp_zip_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        temp_zip.close()
        temp_zip_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process archive upload: {exc}",
        )
    finally:
        temp_zip.close()

    # Enqueue job into single-worker queue
    queue = get_job_queue()
    record = await queue.enqueue(job_id=job_id, zip_path=str(temp_zip_path))
    record.target_name = filename

    return {
        "job_id": job_id,
        "jobId": job_id,
        "status": "queued",
        "poll_url": f"/api/jobs/{job_id}",
        "pollUrl": f"/api/jobs/{job_id}",
        "message": "Scan job successfully queued",
    }
