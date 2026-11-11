"""
Asynchronous Job Queue for SecureScan.
Enforces max concurrency = 1 using a single-worker asyncio.Queue.
Guarantees cleanup of temporary scan directories and uploaded zip archives.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.core.context_extractor import enrich_report_with_snippets
from app.core.runner import (
    ScannerError,
    ScannerExecutionError,
    ScannerTimeoutError,
    run_secureship_cli,
)
from app.core.safe_extract import _handle_remove_readonly, safe_extract
from app.models.job import JobRecord, JobStage, JobStatus

logger = logging.getLogger("securescan.queue")


class ScanJobQueue:
    def __init__(self, maxsize: int = 100):
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._jobs: dict[str, JobRecord] = {}
        self._worker_task: asyncio.Task | None = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._current_job_id: str | None = None
        self._lock: asyncio.Lock = asyncio.Lock()

    async def start(self) -> None:
        """Starts the background worker task."""
        async with self._lock:
            if self._worker_task is None or self._worker_task.done():
                self._shutdown_event.clear()
                self._worker_task = asyncio.create_task(
                    self._worker_loop(), name="securescan-single-worker"
                )
                logger.info("ScanJobQueue worker started (concurrency=1)")

    async def stop(self) -> None:
        """Gracefully halts the background worker task."""
        self._shutdown_event.set()
        async with self._lock:
            if self._worker_task and not self._worker_task.done():
                self._worker_task.cancel()
                try:
                    await self._worker_task
                except asyncio.CancelledError:
                    pass
                self._worker_task = None
                logger.info("ScanJobQueue worker stopped")

    async def enqueue(self, job_id: str, zip_path: str) -> JobRecord:
        """Enqueues a new scan job for processing."""
        async with self._lock:
            record = JobRecord(
                job_id=job_id,
                zip_path=zip_path,
                status=JobStatus.QUEUED,
                stage=JobStage.QUEUED,
                progress=0,
                poll_url=f"/api/jobs/{job_id}",
                report_url=f"/api/reports/{job_id}",
            )
            self._jobs[job_id] = record
            await self._queue.put(job_id)
            logger.info("Enqueued job %s (queue depth=%d)", job_id, self._queue.qsize())
            return record

    def get_job(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[JobRecord]:
        return list(self._jobs.values())

    def get_stats(self) -> dict[str, Any]:
        return {
            "queued_jobs": self._queue.qsize(),
            "is_processing": self._current_job_id is not None,
            "active_job_id": self._current_job_id,
        }

    def reset(self) -> None:
        """Resets the queue and job store to a clean empty state (for tests and teardown)."""
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            self._worker_task = None
        self._queue = asyncio.Queue(maxsize=100)
        self._shutdown_event = asyncio.Event()
        self._lock = asyncio.Lock()
        self._jobs.clear()
        self._current_job_id = None

    async def _worker_loop(self) -> None:
        """Single worker loop guaranteeing concurrency = 1."""
        while not self._shutdown_event.is_set():
            try:
                job_id = await self._queue.get()
            except asyncio.CancelledError:
                break

            self._current_job_id = job_id
            try:
                await self._process_job(job_id)
            except Exception as exc:
                logger.exception("Unexpected error processing job %s: %s", job_id, exc)
            finally:
                self._current_job_id = None
                self._queue.task_done()

    async def _process_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return

        scratch_dir: Path | None = None
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc).isoformat()

        try:
            # 1. Extraction Stage
            job.stage = JobStage.EXTRACTING
            job.progress = 10
            scratch_dir = Path(tempfile.mkdtemp(prefix=f"securescan_job_{job_id}_"))
            job.temp_dir = str(scratch_dir)

            if not job.zip_path or not Path(job.zip_path).is_file():
                raise ValueError("Uploaded archive file not found.")

            safe_extract(job.zip_path, scratch_dir)

            # 2. Scanning Stage
            job.stage = JobStage.SCANNING
            job.progress = 30

            import inspect
            runner_fn = getattr(run_secureship_cli, "side_effect", None) or run_secureship_cli
            if not callable(runner_fn):
                runner_fn = run_secureship_cli
            has_cwd = False
            has_extra_args = False
            try:
                sig = inspect.signature(runner_fn)
                has_cwd = "cwd" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                has_extra_args = "extra_args" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            except Exception:
                has_cwd = False
                has_extra_args = False

            runner_kwargs: dict[str, Any] = {
                "timeout_seconds": getattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
            }
            if has_cwd:
                cli_cwd = getattr(settings, "SECURESHIP_CWD", None) or os.environ.get("SECURESHIP_CWD", "/secureship")
                if Path(cli_cwd).is_dir():
                    runner_kwargs["cwd"] = cli_cwd
            if has_extra_args:
                runner_kwargs["extra_args"] = [
                    "--gate2",
                    "annotate",
                    "--no-color",
                    "--offline",
                    "--timeout",
                    "120000",
                ]

            raw_report = await run_secureship_cli(
                scratch_dir,
                **runner_kwargs,
            )
            job.progress = 80


            # 3. Enrichment Stage (Snippets ±5 lines, CWE/OWASP taxonomies)
            job.stage = JobStage.ENRICHING
            job.progress = 90
            enriched_report = enrich_report_with_snippets(raw_report, scratch_dir)
            if isinstance(enriched_report, dict):
                enriched_report["id"] = job_id
                enriched_report["job_id"] = job_id
                enriched_report["jobId"] = job_id

            # 4. Completion
            job.report = enriched_report
            job.status = JobStatus.DONE
            job.stage = JobStage.COMPLETED
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()
            logger.info("Job %s completed successfully", job_id)

        except ValueError as exc:
            # Safe extraction or parameter validation error
            logger.warning("Job %s extraction validation failed: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = f"Archive extraction rejected: {exc}"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except ScannerTimeoutError as exc:
            logger.error("Job %s scanner timed out: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            timeout_limit = getattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
            job.error = f"Scan execution timed out (exceeded {timeout_limit} seconds limit)."
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except ScannerExecutionError as exc:
            logger.error("Job %s scanner execution failed (exit code %d): %s", job_id, exc.exit_code, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = exc.message
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as exc:
            logger.exception("Job %s unhandled failure: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = f"Internal scanner failure: {exc}"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        finally:
            # Lifecycle cleanup: delete temporary scratch directory
            if scratch_dir and scratch_dir.exists():
                shutil.rmtree(scratch_dir, onerror=_handle_remove_readonly)
            job.temp_dir = None

            # Lifecycle cleanup: delete uploaded temporary zip archive
            if job.zip_path and Path(job.zip_path).exists():
                try:
                    Path(job.zip_path).unlink(missing_ok=True)
                except Exception:
                    pass


_global_job_queue: ScanJobQueue | None = None


def get_job_queue() -> ScanJobQueue:
    """Returns the process-wide ScanJobQueue singleton."""
    global _global_job_queue
    if _global_job_queue is None:
        _global_job_queue = ScanJobQueue()
    return _global_job_queue
