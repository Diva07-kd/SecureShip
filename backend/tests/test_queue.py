"""
Unit tests for Asynchronous Job Queue (backend/app/core/queue.py).
Tests FIFO scheduling, concurrency = 1 invariant, lifecycle state transitions,
failure handling, resource cleanup, and health metrics.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.core.queue import ScanJobQueue
from app.core.runner import ScannerExecutionError, ScannerTimeoutError
from app.models.job import JobStage, JobStatus


@pytest.fixture
def temp_zip(tmp_path):
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(b"PK\x03\x04test_content")
    return zip_file


@pytest.mark.asyncio
async def test_queue_concurrency_one_invariant(tmp_path):
    """Validates that at most 1 job is executing concurrently."""
    queue = ScanJobQueue()
    await queue.start()

    concurrent_running = []
    current_running = 0

    async def mock_scan_runner(scan_target_dir=None, **kwargs):
        nonlocal current_running
        current_running += 1
        concurrent_running.append(current_running)
        await asyncio.sleep(0.05)  # Simulate scan work
        current_running -= 1
        return {"summary": {"totalReported": 0}, "findings": []}

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", side_effect=mock_scan_runner):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                # Create dummy zip files
                z1 = tmp_path / "1.zip"
                z2 = tmp_path / "2.zip"
                z3 = tmp_path / "3.zip"
                z1.write_bytes(b"1")
                z2.write_bytes(b"2")
                z3.write_bytes(b"3")

                # Enqueue 3 jobs simultaneously
                await queue.enqueue("job-1", str(z1))
                await queue.enqueue("job-2", str(z2))
                await queue.enqueue("job-3", str(z3))

                # Wait for all jobs to complete
                for _ in range(100):
                    j1 = queue.get_job("job-1")
                    j2 = queue.get_job("job-2")
                    j3 = queue.get_job("job-3")
                    if (
                        j1 and j1.status in (JobStatus.DONE, JobStatus.FAILED)
                        and j2 and j2.status in (JobStatus.DONE, JobStatus.FAILED)
                        and j3 and j3.status in (JobStatus.DONE, JobStatus.FAILED)
                    ):
                        break
                    await asyncio.sleep(0.02)

    await queue.stop()

    assert len(concurrent_running) >= 3
    # Concurrency peak must never exceed 1
    assert max(concurrent_running) == 1
    assert queue.get_job("job-1").status == JobStatus.DONE
    assert queue.get_job("job-2").status == JobStatus.DONE
    assert queue.get_job("job-3").status == JobStatus.DONE


@pytest.mark.asyncio
async def test_queue_lifecycle_success(temp_zip):
    """Validates complete state machine transitions for a successful scan."""
    queue = ScanJobQueue()
    await queue.start()

    mock_report = {"summary": {"totalReported": 0}, "findings": []}

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value=mock_report)):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                job = await queue.enqueue("job-success", str(temp_zip))
                assert job.status == JobStatus.QUEUED
                assert job.progress == 0

                for _ in range(50):
                    updated = queue.get_job("job-success")
                    if updated and updated.status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.02)

                final_job = queue.get_job("job-success")
                assert final_job.status == JobStatus.DONE
                assert final_job.stage == JobStage.COMPLETED
                assert final_job.progress == 100
                assert final_job.report is not None
                assert final_job.error is None
                assert final_job.started_at is not None
                assert final_job.completed_at is not None

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_extraction_failure_sets_failed(temp_zip):
    """Extraction security violation (ValueError) transitions job to FAILED."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract", side_effect=ValueError("Zip-slip path traversal rejected")):
        await queue.enqueue("job-fail-extract", str(temp_zip))

        for _ in range(50):
            job = queue.get_job("job-fail-extract")
            if job and job.status == JobStatus.FAILED:
                break
            await asyncio.sleep(0.02)

        job = queue.get_job("job-fail-extract")
        assert job.status == JobStatus.FAILED
        assert job.stage == JobStage.FAILED
        assert "Zip-slip path traversal rejected" in job.error
        assert job.report is None

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_scanner_failure_sets_failed(temp_zip):
    """ScannerExecutionError transitions job to FAILED."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=ScannerExecutionError("Exit 3", exit_code=3))):
            await queue.enqueue("job-fail-scanner", str(temp_zip))

            for _ in range(50):
                job = queue.get_job("job-fail-scanner")
                if job and job.status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.02)

            job = queue.get_job("job-fail-scanner")
            assert job.status == JobStatus.FAILED
            assert job.stage == JobStage.FAILED
            assert "Exit 3" in job.error

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_scanner_timeout_sets_failed(temp_zip):
    """ScannerTimeoutError transitions job to FAILED."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=ScannerTimeoutError("Scan timed out", timeout_seconds=300))):
            await queue.enqueue("job-timeout", str(temp_zip))

            for _ in range(50):
                job = queue.get_job("job-timeout")
                if job and job.status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.02)

            job = queue.get_job("job-timeout")
            assert job.status == JobStatus.FAILED
            assert job.stage == JobStage.FAILED
            assert "timed out" in job.error.lower()

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_temp_dir_deleted_on_success_and_failure(temp_zip):
    """Scratch directories and zip files must be deleted in both success and failure states."""
    queue = ScanJobQueue()
    await queue.start()

    created_dirs = []

    def mock_safe_extract(src, dst):
        created_dirs.append(Path(dst))

    # 1. Test success cleanup
    with patch("app.core.queue.safe_extract", side_effect=mock_safe_extract):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value={"findings": []})):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                zip1 = temp_zip.parent / "test1.zip"
                zip1.write_bytes(b"content1")
                await queue.enqueue("clean-1", str(zip1))

                for _ in range(50):
                    if queue.get_job("clean-1").status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.02)

                assert len(created_dirs) == 1
                assert not created_dirs[0].exists(), "Temporary directory must be deleted after success"
                assert not zip1.exists(), "Uploaded zip file must be deleted after success"

    # 2. Test failure cleanup
    with patch("app.core.queue.safe_extract", side_effect=mock_safe_extract):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=RuntimeError("Unexpected crash"))):
            zip2 = temp_zip.parent / "test2.zip"
            zip2.write_bytes(b"content2")
            await queue.enqueue("clean-2", str(zip2))

            for _ in range(50):
                if queue.get_job("clean-2").status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.02)

            assert len(created_dirs) == 2
            assert not created_dirs[1].exists(), "Temporary directory must be deleted after failure"
            assert not zip2.exists(), "Uploaded zip file must be deleted after failure"

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_stats_and_health(tmp_path):
    """Health metrics must accurately report queue depth and active processing status."""
    queue = ScanJobQueue()
    stats_empty = queue.get_stats()
    assert stats_empty["queued_jobs"] == 0
    assert stats_empty["is_processing"] is False
    assert stats_empty["active_job_id"] is None

    # Enqueue a job without starting worker
    z = tmp_path / "unstarted.zip"
    z.write_bytes(b"test")
    await queue.enqueue("job-unstarted", str(z))

    stats_queued = queue.get_stats()
    assert stats_queued["queued_jobs"] == 1
    assert stats_queued["is_processing"] is False

    jobs = queue.list_jobs()
    assert len(jobs) == 1
    assert jobs[0].job_id == "job-unstarted"


@pytest.mark.asyncio
async def test_queue_passes_required_scanner_flags(temp_zip):
    """Validates that queue passes the complete set of required flags to runner (R1)."""
    queue = ScanJobQueue()
    await queue.start()

    mock_runner = AsyncMock(return_value={"summary": {"totalReported": 0}, "findings": []})

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", mock_runner):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                job = await queue.enqueue("job-flags-check", str(temp_zip))
                for _ in range(50):
                    if queue.get_job("job-flags-check").status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.02)

                assert mock_runner.called
                kwargs = mock_runner.call_args.kwargs
                assert "extra_args" in kwargs
                assert kwargs["extra_args"] == [
                    "--gate2",
                    "annotate",
                    "--no-color",
                    "--offline",
                    "--timeout",
                    "120000",
                ]

    await queue.stop()


@pytest.mark.asyncio
async def test_queue_scanner_timeout_dynamic_error_message(temp_zip):
    """ScannerTimeoutError reflects dynamic settings.SCAN_TIMEOUT_SECONDS in job error (R1)."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=ScannerTimeoutError("Scan timed out", timeout_seconds=600))):
            with patch("app.core.queue.settings") as mock_settings:
                mock_settings.SCAN_TIMEOUT_SECONDS = 600
                await queue.enqueue("job-timeout-dyn", str(temp_zip))

                for _ in range(50):
                    job = queue.get_job("job-timeout-dyn")
                    if job and job.status == JobStatus.FAILED:
                        break
                    await asyncio.sleep(0.02)

                job = queue.get_job("job-timeout-dyn")
                assert job.status == JobStatus.FAILED
                assert job.stage == JobStage.FAILED
                assert "exceeded 600 seconds limit" in job.error

    await queue.stop()
