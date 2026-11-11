"""
Empirical Challenge & Stress Test Suite for Milestone 1 (Backend & Scanner Reliability).
Challenger: Challenger M1_1 (Queue Flags & Timeout Challenger).

Validates:
1. Exact runner arguments: backend/app/core/queue.py passes ["--gate2", "annotate", "--no-color", "--offline", "--timeout", "120000"]
   to run_secureship_cli, with exact string types, exact ordering, and correct length.
2. Dynamic timeout error messages: When scanner execution times out, the error message dynamically includes
   the configured SCAN_TIMEOUT_SECONDS (e.g. 600s, 1200s, 45s) and falls back safely to 300s.
3. Edge cases:
   - Behavior when extra_args is None or [] in runner.py and queue.py.
   - Behavior when run_secureship_cli raises unexpected exceptions (MemoryError, KeyError, RuntimeError, OSError).
   - Queue worker loop survival (worker continues processing jobs after a fatal error).
   - Resource cleanup in all lifecycle states (success, timeout, scanner error, unhandled error).
   - Windows/POSIX read-only file handling during scratch directory removal.
   - Missing or deleted zip files during processing.
4. Concurrency invariants: strictly 1 job at a time under burst load, preserving FIFO order.
"""

from __future__ import annotations

import asyncio
import os
import stat
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.config import settings
from app.core.queue import ScanJobQueue
from app.core.runner import (
    DEFAULT_TIMEOUT_SECONDS,
    ScannerError,
    ScannerExecutionError,
    ScannerNotFoundError,
    ScannerTimeoutError,
    run_secureship_cli,
)
from app.models.job import JobRecord, JobStage, JobStatus


@pytest.fixture
def dummy_zip(tmp_path: Path) -> Path:
    """Creates a valid minimal zip file for queue job tests."""
    zip_path = tmp_path / "valid_test.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "print('hello securescan')\n")
    return zip_path


class TestQueueExactRunnerFlags:
    """Empirically tests that queue.py passes exact runner arguments to run_secureship_cli (R1)."""

    @pytest.mark.asyncio
    async def test_queue_passes_exact_flag_vector(self, dummy_zip: Path):
        """Verifies exact flags: ['--gate2', 'annotate', '--no-color', '--offline', '--timeout', '120000']."""
        queue = ScanJobQueue()
        await queue.start()

        mock_runner = AsyncMock(return_value={"summary": {"totalReported": 0}, "findings": []})

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", mock_runner):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    job = await queue.enqueue("test-flags-vector", str(dummy_zip))

                    for _ in range(50):
                        updated = queue.get_job("test-flags-vector")
                        if updated and updated.status == JobStatus.DONE:
                            break
                        await asyncio.sleep(0.02)

                    assert mock_runner.called, "run_secureship_cli was not invoked"
                    kwargs = mock_runner.call_args.kwargs
                    assert "extra_args" in kwargs, "'extra_args' not passed in runner kwargs"

                    extra_args = kwargs["extra_args"]
                    expected_flags = [
                        "--gate2",
                        "annotate",
                        "--no-color",
                        "--offline",
                        "--timeout",
                        "120000",
                    ]
                    assert extra_args == expected_flags, f"Mismatch in runner arguments: {extra_args} != {expected_flags}"
                    assert len(extra_args) == 6, f"Expected 6 args, got {len(extra_args)}"
                    # Verify each element is strictly a string (not int or other type)
                    for idx, item in enumerate(extra_args):
                        assert isinstance(item, str), f"Flag at index {idx} ({item}) must be str, got {type(item)}"

        await queue.stop()

    @pytest.mark.asyncio
    async def test_runner_constructs_subprocess_command_with_extra_args(self, tmp_path: Path):
        """Verifies that run_secureship_cli properly appends extra_args into create_subprocess_exec."""
        dummy_dir = tmp_path / "target_src"
        dummy_dir.mkdir()

        passed_cmd_args: list[str] = []

        async def mock_subprocess_exec(*args, **kwargs):
            nonlocal passed_cmd_args
            passed_cmd_args = list(args)
            proc_mock = MagicMock()
            proc_mock.communicate = AsyncMock(return_value=(b'{"summary": {"totalReported": 0}, "findings": []}', b""))
            proc_mock.returncode = 0
            return proc_mock

        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "cli/dist/index.js")):
            with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
                flags = ["--gate2", "annotate", "--no-color", "--offline", "--timeout", "120000"]
                res = await run_secureship_cli(dummy_dir, extra_args=flags)

                assert res == {"summary": {"totalReported": 0}, "findings": []}
                # Check that command args end with the extra flags
                assert passed_cmd_args[-6:] == flags
                # Ensure all arguments in subprocess exec are strings
                for arg in passed_cmd_args:
                    assert isinstance(arg, str), f"Subprocess command arg {arg} must be string"

    @pytest.mark.asyncio
    async def test_queue_handles_runner_signature_without_extra_args(self, dummy_zip: Path):
        """Verifies queue inspection omits extra_args if runner signature does not accept it."""
        queue = ScanJobQueue()
        await queue.start()

        # Legacy runner that only accepts (scan_target_dir, timeout_seconds=300)
        async def legacy_runner(scan_target_dir, timeout_seconds=300):
            return {"summary": {"totalReported": 0}, "findings": []}

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", side_effect=legacy_runner):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    job = await queue.enqueue("test-legacy-runner", str(dummy_zip))

                    for _ in range(50):
                        updated = queue.get_job("test-legacy-runner")
                        if updated and updated.status == JobStatus.DONE:
                            break
                        await asyncio.sleep(0.02)

                    updated = queue.get_job("test-legacy-runner")
                    assert updated.status == JobStatus.DONE
                    assert updated.error is None

        await queue.stop()


class TestScannerTimeoutDynamicErrorMessage:
    """Empirically tests that scanner timeouts produce dynamic error messages with configured limit."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("timeout_setting", [600, 1200, 45, 900])
    async def test_timeout_error_dynamically_includes_configured_seconds(self, dummy_zip: Path, timeout_setting: int):
        """Verifies that job.error dynamically matches getattr(settings, 'SCAN_TIMEOUT_SECONDS')."""
        queue = ScanJobQueue()
        await queue.start()

        with patch("app.core.queue.safe_extract"):
            with patch(
                "app.core.queue.run_secureship_cli",
                AsyncMock(side_effect=ScannerTimeoutError("Timeout", timeout_seconds=timeout_setting)),
            ):
                with patch("app.core.queue.settings") as mock_settings:
                    mock_settings.SCAN_TIMEOUT_SECONDS = timeout_setting
                    job_id = f"job-timeout-{timeout_setting}"
                    await queue.enqueue(job_id, str(dummy_zip))

                    for _ in range(50):
                        job = queue.get_job(job_id)
                        if job and job.status == JobStatus.FAILED:
                            break
                        await asyncio.sleep(0.02)

                    job = queue.get_job(job_id)
                    assert job.status == JobStatus.FAILED
                    assert job.stage == JobStage.FAILED
                    assert job.progress == 100
                    expected_error = f"Scan execution timed out (exceeded {timeout_setting} seconds limit)."
                    assert job.error == expected_error, f"Expected '{expected_error}', got '{job.error}'"

        await queue.stop()

    @pytest.mark.asyncio
    async def test_timeout_fallback_to_300_when_setting_missing(self, dummy_zip: Path):
        """Verifies graceful fallback to 300 seconds when SCAN_TIMEOUT_SECONDS is absent on settings."""
        queue = ScanJobQueue()
        await queue.start()

        class MinimalSettings:
            pass

        with patch("app.core.queue.safe_extract"):
            with patch(
                "app.core.queue.run_secureship_cli",
                AsyncMock(side_effect=ScannerTimeoutError("Timeout", timeout_seconds=300)),
            ):
                with patch("app.core.queue.settings", new=MinimalSettings()):
                    await queue.enqueue("job-timeout-fallback", str(dummy_zip))

                    for _ in range(50):
                        job = queue.get_job("job-timeout-fallback")
                        if job and job.status == JobStatus.FAILED:
                            break
                        await asyncio.sleep(0.02)

                    job = queue.get_job("job-timeout-fallback")
                    assert job.status == JobStatus.FAILED
                    assert "exceeded 300 seconds limit" in job.error

        await queue.stop()

    @pytest.mark.asyncio
    async def test_configured_timeout_passed_to_runner_kwargs(self, dummy_zip: Path):
        """Verifies queue passes timeout_seconds matching settings.SCAN_TIMEOUT_SECONDS to runner."""
        queue = ScanJobQueue()
        await queue.start()

        mock_runner = AsyncMock(return_value={"summary": {}, "findings": []})

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", mock_runner):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    with patch("app.core.queue.settings") as mock_settings:
                        mock_settings.SCAN_TIMEOUT_SECONDS = 750
                        await queue.enqueue("job-timeout-kwarg", str(dummy_zip))

                        for _ in range(50):
                            if queue.get_job("job-timeout-kwarg").status == JobStatus.DONE:
                                break
                            await asyncio.sleep(0.02)

                        assert mock_runner.called
                        assert mock_runner.call_args.kwargs.get("timeout_seconds") == 750

        await queue.stop()


class TestQueueEdgeCasesEmptyExtraArgs:
    """Empirically tests runner behavior with empty extra_args."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("empty_val", [None, []])
    async def test_runner_handles_none_or_empty_extra_args(self, tmp_path: Path, empty_val):
        """Verifies run_secureship_cli works cleanly when extra_args is None or []."""
        dummy_dir = tmp_path / "target_dir"
        dummy_dir.mkdir()

        passed_args: list[str] = []

        async def mock_exec(*args, **kwargs):
            nonlocal passed_args
            passed_args = list(args)
            p = MagicMock()
            p.communicate = AsyncMock(return_value=(b'{"summary": {}, "findings": []}', b""))
            p.returncode = 0
            return p

        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "cli.js")):
            with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
                res = await run_secureship_cli(dummy_dir, extra_args=empty_val)
                assert res == {"summary": {}, "findings": []}
                # When extra_args is empty, cmd_args ends with --json
                assert passed_args[-1] == "--json"


class TestQueueEdgeCasesUnexpectedExceptions:
    """Empirically tests unexpected exceptions and queue worker resilience."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "hostile_exc, expected_err_part",
        [
            (RuntimeError("Subprocess segmentation fault"), "Internal scanner failure: Subprocess segmentation fault"),
            (MemoryError("OOM reading large AST"), "Internal scanner failure: OOM reading large AST"),
            (KeyError("missing_summary_key"), "Internal scanner failure: 'missing_summary_key'"),
            (OSError("I/O device failed"), "Internal scanner failure: I/O device failed"),
            (ScannerNotFoundError("Node binary not found"), "Internal scanner failure: Node binary not found"),
            (ZeroDivisionError("division by zero"), "Internal scanner failure: division by zero"),
        ],
    )
    async def test_unexpected_exceptions_transition_job_to_failed(
        self, dummy_zip: Path, hostile_exc: Exception, expected_err_part: str
    ):
        """Verifies all unexpected exceptions set status=FAILED, stage=FAILED, progress=100, and format error."""
        queue = ScanJobQueue()
        await queue.start()

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=hostile_exc)):
                job_id = f"job-exc-{type(hostile_exc).__name__}"
                await queue.enqueue(job_id, str(dummy_zip))

                for _ in range(50):
                    job = queue.get_job(job_id)
                    if job and job.status == JobStatus.FAILED:
                        break
                    await asyncio.sleep(0.02)

                job = queue.get_job(job_id)
                assert job.status == JobStatus.FAILED
                assert job.stage == JobStage.FAILED
                assert job.progress == 100
                assert job.completed_at is not None
                assert expected_err_part in job.error

        await queue.stop()

    @pytest.mark.asyncio
    async def test_queue_worker_resilience_after_fatal_exception(self, dummy_zip: Path, tmp_path: Path):
        """Validates that a fatal exception in Job 1 does not kill worker loop; Job 2 processes successfully."""
        queue = ScanJobQueue()
        await queue.start()

        # Job 1 zip and Job 2 zip
        z1 = tmp_path / "j1.zip"
        z2 = tmp_path / "j2.zip"
        z1.write_bytes(b"PK01")
        z2.write_bytes(b"PK02")

        async def runner_dispatcher(target_dir, **kwargs):
            if "job-fatal" in str(target_dir):
                raise RuntimeError("Catastrophic engine crash!")
            return {"summary": {"totalReported": 0}, "findings": []}

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", side_effect=runner_dispatcher):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    # Enqueue both
                    await queue.enqueue("job-fatal", str(z1))
                    await queue.enqueue("job-subsequent", str(z2))

                    # Wait for job-subsequent to finish
                    for _ in range(100):
                        j2 = queue.get_job("job-subsequent")
                        if j2 and j2.status in (JobStatus.DONE, JobStatus.FAILED):
                            break
                        await asyncio.sleep(0.02)

                    j1 = queue.get_job("job-fatal")
                    j2 = queue.get_job("job-subsequent")

                    assert j1.status == JobStatus.FAILED
                    assert "Catastrophic engine crash!" in j1.error

                    # Job 2 MUST be DONE - worker survived!
                    assert j2.status == JobStatus.DONE
                    assert j2.progress == 100
                    assert j2.error is None

        await queue.stop()


class TestQueueResourceCleanup:
    """Empirically tests scratch directory and temporary zip file cleanup across all outcomes."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "outcome, runner_behavior",
        [
            ("success", AsyncMock(return_value={"summary": {}, "findings": []})),
            ("timeout", AsyncMock(side_effect=ScannerTimeoutError("Timeout", timeout_seconds=300))),
            ("scanner_error", AsyncMock(side_effect=ScannerExecutionError("Exit 2", exit_code=2))),
            ("unhandled_error", AsyncMock(side_effect=KeyError("Corrupted data"))),
        ],
    )
    async def test_scratch_dir_and_zip_deleted_in_all_lifecycle_outcomes(
        self, tmp_path: Path, outcome: str, runner_behavior
    ):
        """Scratch directory and uploaded zip file MUST be completely cleaned up on all outcomes."""
        queue = ScanJobQueue()
        await queue.start()

        created_scratch_dirs: list[Path] = []

        def capture_extract(src, dst):
            scratch_path = Path(dst)
            created_scratch_dirs.append(scratch_path)
            # Create a file inside scratch dir
            (scratch_path / "extracted.py").write_text("code = 123")

        job_zip = tmp_path / f"job_{outcome}.zip"
        job_zip.write_bytes(b"PK_test_data")

        with patch("app.core.queue.safe_extract", side_effect=capture_extract):
            with patch("app.core.queue.run_secureship_cli", runner_behavior):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    await queue.enqueue(f"clean-{outcome}", str(job_zip))

                    for _ in range(50):
                        job = queue.get_job(f"clean-{outcome}")
                        if job and job.status in (JobStatus.DONE, JobStatus.FAILED):
                            break
                        await asyncio.sleep(0.02)

                    assert len(created_scratch_dirs) == 1
                    scratch_dir = created_scratch_dirs[0]
                    # Verify scratch directory is deleted
                    assert not scratch_dir.exists(), f"Scratch dir {scratch_dir} was not deleted after {outcome}"
                    # Verify uploaded zip is deleted
                    assert not job_zip.exists(), f"Zip file {job_zip} was not deleted after {outcome}"

        await queue.stop()

    @pytest.mark.asyncio
    async def test_scratch_dir_cleanup_with_readonly_files(self, tmp_path: Path):
        """Verifies _handle_remove_readonly deletes read-only files inside scratch directory."""
        queue = ScanJobQueue()
        await queue.start()

        created_scratch: list[Path] = []

        def extract_with_readonly_files(src, dst):
            scratch = Path(dst)
            created_scratch.append(scratch)
            ro_file = scratch / "locked_file.txt"
            ro_file.write_text("read-only payload")
            # Mark file read-only
            os.chmod(ro_file, stat.S_IREAD)

        test_zip = tmp_path / "readonly_test.zip"
        test_zip.write_bytes(b"PK_ro")

        with patch("app.core.queue.safe_extract", side_effect=extract_with_readonly_files):
            with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value={"summary": {}, "findings": []})):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    await queue.enqueue("job-readonly-cleanup", str(test_zip))

                    for _ in range(50):
                        job = queue.get_job("job-readonly-cleanup")
                        if job and job.status == JobStatus.DONE:
                            break
                        await asyncio.sleep(0.02)

                    assert len(created_scratch) == 1
                    assert not created_scratch[0].exists(), "Scratch dir with read-only file was not removed"
                    assert not test_zip.exists(), "Uploaded zip file was not removed"

        await queue.stop()

    @pytest.mark.asyncio
    async def test_missing_zip_file_fails_cleanly(self):
        """Verifies job transitions to FAILED when zip file does not exist on disk."""
        queue = ScanJobQueue()
        await queue.start()

        await queue.enqueue("job-missing-zip", "C:/non/existent/path/missing.zip")

        for _ in range(50):
            job = queue.get_job("job-missing-zip")
            if job and job.status == JobStatus.FAILED:
                break
            await asyncio.sleep(0.02)

        job = queue.get_job("job-missing-zip")
        assert job.status == JobStatus.FAILED
        assert job.stage == JobStage.FAILED
        assert "Uploaded archive file not found" in job.error

        await queue.stop()

    @pytest.mark.asyncio
    async def test_zip_file_deleted_externally_mid_scan(self, tmp_path: Path):
        """Verifies queue cleanup tolerates zip file being unlinked externally during scan."""
        queue = ScanJobQueue()
        await queue.start()

        test_zip = tmp_path / "external_delete.zip"
        test_zip.write_bytes(b"PK_delete_me")

        async def runner_deletes_zip(target_dir, **kwargs):
            if test_zip.exists():
                test_zip.unlink()
            return {"summary": {}, "findings": []}

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", side_effect=runner_deletes_zip):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    await queue.enqueue("job-externally-deleted", str(test_zip))

                    for _ in range(50):
                        job = queue.get_job("job-externally-deleted")
                        if job and job.status == JobStatus.DONE:
                            break
                        await asyncio.sleep(0.02)

                    job = queue.get_job("job-externally-deleted")
                    assert job.status == JobStatus.DONE
                    assert not test_zip.exists()

        await queue.stop()


class TestQueueConcurrencyAndFIFOOrder:
    """Empirically tests concurrency=1 invariant and FIFO ordering under burst load."""

    @pytest.mark.asyncio
    async def test_burst_enqueue_strictly_one_job_at_a_time(self, tmp_path: Path):
        """Verifies that under burst load of 10 jobs, peak concurrency never exceeds 1."""
        queue = ScanJobQueue()
        await queue.start()

        concurrent_counter = 0
        peak_concurrency = 0

        async def slow_runner(target_dir, **kwargs):
            nonlocal concurrent_counter, peak_concurrency
            concurrent_counter += 1
            if concurrent_counter > peak_concurrency:
                peak_concurrency = concurrent_counter
            await asyncio.sleep(0.03)
            concurrent_counter -= 1
            return {"summary": {}, "findings": []}

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", side_effect=slow_runner):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    job_ids = [f"burst-job-{i}" for i in range(10)]
                    zip_files = []
                    for j_id in job_ids:
                        zf = tmp_path / f"{j_id}.zip"
                        zf.write_bytes(b"PK")
                        zip_files.append(zf)
                        await queue.enqueue(j_id, str(zf))

                    # Poll until all are done
                    for _ in range(200):
                        all_done = all(
                            queue.get_job(jid) and queue.get_job(jid).status == JobStatus.DONE
                            for jid in job_ids
                        )
                        if all_done:
                            break
                        await asyncio.sleep(0.02)

                    for jid in job_ids:
                        assert queue.get_job(jid).status == JobStatus.DONE

                    assert peak_concurrency == 1, f"Concurrency violation! Peak was {peak_concurrency} > 1"

        await queue.stop()

    @pytest.mark.asyncio
    async def test_fifo_execution_order_preserved(self, tmp_path: Path):
        """Verifies that jobs execute in strict First-In-First-Out order."""
        queue = ScanJobQueue()
        await queue.start()

        execution_order: list[str] = []

        async def logging_runner(target_dir, **kwargs):
            job_name = Path(target_dir).name
            execution_order.append(job_name)
            await asyncio.sleep(0.01)
            return {"summary": {}, "findings": []}

        with patch("app.core.queue.safe_extract"):
            with patch("app.core.queue.run_secureship_cli", side_effect=logging_runner):
                with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                    expected_order = [f"fifo-{i}" for i in range(5)]
                    for name in expected_order:
                        zf = tmp_path / f"{name}.zip"
                        zf.write_bytes(b"PK")
                        await queue.enqueue(name, str(zf))

                    for _ in range(100):
                        all_done = all(
                            queue.get_job(name) and queue.get_job(name).status == JobStatus.DONE
                            for name in expected_order
                        )
                        if all_done:
                            break
                        await asyncio.sleep(0.02)

                    # Execution order must contain each job prefix in sequential order
                    for idx, name in enumerate(expected_order):
                        assert any(name in executed for executed in execution_order[idx:idx+1]), (
                            f"FIFO violation at index {idx}: expected {name}, got {execution_order}"
                        )

        await queue.stop()
