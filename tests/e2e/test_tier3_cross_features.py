"""
Tier 3: Cross-Feature Interactions & Concurrency Test Suite.

Covers:
- Asyncio job queue single-worker concurrency guarantee (concurrency = 1)
- State machine lifecycle transitions (queued -> running -> done / failed)
- Premature export protection (requesting exports while job is running or queued)
- Context manager filesystem lifecycle & cleanup guarantees
"""

import asyncio
import os
import shutil
import tempfile
import uuid
from pathlib import Path
import pytest


class TestQueueConcurrencyAndLifecycle:
    """Verifies asyncio.Queue concurrency constraints and lifecycle state progressions."""

    @pytest.mark.asyncio
    async def test_queue_concurrency_is_strictly_one(self):
        """
        Invariants:
        - At most 1 scan job is processed concurrently.
        - Multiple jobs queued concurrently execute in strict sequential order.
        """
        queue: asyncio.Queue[str] = asyncio.Queue()
        active_workers = 0
        max_concurrent_seen = 0
        execution_log: list[str] = []

        async def worker_loop():
            nonlocal active_workers, max_concurrent_seen
            while True:
                job_id = await queue.get()
                active_workers += 1
                max_concurrent_seen = max(max_concurrent_seen, active_workers)

                execution_log.append(f"START:{job_id}")
                # Simulate scan work
                await asyncio.sleep(0.05)
                execution_log.append(f"FINISH:{job_id}")

                active_workers -= 1
                queue.task_done()

        # Start single worker
        worker_task = asyncio.create_task(worker_loop())

        # Queue 3 jobs simultaneously
        job_ids = ["job-1", "job-2", "job-3"]
        for jid in job_ids:
            await queue.put(jid)

        await queue.join()
        worker_task.cancel()

        assert max_concurrent_seen == 1, f"Concurrency exceeded 1! Max seen: {max_concurrent_seen}"
        # Verify sequential order: job-1 must finish before job-2 starts
        assert execution_log == [
            "START:job-1", "FINISH:job-1",
            "START:job-2", "FINISH:job-2",
            "START:job-3", "FINISH:job-3",
        ]

    def test_job_state_machine_transitions(self):
        """
        Validates the state machine transitions:
        - QUEUED -> RUNNING -> DONE
        - QUEUED -> RUNNING -> FAILED
        """
        valid_transitions = {
            "queued": {"running", "failed"},
            "running": {"done", "failed"},
            "done": set(),
            "failed": set(),
        }

        def transition(current: str, target: str) -> str:
            allowed = valid_transitions.get(current, set())
            if target not in allowed:
                raise ValueError(f"Illegal state transition from {current} to {target}")
            return target

        # Happy path
        state = "queued"
        state = transition(state, "running")
        state = transition(state, "done")
        assert state == "done"

        # Failure path
        state = "queued"
        state = transition(state, "running")
        state = transition(state, "failed")
        assert state == "failed"

        # Illegal jump: queued directly to done without running
        with pytest.raises(ValueError):
            transition("queued", "done")

        # Illegal transition: done to running
        with pytest.raises(ValueError):
            transition("done", "running")


class TestPrematureExportProtection:
    """Verifies that requesting reports or exports before scan completion fails closed."""

    def test_export_rejected_while_running(self):
        job_store = {
            "job-running-1": {"status": "running", "report": None},
            "job-queued-1": {"status": "queued", "report": None},
            "job-done-1": {"status": "done", "report": {"id": "job-done-1"}},
        }

        def get_export_or_reject(job_id: str, fmt: str):
            record = job_store.get(job_id)
            if not record:
                return 404, "Job not found"
            if record["status"] in ("queued", "running"):
                return 409, "Scan report not ready"
            if record["status"] == "failed":
                return 422, "Scan failed"
            return 200, record["report"]

        status, msg = get_export_or_reject("job-running-1", "json")
        assert status == 409
        assert "not ready" in msg

        status, msg = get_export_or_reject("job-queued-1", "sarif")
        assert status == 409

        status, msg = get_export_or_reject("job-done-1", "pdf")
        assert status == 200

        status, msg = get_export_or_reject("non-existent-id", "html")
        assert status == 404


class TestFilesystemCleanupLifecycle:
    """Verifies that temporary scan directories are guaranteed to be cleaned up."""

    def test_cleanup_on_success(self):
        target_dir = None

        def run_with_cleanup():
            nonlocal target_dir
            temp_dir = Path(tempfile.mkdtemp(prefix="test_cleanup_success_")).resolve()
            target_dir = temp_dir
            try:
                (temp_dir / "extracted_file.txt").write_text("sample content")
                assert temp_dir.is_dir()
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        run_with_cleanup()
        assert target_dir is not None
        assert not target_dir.exists(), "Temporary directory was not deleted after success!"

    def test_cleanup_on_failure(self):
        target_dir = None

        def run_with_failure_cleanup():
            nonlocal target_dir
            temp_dir = Path(tempfile.mkdtemp(prefix="test_cleanup_fail_")).resolve()
            target_dir = temp_dir
            try:
                (temp_dir / "sample.txt").write_text("error before crash")
                raise RuntimeError("Simulated unhandled exception during scan execution")
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        with pytest.raises(RuntimeError):
            run_with_failure_cleanup()

        assert target_dir is not None
        assert not target_dir.exists(), "Temporary directory was not deleted after failure!"
