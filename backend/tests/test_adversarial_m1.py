"""
Milestone 1 Adversarial & Stress Verification Suite.
Authored by: teamwork_challenger (challenger_m1_2)

Empirically tests:
1. Job queue concurrency invariant (concurrency = 1) under heavy burst load.
2. FIFO determinism of job processing.
3. Resource cleanup of temporary scratch directories and zip archives upon cancellation and failure.
4. Code context extractor boundary edge cases (0-line, 1-line, negative lines, huge line numbers,
   1MB line width, binary null bytes, Latin-1, Shift-JIS, path traversal, nonexistent/dir targets).
5. CWE extraction and OWASP mapping robustness against malformed, boundary, and unexpected inputs.
6. Empirical reproduction of adversarial bug findings (subprocess leak on cancel, None CWE crash).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, List
from unittest.mock import AsyncMock, patch

import pytest

from app.core.context_extractor import (
    enrich_findings_with_context,
    enrich_report_with_snippets,
    extract_code_snippet,
)
from app.core.queue import ScanJobQueue
from app.core.runner import run_secureship_cli
from app.models.job import JobRecord, JobStage, JobStatus
from app.models.report import (
    CodeSnippet,
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    OwaspCategory,
    ReachabilityVerdict,
    ScanReport,
    Severity,
    extract_cwe_ids,
    map_cwe_to_owasp,
    normalize_cwe_id,
    normalize_reachability_verdict,
)


# =============================================================================
# Helper: Create valid dummy zip archive
# =============================================================================

def _create_dummy_zip(dest_path: Path, filename: str = "main.py", content: str = "print('hello')\n") -> Path:
    with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return dest_path


# =============================================================================
# Suite 1: ScanJobQueue Concurrency & Lifecycle Stress Tests
# =============================================================================

class TestQueueConcurrencyStress:
    """Stress tests verifying single-concurrency invariant, FIFO ordering, and cleanup."""

    @pytest.mark.asyncio
    async def test_queue_burst_concurrency_never_exceeds_one(self, tmp_path: Path):
        """
        Burst-enqueue 15 jobs concurrently and assert that at NO point in time
        more than 1 job is in JobStatus.RUNNING.
        """
        queue = ScanJobQueue(maxsize=50)
        await queue.start()

        num_jobs = 15
        running_tracker: list[int] = []
        active_jobs: set[str] = set()
        completed_order: list[str] = []
        concurrency_violated = False

        async def mock_run_secureship_cli(scan_target_dir: Path, timeout_seconds: int = 300) -> dict[str, Any]:
            nonlocal concurrency_violated
            active_count = len(active_jobs)
            running_tracker.append(active_count)
            if active_count > 1:
                concurrency_violated = True
            await asyncio.sleep(0.02)  # Simulate CLI workload
            return {
                "id": "mock-report",
                "findings": [],
                "scanners": [],
                "summary": {"total_findings": 0},
            }

        with patch("app.core.queue.run_secureship_cli", side_effect=mock_run_secureship_cli):
            orig_process = queue._process_job

            async def instrumented_process(job_id: str):
                nonlocal concurrency_violated
                active_jobs.add(job_id)
                if len(active_jobs) > 1:
                    concurrency_violated = True
                try:
                    await orig_process(job_id)
                finally:
                    active_jobs.discard(job_id)
                    completed_order.append(job_id)

            queue._process_job = instrumented_process

            zip_paths: list[Path] = []
            for i in range(num_jobs):
                zp = _create_dummy_zip(tmp_path / f"job_{i}.zip")
                zip_paths.append(zp)

            async def enqueue_worker(idx: int):
                return await queue.enqueue(f"job_{idx:02d}", str(zip_paths[idx]))

            await asyncio.gather(*(enqueue_worker(i) for i in range(num_jobs)))

            while len(completed_order) < num_jobs:
                running_now = [j.job_id for j in queue.list_jobs() if j.status == JobStatus.RUNNING]
                assert len(running_now) <= 1, f"Concurrency violated! Active running: {running_now}"
                await asyncio.sleep(0.01)

            await queue.stop()

        assert not concurrency_violated, "Invariant violation: more than 1 job was running simultaneously!"
        assert len(completed_order) == num_jobs
        assert all(count <= 1 for count in running_tracker)

    @pytest.mark.asyncio
    async def test_queue_deterministic_fifo_execution(self, tmp_path: Path):
        """
        Verify that jobs are dispatched and processed in strict FIFO order.
        """
        queue = ScanJobQueue(maxsize=20)
        await queue.start()

        execution_order: list[str] = []

        async def mock_run_secureship_cli(scan_target_dir: Path, timeout_seconds: int = 300) -> dict[str, Any]:
            await asyncio.sleep(0.01)
            return {"id": "mock", "findings": [], "summary": {}}

        with patch("app.core.queue.run_secureship_cli", side_effect=mock_run_secureship_cli):
            orig_process = queue._process_job

            async def recording_process(job_id: str):
                execution_order.append(job_id)
                await orig_process(job_id)

            queue._process_job = recording_process

            expected_order = [f"fifo_{i:02d}" for i in range(10)]
            for jid in expected_order:
                zp = _create_dummy_zip(tmp_path / f"{jid}.zip")
                await queue.enqueue(jid, str(zp))

            while len(execution_order) < len(expected_order):
                await asyncio.sleep(0.02)

            await queue.stop()

        assert execution_order == expected_order, f"FIFO order broken! Expected: {expected_order}, Got: {execution_order}"

    @pytest.mark.asyncio
    async def test_queue_cleanup_when_worker_is_cancelled(self, tmp_path: Path):
        """
        Verify that scratch directories and uploaded archives are cleaned up
        even when the worker task is cancelled mid-execution.
        """
        queue = ScanJobQueue()
        await queue.start()

        started_event = asyncio.Event()
        captured_scratch_dir: list[Path] = []

        async def hang_forever(scan_target_dir: Path, timeout_seconds: int = 300):
            captured_scratch_dir.append(scan_target_dir)
            started_event.set()
            await asyncio.sleep(3600)

        with patch("app.core.queue.run_secureship_cli", side_effect=hang_forever):
            zp = _create_dummy_zip(tmp_path / "cancel_test.zip")
            await queue.enqueue("cancelled_job", str(zp))

            await asyncio.wait_for(started_event.wait(), timeout=5.0)

            assert len(captured_scratch_dir) == 1
            scratch = captured_scratch_dir[0]
            assert scratch.exists(), "Scratch directory should exist during execution"

            await queue.stop()

            assert not scratch.exists(), f"Scratch dir was leaked on worker cancellation: {scratch}"
            assert not zp.exists(), f"Uploaded zip was leaked on worker cancellation: {zp}"

    @pytest.mark.asyncio
    async def test_queue_cleanup_on_unexpected_exception(self, tmp_path: Path):
        """
        Verify that scratch directories and uploaded archives are cleaned up
        when an unhandled unexpected exception is raised during scan.
        """
        queue = ScanJobQueue()
        await queue.start()

        captured_scratch_dir: list[Path] = []

        async def crash_scanner(scan_target_dir: Path, timeout_seconds: int = 300):
            captured_scratch_dir.append(scan_target_dir)
            raise RuntimeError("Catastrophic unexpected hardware/process fault")

        with patch("app.core.queue.run_secureship_cli", side_effect=crash_scanner):
            zp = _create_dummy_zip(tmp_path / "crash_test.zip")
            await queue.enqueue("crashed_job", str(zp))

            for _ in range(50):
                job = queue.get_job("crashed_job")
                if job and job.status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.05)

            job = queue.get_job("crashed_job")
            assert job is not None
            assert job.status == JobStatus.FAILED
            assert "Catastrophic" in (job.error or "")

            assert len(captured_scratch_dir) == 1
            scratch = captured_scratch_dir[0]
            assert not scratch.exists(), f"Scratch dir leaked on unexpected exception: {scratch}"
            assert not zp.exists(), f"Uploaded zip leaked on unexpected exception: {zp}"

            await queue.stop()


# =============================================================================
# Suite 2: Context Extractor Boundary & Malformed Inputs Stress Tests
# =============================================================================

class TestContextExtractorBoundaryStress:
    """Stress tests verifying context extractor resilience against edge cases."""

    def test_extract_from_zero_byte_empty_file(self, tmp_path: Path):
        """0-line file must return None without raising exceptions."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("", encoding="utf-8")

        res = extract_code_snippet(tmp_path, "empty.py", start_line=1, end_line=1)
        assert res is None

        res_oob = extract_code_snippet(tmp_path, "empty.py", start_line=10, end_line=20)
        assert res_oob is None

    def test_extract_from_single_line_file(self, tmp_path: Path):
        """1-line file without trailing newline must slice cleanly and clamp safely."""
        single_file = tmp_path / "single.py"
        single_file.write_text("x = 42", encoding="utf-8")

        res = extract_code_snippet(tmp_path, "single.py", start_line=1, end_line=1, context_lines=5)
        assert res is not None
        assert res.start_line == 1
        assert res.end_line == 1
        assert res.target_start == 1
        assert res.target_end == 1
        assert len(res.lines) == 1
        assert res.lines[0].content == "x = 42"
        assert res.lines[0].is_target is True

        res_oob = extract_code_snippet(tmp_path, "single.py", start_line=50, end_line=100)
        assert res_oob is not None
        assert res_oob.start_line == 1
        assert res_oob.end_line == 1
        assert res_oob.target_start == 1
        assert res_oob.target_end == 1

    def test_extract_with_negative_line_numbers(self, tmp_path: Path):
        """Negative and zero line numbers must clamp to line 1 without crashing."""
        sample = tmp_path / "sample.py"
        sample.write_text("\n".join(f"line_{i}" for i in range(1, 11)), encoding="utf-8")

        res = extract_code_snippet(tmp_path, "sample.py", start_line=-10, end_line=-1)
        assert res is not None
        assert res.target_start == 1
        assert res.target_end == 1
        assert res.start_line == 1
        assert all(l.line_number > 0 for l in res.lines)

        res_zero = extract_code_snippet(tmp_path, "sample.py", start_line=0, end_line=0)
        assert res_zero is not None
        assert res_zero.target_start == 1
        assert res_zero.target_end == 1

    def test_extract_with_inverted_line_numbers(self, tmp_path: Path):
        """start_line > end_line (e.g., start=8, end=3) must clamp safely."""
        sample = tmp_path / "sample.py"
        sample.write_text("\n".join(f"line_{i}" for i in range(1, 11)), encoding="utf-8")

        res = extract_code_snippet(tmp_path, "sample.py", start_line=8, end_line=3)
        assert res is not None
        assert res.target_start <= res.target_end
        assert res.start_line <= res.end_line

    def test_extract_with_huge_out_of_bounds_lines(self, tmp_path: Path):
        """Line numbers far exceeding file length (999,999) clamp to total_lines."""
        sample = tmp_path / "sample.py"
        sample.write_text("\n".join(f"line_{i}" for i in range(1, 11)), encoding="utf-8")

        res = extract_code_snippet(tmp_path, "sample.py", start_line=999999, end_line=1000005, context_lines=5)
        assert res is not None
        assert res.target_start == 10
        assert res.target_end == 10
        assert res.end_line == 10
        assert res.start_line == 5
        assert len(res.lines) == 6

    def test_extract_huge_horizontal_line_length(self, tmp_path: Path):
        """File with a single minified line of 1 MB slices without memory exhaustion or crash."""
        sample = tmp_path / "minified.js"
        huge_str = "var a = 'test';" * 70000
        sample.write_text(huge_str, encoding="utf-8")

        res = extract_code_snippet(tmp_path, "minified.js", start_line=1, end_line=1)
        assert res is not None
        assert len(res.lines) == 1
        assert len(res.lines[0].content) == len(huge_str)

    def test_binary_null_byte_rejection_at_boundaries(self, tmp_path: Path):
        """Binary files containing null bytes at various offsets are rejected."""
        bin0 = tmp_path / "null0.bin"
        bin0.write_bytes(b"\x00" + b"A" * 100)
        assert extract_code_snippet(tmp_path, "null0.bin", 1, 1) is None

        bin1k = tmp_path / "null1k.bin"
        bin1k.write_bytes(b"A" * 1024 + b"\x00" + b"B" * 100)
        assert extract_code_snippet(tmp_path, "null1k.bin", 1, 1) is None

        bin4k = tmp_path / "null4k.bin"
        bin4k.write_bytes(b"A" * 4095 + b"\x00" + b"B" * 100)
        assert extract_code_snippet(tmp_path, "null4k.bin", 1, 1) is None

    def test_encoding_fallback_latin1_and_shiftjis(self, tmp_path: Path):
        """Non-UTF8 files (Latin-1 and Shift-JIS) must not crash."""
        latin1_file = tmp_path / "latin1.py"
        latin1_bytes = b"# -*- coding: latin-1 -*-\nname = 'M\xfcnchen'\ncity = 'S\xe3o Paulo'\n"
        latin1_file.write_bytes(latin1_bytes)

        res_latin1 = extract_code_snippet(tmp_path, "latin1.py", start_line=2, end_line=3)
        assert res_latin1 is not None
        assert "München" in res_latin1.raw_content or "M" in res_latin1.raw_content

        sjis_file = tmp_path / "sjis.py"
        sjis_bytes = b"# Shift-JIS comment\nx = '\x93\xfa\x96{\x8c\xea'\n"
        sjis_file.write_bytes(sjis_bytes)

        res_sjis = extract_code_snippet(tmp_path, "sjis.py", start_line=2, end_line=2)
        assert res_sjis is not None
        assert len(res_sjis.lines) > 0

    def test_path_traversal_and_escapes_rejected(self, tmp_path: Path):
        """Directory traversal and absolute path inputs return None safely."""
        sub = tmp_path / "subdir"
        sub.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("classified", encoding="utf-8")

        assert extract_code_snippet(sub, "../secret.txt", 1, 1) is None
        assert extract_code_snippet(sub, "../../secret.txt", 1, 1) is None
        assert extract_code_snippet(sub, "/etc/passwd", 1, 1) is None
        assert extract_code_snippet(sub, "C:\\Windows\\win.ini", 1, 1) is None
        assert extract_code_snippet(sub, "", 1, 1) is None

    def test_nonexistent_and_directory_targets(self, tmp_path: Path):
        """Nonexistent paths or directory paths return None safely."""
        assert extract_code_snippet(tmp_path, "ghost.py", 1, 1) is None

        dir_path = tmp_path / "is_a_dir"
        dir_path.mkdir()
        assert extract_code_snippet(tmp_path, "is_a_dir", 1, 1) is None


# =============================================================================
# Suite 3: CWE Normalization & OWASP Top 10 Model Stress Tests
# =============================================================================

class TestModelAndOwaspStress:
    """Stress tests verifying CWE extraction and OWASP mapping robustness."""

    def test_extract_cwe_ids_all_variations_and_mangled_tokens(self):
        """Comprehensive verification of extract_cwe_ids on malformed and mangled tokens."""
        assert extract_cwe_ids(None) == []
        assert extract_cwe_ids("") == []
        assert extract_cwe_ids([]) == []
        assert extract_cwe_ids(0) == []
        assert extract_cwe_ids([None, "", "   "]) == []

        assert extract_cwe_ids("CWE-79") == ["CWE-79"]
        assert extract_cwe_ids("cwe-79") == ["CWE-79"]
        assert extract_cwe_ids("CWE_89") == ["CWE-89"]
        assert extract_cwe_ids("CWE:22") == ["CWE-22"]
        assert extract_cwe_ids("cwe 352") == ["CWE-352"]

        assert extract_cwe_ids(["079", 89, "0022"]) == ["CWE-22", "CWE-79", "CWE-89"]

        mixed_str = "Reported issues: CWE-79 (XSS) and cwe:89 (SQLi) along with rule CWE_22"
        assert extract_cwe_ids(mixed_str) == ["CWE-22", "CWE-79", "CWE-89"]

        assert extract_cwe_ids(["CWE-INVALID", "CWE-", "cwe", "random_string"]) == []
        assert extract_cwe_ids([True, False, 123.456]) == []

    def test_map_cwe_to_owasp_across_all_ten_categories(self):
        """Verify authoritative mapping for representative CWEs in every OWASP 2021 category."""
        category_checks = [
            ("CWE-22", OwaspCategory.A01_2021.value),
            ("CWE-284", OwaspCategory.A01_2021.value),
            ("CWE-352", OwaspCategory.A01_2021.value),
            ("CWE-311", OwaspCategory.A02_2021.value),
            ("CWE-327", OwaspCategory.A02_2021.value),
            ("CWE-330", OwaspCategory.A02_2021.value),
            ("CWE-78", OwaspCategory.A03_2021.value),
            ("CWE-79", OwaspCategory.A03_2021.value),
            ("CWE-89", OwaspCategory.A03_2021.value),
            ("CWE-209", OwaspCategory.A04_2021.value),
            ("CWE-256", OwaspCategory.A04_2021.value),
            ("CWE-16", OwaspCategory.A05_2021.value),
            ("CWE-611", OwaspCategory.A05_2021.value),
            ("CWE-937", OwaspCategory.A06_2021.value),
            ("CWE-1104", OwaspCategory.A06_2021.value),
            ("CWE-287", OwaspCategory.A07_2021.value),
            ("CWE-798", OwaspCategory.A07_2021.value),
            ("CWE-502", OwaspCategory.A08_2021.value),
            ("CWE-494", OwaspCategory.A08_2021.value),
            ("CWE-117", OwaspCategory.A09_2021.value),
            ("CWE-778", OwaspCategory.A09_2021.value),
            ("CWE-918", OwaspCategory.A10_2021.value),
        ]

        for cwe, expected_owasp in category_checks:
            actual = map_cwe_to_owasp(cwe_ids=[cwe])
            assert actual == expected_owasp, f"Mismatch for {cwe}: expected {expected_owasp}, got {actual}"

    def test_map_cwe_to_owasp_heuristics_and_fallbacks(self):
        """Verify Tier 2 (regex heuristics) and Tier 3 (category fallback)."""
        assert map_cwe_to_owasp([], rule_id="python-sqli-inject") == OwaspCategory.A03_2021.value
        assert map_cwe_to_owasp([], rule_id="hardcoded-jwt-secret") == OwaspCategory.A07_2021.value
        assert map_cwe_to_owasp([], description="pickle deserialization flaw") == OwaspCategory.A08_2021.value
        assert map_cwe_to_owasp([], description="weak md5 cipher detected") == OwaspCategory.A02_2021.value
        assert map_cwe_to_owasp([], rule_id="ssrf-fetch-target") == OwaspCategory.A10_2021.value
        assert map_cwe_to_owasp([], rule_id="log-forging-issue") == OwaspCategory.A09_2021.value

        assert map_cwe_to_owasp([], category=FindingCategory.SECRET) == OwaspCategory.A07_2021.value
        assert map_cwe_to_owasp([], category=FindingCategory.SCA) == OwaspCategory.A06_2021.value
        assert map_cwe_to_owasp([], category=FindingCategory.IAC) == OwaspCategory.A05_2021.value

        assert map_cwe_to_owasp([]) == OwaspCategory.UNKNOWN.value
        assert map_cwe_to_owasp(["CWE-99999"], category="UNKNOWN", rule_id="custom", description="custom") == OwaspCategory.UNKNOWN.value

    def test_enrich_report_with_snippets_empty_and_malformed(self, tmp_path: Path):
        """enrich_report_with_snippets handles empty and malformed dictionary payloads without crashing."""
        assert enrich_report_with_snippets({}, tmp_path) == {}

        malformed_report = {
            "findings": [
                None,
                "string-finding",
                {"location": None, "cweIds": None, "ruleId": None},
                {
                    "location": {"filePath": "missing.py", "startLine": 1, "endLine": 1},
                    "cweIds": ["CWE-89"],
                    "ruleId": "sql-injection",
                },
            ]
        }
        enriched = enrich_report_with_snippets(malformed_report, tmp_path)
        assert len(enriched["findings"]) == 4
        valid_finding = enriched["findings"][3]
        assert valid_finding["owaspCategory"] == OwaspCategory.A03_2021.value
        assert valid_finding["cweIds"] == ["CWE-89"]

    # =========================================================================
    # Adversarial Bug Verifications (Previously Failing Edge Cases Now Fixed)
    # =========================================================================

    def test_finding_map_cwe_to_owasp_missing_none_cwe_ids(self):
        """
        Adversarial Test: map_cwe_to_owasp must handle missing CWE IDs (cwe_ids=None) gracefully
        without raising unhandled TypeError.
        """
        result = map_cwe_to_owasp(cwe_ids=None)
        assert result == OwaspCategory.UNKNOWN.value

    @pytest.mark.asyncio
    async def test_finding_runner_kills_child_on_cancellation(self, tmp_path: Path):
        """
        Adversarial Test: Child process must be killed when run_secureship_cli task is cancelled.
        """
        target = tmp_path / "target"
        target.mkdir()
        script = tmp_path / "slow.py"
        script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")

        captured_proc = []
        orig_create = asyncio.create_subprocess_exec

        async def wrap_create(*args, **kwargs):
            proc = await orig_create(*args, **kwargs)
            captured_proc.append(proc)
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=wrap_create):
            task = asyncio.create_task(
                run_secureship_cli(
                    scan_target_dir=target,
                    timeout_seconds=300,
                    node_path=sys.executable,
                    cli_path=str(script),
                )
            )
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            assert len(captured_proc) == 1
            proc = captured_proc[0]
            try:
                assert proc.returncode is not None, "Child process was orphaned/leaked after cancellation!"
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
