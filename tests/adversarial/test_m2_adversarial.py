"""
SecureScan Milestone 2 Adversarial Stress & Penetration Test Suite (Adversarial Track).
Authored by: Challenger M2-1 (Adversarial Critic)

Empirically challenges and stress-tests:
1. Malformed upload payloads: empty files, non-zip extensions, corrupt headers, missing PK signatures.
2. Boundary size testing: exact 50MB boundary (accepted) vs 50MB + 1 byte (rejected with 413) and temp file cleanup.
3. Job polling stress: nonexistent UUIDs, directory traversal in IDs, XSS/SQLi injection in path params, rapid concurrent polling.
4. Report retrieval state machine matrix: 404 for missing, 409 for queued/running, 422 for failed, 400 for bad format, case-insensitivity.
5. Rate limiting stress: SlowAPI 10 uploads/hour/IP quota enforcement (429 on 11th request) and client IP isolation.
6. Queue concurrency stress: concurrency=1 invariant under burst load, FIFO determinism, dynamic queue depth tracking.
7. Health endpoint dual-path parity and scanner readiness.
"""

from __future__ import annotations

import asyncio
import io
import os
import sys
import tempfile
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
backend_path = Path(__file__).resolve().parents[2] / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.main import app
from app.config import settings
from app.core.queue import ScanJobQueue, get_job_queue
from app.models.job import JobRecord, JobStage, JobStatus
from app.routers.upload import limiter, MAX_UPLOAD_BYTES


# =========================================================================
# Fixtures & Helpers
# =========================================================================

@pytest.fixture(autouse=True)
def reset_rate_limiter_and_queue():
    """Ensure clean rate limiter storage and queue state for each test."""
    limiter.reset()
    queue = get_job_queue()
    queue.reset()
    yield
    limiter.reset()
    queue.reset()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, client=("127.0.0.1", 50000))


def make_valid_zip_bytes(filename: str = "sample.py", content: str = "print('hello')") -> bytes:
    """Generates an in-memory valid zip archive containing one file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


# =========================================================================
# 1. Malformed Upload Payloads Stress Tests
# =========================================================================

class TestUploadMalformedPayloadsAdversarial:
    """Stress tests upload validation against corrupt, forged, and malformed files."""

    def test_upload_zero_byte_empty_file(self, client: TestClient):
        """0-byte file named .zip must be rejected with HTTP 400."""
        response = client.post(
            "/api/scan",
            files={"file": ("empty.zip", b"", "application/zip")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    @pytest.mark.parametrize(
        "bad_filename,mime_type",
        [
            ("payload.tar", "application/x-tar"),
            ("payload.tar.gz", "application/gzip"),
            ("payload.tgz", "application/gzip"),
            ("malware.exe", "application/x-msdownload"),
            ("script.sh", "application/x-sh"),
            ("exploit.php", "application/x-php"),
            ("index.js", "application/javascript"),
            ("app.py", "text/x-python"),
            ("archive.zip.exe", "application/x-msdownload"),
            ("archive.zip.bak", "application/octet-stream"),
            ("no_extension", "application/octet-stream"),
            (".zip.tar", "application/x-tar"),
        ],
    )
    def test_upload_forbidden_extensions_matrix(self, client: TestClient, bad_filename: str, mime_type: str):
        """Any file extension other than .zip must be rejected with HTTP 400."""
        valid_zip = make_valid_zip_bytes()
        response = client.post(
            "/api/scan",
            files={"file": (bad_filename, valid_zip, mime_type)},
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert "Only .zip archives are supported" in detail

    @pytest.mark.parametrize(
        "header_name,header_bytes",
        [
            ("null_bytes", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("windows_pe", b"MZ\x90\x00\x03\x00\x00\x00"),
            ("linux_elf", b"\x7fELF\x02\x01\x01\x00"),
            ("gif_image", b"GIF89a\x01\x00\x01\x00"),
            ("html_doc", b"<!DOCTYPE html><html><body>"),
            ("gzip_stream", b"\x1f\x8b\x08\x00\x00\x00\x00\x00"),
            ("seven_zip", b"7z\xbc\xaf\x27\x1c\x00\x04"),
            ("rar_archive", b"Rar!\x1a\x07\x00\x00\x00\x00"),
            ("plain_text", b"This is just ASCII text pretending to be a zip archive."),
        ],
    )
    def test_upload_spoofed_magic_bytes_rejected(self, client: TestClient, header_name: str, header_bytes: bytes):
        """Files claiming to be .zip but without PK magic bytes must be rejected with HTTP 400."""
        payload = header_bytes + b"\x00" * 512
        response = client.post(
            "/api/scan",
            files={"file": (f"{header_name}.zip", payload, "application/zip")},
        )
        assert response.status_code == 400
        assert "missing PK magic header" in response.json()["detail"]

    def test_upload_uppercase_and_mixed_case_zip_extension(self, client: TestClient):
        """Upper and mixed case extensions (.ZIP, .Zip) must be accepted."""
        valid_zip = make_valid_zip_bytes()
        r1 = client.post(
            "/api/scan",
            files={"file": ("project.ZIP", valid_zip, "application/zip")},
        )
        assert r1.status_code == 200
        assert "job_id" in r1.json()

        r2 = client.post(
            "/api/scan",
            files={"file": ("module.Zip", valid_zip, "application/zip")},
        )
        assert r2.status_code == 200

    def test_upload_unicode_filename_handled_cleanly(self, client: TestClient):
        """Non-ASCII and Unicode zip filenames must not crash upload handling."""
        valid_zip = make_valid_zip_bytes()
        response = client.post(
            "/api/scan",
            files={"file": ("安全測試_測試專案.zip", valid_zip, "application/zip")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data

    @pytest.mark.asyncio
    async def test_upload_corrupt_zip_body_fails_at_worker_stage(self):
        """
        An archive that starts with valid PK header but has corrupt body
        is accepted into the queue, but the worker marks the job FAILED.
        """
        from httpx import ASGITransport, AsyncClient

        queue = get_job_queue()
        await queue.stop()
        queue.reset()
        await queue.start()
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                corrupt_zip = b"PK\x03\x04" + os.urandom(256)
                response = await ac.post(
                    "/api/scan",
                    files={"file": ("corrupt_body.zip", corrupt_zip, "application/zip")},
                )
                assert response.status_code == 200
                job_id = response.json()["job_id"]

                # Wait for background worker to process job
                for _ in range(40):
                    job = queue.get_job(job_id)
                    if job and job.status == JobStatus.FAILED:
                        break
                    await asyncio.sleep(0.05)

                job = queue.get_job(job_id)
                assert job is not None
                assert job.status == JobStatus.FAILED
                assert "Archive extraction rejected" in str(job.error)

                # Polling report must return 422 Unprocessable Entity
                res_report = await ac.get(f"/api/reports/{job_id}")
                assert res_report.status_code == 422
                assert "Scan failed" in res_report.json()["detail"]
        finally:
            await queue.stop()


# =========================================================================
# 2. Boundary Size Testing (50MB Boundary)
# =========================================================================

class TestBoundarySizeAdversarial:
    """Stress tests upload size ceiling at exact 50MB and 50MB + 1 byte."""

    @pytest.fixture(autouse=True)
    def calibrate_upload_limit(self, request, monkeypatch):
        """Monkeypatch upload limit to 50MB for fast execution without allocating 600MB."""
        if request.node.name == "test_production_upload_limit_configuration":
            return
        test_limit = 50 * 1024 * 1024
        import sys
        import app.routers.upload as upload_mod
        monkeypatch.setattr(upload_mod, "MAX_UPLOAD_BYTES", test_limit)
        current_mod = sys.modules[self.__module__]
        monkeypatch.setattr(current_mod, "MAX_UPLOAD_BYTES", test_limit)
        return test_limit

    def test_production_upload_limit_configuration(self):
        """Assert production upload limit is configured to 600MB."""
        import app.routers.upload as upload_mod
        assert upload_mod.MAX_UPLOAD_BYTES == 600 * 1024 * 1024
        assert settings.MAX_UPLOAD_SIZE_BYTES == 600 * 1024 * 1024

    def test_upload_exact_50mb_boundary_accepted(self, client: TestClient):
        """Exact 50 MB (52,428,800 bytes) payload must not be rejected with HTTP 413."""
        exact_50mb = b"PK\x03\x04" + b"\x00" * (MAX_UPLOAD_BYTES - 4)
        assert len(exact_50mb) == MAX_UPLOAD_BYTES

        response = client.post(
            "/api/scan",
            files={"file": ("exact_50mb.zip", exact_50mb, "application/zip")},
        )
        assert response.status_code == 200
        jid = response.json().get("job_id")
        assert jid is not None
        job = client.app.state.limiter and get_job_queue().get_job(jid)
        if job and job.zip_path and Path(job.zip_path).exists():
            Path(job.zip_path).unlink(missing_ok=True)

    def test_upload_50mb_plus_1_byte_rejected_with_413(self, client: TestClient):
        """50 MB + 1 byte (52,428,801 bytes) payload must be rejected with HTTP 413."""
        too_large = b"PK\x03\x04" + b"\x00" * (MAX_UPLOAD_BYTES - 4 + 1)
        assert len(too_large) == MAX_UPLOAD_BYTES + 1

        response = client.post(
            "/api/scan",
            files={"file": ("too_large.zip", too_large, "application/zip")},
        )
        assert response.status_code == 413
        assert "exceeds 50 MB limit" in response.json()["detail"]

    def test_upload_streaming_cleanup_on_413(self, client: TestClient):
        """When 413 is triggered mid-stream, the partial temporary file must be unlinked."""
        payload = b"PK\x03\x04" + b"\x00" * (51 * 1024 * 1024 - 4)
        temp_dir = Path(tempfile.gettempdir())
        before_files = set(temp_dir.glob("upload_*_*.zip"))

        response = client.post(
            "/api/scan",
            files={"file": ("stream_overflow.zip", payload, "application/zip")},
        )
        assert response.status_code == 413

        after_files = set(temp_dir.glob("upload_*_*.zip"))
        new_lingering_files = after_files - before_files
        assert len(new_lingering_files) == 0, f"Lingering upload files found: {new_lingering_files}"


# =========================================================================
# 3. Job Polling Stress Tests
# =========================================================================

class TestJobPollingStressAdversarial:
    """Stress tests job status polling against hostile inputs and concurrency."""

    def test_poll_nonexistent_job_returns_404(self, client: TestClient):
        """Querying a non-existent UUID must return HTTP 404."""
        random_uuid = str(uuid.uuid4())
        response = client.get(f"/api/jobs/{random_uuid}")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.parametrize(
        "hostile_id",
        [
            "00000000-0000-0000-0000-000000000000",
            "../../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "<script>alert('xss')</script>",
            "'; DROP TABLE jobs; --",
            "' OR '1'='1",
            "null",
            "undefined",
            "None",
            "a" * 1000,
        ],
    )
    def test_poll_hostile_job_ids_return_404_cleanly(self, client: TestClient, hostile_id: str):
        """Hostile path traversal, SQLi, and XSS identifiers in job_id must fail closed with 404."""
        response = client.get(f"/api/jobs/{hostile_id}")
        assert response.status_code in (404, 400)
        assert "<script>" not in response.text

    def test_poll_rapid_concurrent_polling_on_done_job(self, client: TestClient):
        """50 concurrent status polls on a seeded done job must all return 200 without race condition."""
        queue = get_job_queue()
        job_id = f"stress-done-{uuid.uuid4()}"
        queue._jobs[job_id] = JobRecord(
            job_id=job_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            poll_url=f"/api/jobs/{job_id}",
            report_url=f"/api/reports/{job_id}",
            completed_at="2026-11-07T12:00:00Z",
        )

        def poll_once():
            res = client.get(f"/api/jobs/{job_id}")
            return res.status_code, res.json()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(poll_once) for _ in range(50)]
            results = [f.result() for f in futures]

        for status_code, data in results:
            assert status_code == 200
            assert data["job_id"] == job_id
            assert data["status"] == "done"
            assert data["progress"] == 100

    def test_poll_rapid_concurrent_polling_on_missing_job(self, client: TestClient):
        """50 concurrent polls on a missing job must all return 404 cleanly."""
        missing_id = f"missing-{uuid.uuid4()}"

        def poll_once():
            return client.get(f"/api/jobs/{missing_id}").status_code

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(poll_once) for _ in range(50)]
            results = [f.result() for f in futures]

        assert all(code == 404 for code in results)


# =========================================================================
# 4. Report Retrieval Edge Cases & State Machine Matrix
# =========================================================================

class TestReportRetrievalEdgeCasesAdversarial:
    """Stress tests report retrieval and exports against job states and format params."""

    def test_report_queued_returns_409(self, client: TestClient):
        """Retrieving report for queued job returns HTTP 409 Conflict."""
        queue = get_job_queue()
        jid = f"queued-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.QUEUED,
            stage=JobStage.QUEUED,
            progress=0,
            poll_url=f"/api/jobs/{jid}",
        )

        res = client.get(f"/api/reports/{jid}")
        assert res.status_code == 409
        assert "not ready" in res.json()["detail"].lower()

        for fmt in ["json", "sarif", "html", "pdf"]:
            res_exp = client.get(f"/api/reports/{jid}/export?format={fmt}")
            assert res_exp.status_code == 409
            assert "not ready" in res_exp.json()["detail"].lower()

    def test_report_running_returns_409(self, client: TestClient):
        """Retrieving report for in-flight running job returns HTTP 409 Conflict."""
        queue = get_job_queue()
        jid = f"running-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.RUNNING,
            stage=JobStage.SCANNING,
            progress=65,
            poll_url=f"/api/jobs/{jid}",
        )

        res = client.get(f"/api/reports/{jid}")
        assert res.status_code == 409
        assert "not ready" in res.json()["detail"].lower()

        res_exp = client.get(f"/api/reports/{jid}/export?format=sarif")
        assert res_exp.status_code == 409

    def test_report_failed_returns_422(self, client: TestClient):
        """Retrieving report for failed job returns HTTP 422 Unprocessable Entity."""
        queue = get_job_queue()
        jid = f"failed-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.FAILED,
            stage=JobStage.FAILED,
            progress=100,
            error="Zip-slip path traversal attempt detected: '../../evil.sh'",
            poll_url=f"/api/jobs/{jid}",
        )

        res = client.get(f"/api/reports/{jid}")
        assert res.status_code == 422
        assert "Scan failed" in res.json()["detail"]
        assert "Zip-slip" in res.json()["detail"]

        for fmt in ["json", "sarif", "html", "pdf"]:
            res_exp = client.get(f"/api/reports/{jid}/export?format={fmt}")
            assert res_exp.status_code == 422
            assert "Scan failed" in res_exp.json()["detail"]

    def test_report_missing_job_returns_404(self, client: TestClient):
        """Retrieving report for unknown job returns HTTP 404."""
        jid = f"unknown-{uuid.uuid4()}"
        res = client.get(f"/api/reports/{jid}")
        assert res.status_code == 404

        res_exp = client.get(f"/api/reports/{jid}/export?format=json")
        assert res_exp.status_code == 404

    @pytest.mark.parametrize(
        "bad_fmt",
        ["docx", "xlsx", "csv", "xml", "yaml", "tar", "exe", "../../etc/passwd", "select*from"],
    )
    def test_export_unsupported_formats_rejected_with_400(self, client: TestClient, bad_fmt: str):
        """Export with non-supported format returns HTTP 400 Bad Request."""
        queue = get_job_queue()
        jid = f"done-fmt-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report={"findings": [], "scanners": [], "summary": {"total_findings": 0}},
        )

        res = client.get(f"/api/reports/{jid}/export?format={bad_fmt}")
        assert res.status_code == 400
        assert "Unsupported export format" in res.json()["detail"]

    def test_export_empty_format_defaults_to_json(self, client: TestClient):
        """Empty format query parameter defaults gracefully to JSON format."""
        queue = get_job_queue()
        jid = f"done-emptyfmt-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report={"id": jid, "findings": [], "scanners": [], "summary": {"total_findings": 0}},
        )

        res = client.get(f"/api/reports/{jid}/export?format=")
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]

    @pytest.mark.parametrize(
        "fmt_param,expected_mime,expected_ext",
        [
            ("JSON", "application/json", "json"),
            ("json", "application/json", "json"),
            ("  sarif  ", "application/sarif+json", "sarif"),
            ("SARIF", "application/sarif+json", "sarif"),
            ("HtMl", "text/html", "html"),
            ("pdf", "application/pdf", "pdf"),
            ("PDF", "application/pdf", "pdf"),
        ],
    )
    def test_export_format_case_insensitivity_and_whitespace(
        self, client: TestClient, fmt_param: str, expected_mime: str, expected_ext: str
    ):
        """Export format parameter handles mixed-case and whitespace permissively."""
        queue = get_job_queue()
        jid = f"done-perm-{uuid.uuid4()}"
        queue._jobs[jid] = JobRecord(
            job_id=jid,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report={
                "id": jid,
                "findings": [],
                "scanners": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    "by_owasp": {},
                },
            },
        )

        res = client.get(f"/api/reports/{jid}/export?format={fmt_param}")
        assert res.status_code == 200
        assert expected_mime in res.headers["content-type"]
        assert f"securescan-report-{jid}.{expected_ext}" in res.headers["content-disposition"]


# =========================================================================
# 5. Rate Limiting Stress Tests
# =========================================================================

class TestRateLimitingAdversarial:
    """Stress tests SlowAPI rate limiter (10 uploads/hour/client IP)."""

    def test_rate_limiting_enforces_10_per_hour_ceiling(self):
        """11th consecutive upload from the same client IP must trigger HTTP 429."""
        limiter.reset()
        ip = "198.51.100.10"
        c = TestClient(app, client=(ip, 50000))
        valid_zip = make_valid_zip_bytes()

        # Send 10 uploads
        statuses = []
        for i in range(10):
            res = c.post(
                "/api/scan",
                files={"file": (f"test_{i}.zip", valid_zip, "application/zip")},
            )
            statuses.append(res.status_code)

        assert all(code == 200 for code in statuses), f"Expected all 10 to pass, got {statuses}"

        # 11th upload from SAME IP must be 429 Too Many Requests
        res_11 = c.post(
            "/api/scan",
            files={"file": ("test_11.zip", valid_zip, "application/zip")},
        )
        assert res_11.status_code == 429
        assert "rate limit exceeded" in res_11.text.lower() or "too many requests" in res_11.text.lower()

        # 12th upload still 429
        res_12 = c.post(
            "/api/scan",
            files={"file": ("test_12.zip", valid_zip, "application/zip")},
        )
        assert res_12.status_code == 429

    def test_rate_limiting_ip_partitioning(self):
        """Exhausting quota for IP_A must NOT block IP_B."""
        limiter.reset()
        ip_a = "198.51.100.20"
        ip_b = "198.51.100.21"
        c_a = TestClient(app, client=(ip_a, 50000))
        c_b = TestClient(app, client=(ip_b, 50000))
        valid_zip = make_valid_zip_bytes()

        # Exhaust IP_A
        for i in range(10):
            c_a.post("/api/scan", files={"file": (f"a_{i}.zip", valid_zip, "application/zip")})

        # Confirm IP_A is blocked
        res_a_blocked = c_a.post(
            "/api/scan", files={"file": ("a_blocked.zip", valid_zip, "application/zip")}
        )
        assert res_a_blocked.status_code == 429

        # IP_B must succeed
        res_b_ok = c_b.post(
            "/api/scan", files={"file": ("b_fresh.zip", valid_zip, "application/zip")}
        )
        assert res_b_ok.status_code == 200
        assert "job_id" in res_b_ok.json()


# =========================================================================
# 6. Queue Concurrency Stress Tests
# =========================================================================

class TestQueueConcurrencyStressAdversarial:
    """Stress tests concurrency=1 invariant and FIFO ordering under burst."""

    @pytest.mark.asyncio
    async def test_burst_enqueue_strictly_preserves_concurrency_one(self):
        """Submitting 6 jobs concurrently must never exceed concurrency=1."""
        q = ScanJobQueue()
        await q.start()

        active_concurrent_scanners = 0
        max_concurrent_seen = 0
        processed_sequence = []

        async def mock_runner(*args, **kwargs):
            nonlocal active_concurrent_scanners, max_concurrent_seen
            active_concurrent_scanners += 1
            max_concurrent_seen = max(max_concurrent_seen, active_concurrent_scanners)
            current_id = q._current_job_id
            processed_sequence.append(current_id)
            await asyncio.sleep(0.04)  # Simulate execution window
            active_concurrent_scanners -= 1
            return {
                "id": current_id,
                "findings": [],
                "scanners": [{"name": "secureship", "status": "SUCCESS"}],
                "summary": {"total_findings": 0, "by_severity": {}, "by_owasp": {}},
            }

        # Prepare 6 dummy zip files on disk
        temp_dir = Path(tempfile.mkdtemp(prefix="queue_stress_"))
        zip_files = []
        try:
            for i in range(6):
                zp = temp_dir / f"test_{i}.zip"
                with zipfile.ZipFile(zp, "w") as zf:
                    zf.writestr("test.py", f"# test file {i}")
                zip_files.append(str(zp))

            job_ids = [f"burst-job-{i}" for i in range(6)]

            with patch("app.core.queue.run_secureship_cli", side_effect=mock_runner):
                # Enqueue all 6 jobs in rapid succession
                for jid, zpath in zip(job_ids, zip_files):
                    await q.enqueue(job_id=jid, zip_path=zpath)

                # Wait for all jobs to complete
                for _ in range(100):
                    if all(q.get_job(jid).status == JobStatus.DONE for jid in job_ids):
                        break
                    await asyncio.sleep(0.03)

            await q.stop()

            # Invariant 1: Max concurrent execution MUST be strictly 1
            assert max_concurrent_seen == 1, f"Concurrency violation! Max seen: {max_concurrent_seen}"

            # Invariant 2: Deterministic FIFO execution order
            assert processed_sequence == job_ids, (
                f"FIFO violation! Expected {job_ids}, but processed {processed_sequence}"
            )

            # Invariant 3: All jobs reach DONE status
            for jid in job_ids:
                job = q.get_job(jid)
                assert job.status == JobStatus.DONE
                assert job.progress == 100
                assert job.report is not None

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_queue_metrics_and_health_tracking(self):
        """Queue depth and processing status must accurately reflect internal state."""
        q = ScanJobQueue()
        await q.start()

        started_event = asyncio.Event()
        release_event = asyncio.Event()

        async def pause_runner(*args, **kwargs):
            started_event.set()
            await release_event.wait()
            return {"findings": [], "scanners": [], "summary": {"total_findings": 0}}

        temp_dir = Path(tempfile.mkdtemp(prefix="metrics_stress_"))
        try:
            zp = temp_dir / "item.zip"
            with zipfile.ZipFile(zp, "w") as zf:
                zf.writestr("a.py", "pass")

            with patch("app.core.queue.run_secureship_cli", side_effect=pause_runner):
                # Enqueue 3 jobs
                await q.enqueue("job-pause-1", str(zp))
                await q.enqueue("job-pause-2", str(zp))
                await q.enqueue("job-pause-3", str(zp))

                # Wait until job 1 starts running
                await asyncio.wait_for(started_event.wait(), timeout=3.0)

                # Inspect stats while job 1 is running
                stats = q.get_stats()
                assert stats["is_processing"] is True
                assert stats["active_job_id"] == "job-pause-1"
                assert stats["queued_jobs"] == 2

                # Release the runner
                release_event.set()

                # Wait for all to finish
                for _ in range(50):
                    if q.get_job("job-pause-3") and q.get_job("job-pause-3").status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.04)

            await q.stop()

            # Final idle stats
            stats_idle = q.get_stats()
            assert stats_idle["is_processing"] is False
            assert stats_idle["active_job_id"] is None
            assert stats_idle["queued_jobs"] == 0

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


# =========================================================================
# 7. Health Endpoints Robustness Tests
# =========================================================================

class TestHealthEndpointsAdversarial:
    """Stress tests /api/health and /health dual routing and payload schema."""

    def test_health_endpoints_dual_routing_parity(self, client: TestClient):
        """Both /api/health and /health must return identical status and schema."""
        r_api = client.get("/api/health")
        r_root = client.get("/health")

        assert r_api.status_code == 200
        assert r_root.status_code == 200

        data_api = r_api.json()
        data_root = r_root.json()

        assert data_api["status"] == "healthy"
        assert data_root["status"] == "healthy"
        assert data_api["service"] == "securescan-api"
        assert data_api["version"] == "1.0.0"

        # Check required scanners readiness keys
        scanners = data_api["scanners"]
        expected_scanners = ["secureship", "opengrep", "gitleaks", "trivy", "osv-scanner", "checkov"]
        for s in expected_scanners:
            assert s in scanners, f"Scanner '{s}' missing from health report"

    def test_root_index_service_metadata(self, client: TestClient):
        """GET / returns online status and navigation links."""
        res = client.get("/")
        assert res.status_code == 200
        data = res.json()
        assert data["service"] == "SecureScan"
        assert data["status"] == "online"
        assert data["docs"] == "/docs"
        assert data["health"] == "/api/health"
