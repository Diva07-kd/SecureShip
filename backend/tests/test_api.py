"""
Integration tests for SecureScan FastAPI API endpoints.
Tests /api/health, /health, /api/scan, /api/jobs/{id}, and /api/reports/{id}/export.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.queue import get_job_queue
from app.models.job import JobRecord, JobStatus, JobStage
from app.models.report import ScanReport, ScanSummary, NormalizedFinding, FindingLocation


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def sample_zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.js", "console.log('hello safe world');")
    return buffer.getvalue()


@pytest.fixture
def seeded_done_job() -> str:
    queue = get_job_queue()
    job_id = "test-seeded-done-job"
    report_dict = {
        "job_id": job_id,
        "id": job_id,
        "target_name": "sample.zip",
        "status": "done",
        "summary": {
            "total_findings": 1,
            "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "by_owasp": {"A03:2021-Injection": 1},
        },
        "scanners": [{"name": "opengrep", "status": "SUCCESS"}],
        "findings": [
            {
                "id": "f-seed-1",
                "rule_id": "secureship-py-sql-injection",
                "scanner_name": "opengrep",
                "category": "SAST",
                "severity": "HIGH",
                "title": "SQL Injection in app.py",
                "description": "User input directly concatenated into query",
                "location": {
                    "file_path": "backend/app.py",
                    "start_line": 24,
                    "end_line": 24,
                },
                "cwe_ids": ["CWE-89"],
                "owasp_category": "A03:2021-Injection",
                "reachability": "REACHABLE",
                "snippet": {
                    "file_path": "backend/app.py",
                    "start_line": 20,
                    "end_line": 28,
                    "lines": [
                        {"line_number": 24, "content": "cursor.execute(query)", "is_target": True}
                    ]
                }
            }
        ]
    }
    record = JobRecord(
        job_id=job_id,
        status=JobStatus.DONE,
        stage=JobStage.COMPLETED,
        progress=100,
        poll_url=f"/api/jobs/{job_id}",
        report_url=f"/api/reports/{job_id}",
        report=report_dict,
        target_name="sample.zip",
        completed_at="2026-11-07T12:00:00Z",
    )

    queue._jobs[job_id] = record
    return job_id


@pytest.fixture
def seeded_in_progress_jobs() -> tuple[str, str]:
    queue = get_job_queue()
    queued_id = "test-seeded-queued-job"
    running_id = "test-seeded-running-job"

    queue._jobs[queued_id] = JobRecord(
        job_id=queued_id,
        status=JobStatus.QUEUED,
        stage=JobStage.QUEUED,
        progress=0,
        poll_url=f"/api/jobs/{queued_id}",
    )
    queue._jobs[running_id] = JobRecord(
        job_id=running_id,
        status=JobStatus.RUNNING,
        stage=JobStage.SCANNING,
        progress=45,
        poll_url=f"/api/jobs/{running_id}",
    )
    return queued_id, running_id


@pytest.fixture
def seeded_failed_job() -> str:
    queue = get_job_queue()
    failed_id = "test-seeded-failed-job"
    queue._jobs[failed_id] = JobRecord(
        job_id=failed_id,
        status=JobStatus.FAILED,
        stage=JobStage.FAILED,
        progress=100,
        error="Zip-slip path traversal rejected",
        poll_url=f"/api/jobs/{failed_id}",
    )
    return failed_id


class TestHealthEndpoint:
    def test_get_api_health(self, client: TestClient):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "queue_depth" in data
        assert "active_jobs" in data
        assert "timestamp" in data
        assert "queue" in data
        assert data["queue"]["queued_jobs"] >= 0
        assert "scanners" in data
        assert "secureship" in data["scanners"]

    def test_get_root_health_alias(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "queue" in data

    def test_get_root(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "SecureScan"
        assert data["status"] == "online"


class TestScanUploadEndpoint:
    def test_upload_invalid_file_extension(self, client: TestClient):
        file_content = b"not a zip file content"
        response = client.post(
            "/api/scan",
            files={"file": ("malicious.sh", file_content, "application/x-sh")},
        )
        assert response.status_code == 400
        assert "Only .zip archives are supported" in response.json()["detail"]

    def test_upload_empty_file(self, client: TestClient):
        response = client.post(
            "/api/scan",
            files={"file": ("empty.zip", b"", "application/zip")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_upload_invalid_magic_bytes(self, client: TestClient):
        # A file named .zip that contains plain text without PK header
        fake_content = b"This is a fake zip header content."
        response = client.post(
            "/api/scan",
            files={"file": ("fake.zip", fake_content, "application/zip")},
        )
        assert response.status_code == 400
        assert "missing PK magic header" in response.json()["detail"]

    def test_upload_valid_zip(self, client: TestClient, sample_zip_bytes: bytes):
        response = client.post(
            "/api/scan",
            files={"file": ("project.zip", sample_zip_bytes, "application/zip")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "queued"
        assert data["poll_url"] == f"/api/jobs/{data['job_id']}"


class TestJobStatusEndpoint:
    def test_job_not_found(self, client: TestClient):
        response = client.get("/api/jobs/nonexistent-uuid-99999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_seeded_job_status(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/jobs/{seeded_done_job}")
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == seeded_done_job
        assert data["status"] == "done"
        assert data["progress"] == 100
        assert data["completed_at"] is not None
        assert data["poll_url"] == f"/api/jobs/{seeded_done_job}"
        assert data["report_url"] == f"/api/reports/{seeded_done_job}"


class TestReportRetrievalEndpoint:
    def test_report_not_found(self, client: TestClient):
        response = client.get("/api/reports/nonexistent-uuid-99999")
        assert response.status_code == 404

    def test_report_in_progress_returns_409(self, client: TestClient, seeded_in_progress_jobs: tuple[str, str]):
        queued_id, running_id = seeded_in_progress_jobs
        res_queued = client.get(f"/api/reports/{queued_id}")
        assert res_queued.status_code == 409
        assert "not ready" in res_queued.json()["detail"].lower()

        res_running = client.get(f"/api/reports/{running_id}")
        assert res_running.status_code == 409
        assert "not ready" in res_running.json()["detail"].lower()

    def test_report_failed_returns_422(self, client: TestClient, seeded_failed_job: str):
        response = client.get(f"/api/reports/{seeded_failed_job}")
        assert response.status_code == 422
        assert "Scan failed" in response.json()["detail"]

    def test_get_seeded_report(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}")
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == seeded_done_job
        assert data["id"] == seeded_done_job
        assert data["summary"]["total_findings"] == 1
        assert "by_severity" in data["summary"]
        assert "severity_counts" in data["summary"]
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["rule_id"] == "secureship-py-sql-injection"
        assert finding["owasp_category"] == "A03:2021-Injection"


class TestReportExports:
    def test_export_json(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}/export?format=json")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
        assert f'attachment; filename="securescan-report-{seeded_done_job}.json"' in response.headers["content-disposition"]
        data = response.json()
        assert data["job_id"] == seeded_done_job

    def test_export_sarif(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}/export?format=sarif")
        assert response.status_code == 200
        assert "application/sarif+json" in response.headers["content-type"]
        assert f'attachment; filename="securescan-report-{seeded_done_job}.sarif"' in response.headers["content-disposition"]
        sarif = response.json()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0

    def test_export_html(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}/export?format=html")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert f'attachment; filename="securescan-report-{seeded_done_job}.html"' in response.headers["content-disposition"]
        assert "<!DOCTYPE html>" in response.text
        assert "SecureScan Audit Report" in response.text
        assert 'rel="stylesheet" href="http' not in response.text
        assert '<script src="http' not in response.text

    def test_export_pdf(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}/export?format=pdf")
        assert response.status_code == 200
        assert "application/pdf" in response.headers["content-type"]
        assert f'attachment; filename="securescan-report-{seeded_done_job}.pdf"' in response.headers["content-disposition"]
        assert response.content.startswith(b"%PDF-")

    def test_export_invalid_format(self, client: TestClient, seeded_done_job: str):
        response = client.get(f"/api/reports/{seeded_done_job}/export?format=docx")
        assert response.status_code == 400
        assert "Unsupported export format" in response.json()["detail"]

    def test_export_not_found(self, client: TestClient):
        response = client.get("/api/reports/nonexistent-uuid-99999/export?format=json")
        assert response.status_code == 404

    def test_export_in_progress_returns_409(self, client: TestClient, seeded_in_progress_jobs: tuple[str, str]):
        queued_id, running_id = seeded_in_progress_jobs
        res_q = client.get(f"/api/reports/{queued_id}/export?format=pdf")
        assert res_q.status_code == 409
        assert "not ready" in res_q.json()["detail"].lower()

        res_r = client.get(f"/api/reports/{running_id}/export?format=html")
        assert res_r.status_code == 409
        assert "not ready" in res_r.json()["detail"].lower()

    def test_export_failed_job_returns_422(self, client: TestClient, seeded_failed_job: str):
        response = client.get(f"/api/reports/{seeded_failed_job}/export?format=json")
        assert response.status_code == 422
        assert "Scan failed" in response.json()["detail"]
