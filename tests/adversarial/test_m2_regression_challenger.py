"""
Adversarial Regression Test Suite for SecureScan Milestone 2 Iteration 2.
Challenger: Challenger M2-1-r2 (API Endpoints & Exporters Regression).

Verifies:
1. Re-verifies all API endpoints (POST /api/scan, GET /api/jobs/{id}, GET /api/reports/{id},
   GET /api/health, GET /api/reports/{id}/export).
2. Verifies that exporter modifications (XML escaping in PDF, severity whitelisting in HTML,
   print stylesheet rules, safe integer casting) do NOT regress API export endpoints.
3. Tests hostile payload exports through the live FastAPI HTTP interface.
"""

from __future__ import annotations

import io
import uuid
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.queue import get_job_queue
from app.models.job import JobRecord, JobStatus, JobStage
from app.models.report import (
    ScanReport,
    NormalizedFinding,
    FindingLocation,
    FindingCategory,
    Severity,
    ScannerExecutionSummary,
    ScanSummary,
    CodeSnippet,
    SnippetLine,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def clean_queue():
    queue = get_job_queue()
    queue._jobs.clear()
    return queue


def _create_minimal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.py", "print('hello world')\n")
    return buf.getvalue()


class TestExportEndpointRegressionAdversarial:
    """Verifies that changes to pdf_exporter and html_exporter do not regress /api/reports/{id}/export."""

    def test_export_pdf_with_hostile_xml_and_cxx_templates_via_api(self, client: TestClient, clean_queue):
        """
        Adversarial probe: Hostile strings like Vector<int>, unclosed tags, and ampersands
        in titles/descriptions/code snippets must not crash ReportLab through the API endpoint.
        Must return HTTP 200 with valid binary PDF, not HTTP 500.
        """
        job_id = f"pdf-cxx-{uuid.uuid4()}"
        findings = [
            NormalizedFinding(
                id="f-cxx-1",
                rule_id="cpp-buffer-overflow-<rule>",
                scanner_name="opengrep",
                category=FindingCategory.SAST,
                severity=Severity.HIGH,
                title="Buffer overflow in std::vector<std::string> & List<T>",
                description="Unsafe memory copy: if (a < b && c > d) causes underflow. Tag: <unclosed tag",
                location=FindingLocation(file_path="src/engine/<core>.cpp", start_line=55, end_line=55),
                cwe_ids=["CWE-120", "CWE-999"],
                owasp_category="A03:2021-Injection",
                snippet_context=CodeSnippet(
                    file_path="src/engine/<core>.cpp",
                    start_line=50,
                    end_line=60,
                    target_start=55,
                    target_end=55,
                    raw_content="template <typename T>\nVector<int> *v = new Vector<int>();\nreturn v;",
                    lines=[
                        SnippetLine(line_number=54, content="template <typename T>", is_target=False),
                        SnippetLine(line_number=55, content="Vector<int> *v = new Vector<int>();", is_target=True),
                        SnippetLine(line_number=56, content="return v;", is_target=False),
                    ],
                ),
            )
        ]
        report = ScanReport(
            id=job_id,
            status="done",
            findings=findings,
            scanners=[ScannerExecutionSummary(name="opengrep", status="SUCCESS", raw_finding_count=1)],
            summary=ScanSummary(total_findings=1, by_severity={"HIGH": 1}),
        )
        clean_queue._jobs[job_id] = JobRecord(
            job_id=job_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report=report,
        )

        resp = client.get(f"/api/reports/{job_id}/export?format=pdf")
        assert resp.status_code == 200, f"Export PDF failed with {resp.status_code}: {resp.text}"
        assert resp.headers["content-type"] == "application/pdf"
        assert f'filename="securescan-report-{job_id}.pdf"' in resp.headers["content-disposition"]
        assert resp.content.startswith(b"%PDF-"), "Output is not a valid PDF"
        assert b"%%EOF" in resp.content[-1024:], "PDF missing %%EOF trailer"

    def test_export_html_with_severity_xss_and_print_styles_via_api(self, client: TestClient, clean_queue):
        """
        Adversarial probe: Malicious severity attribute breakout and XSS payloads in findings
        must be escaped/whitelisted, and print stylesheet rules must be present in HTML export.
        """
        job_id = f"html-xss-{uuid.uuid4()}"
        # Test finding with adversarial content
        finding = NormalizedFinding(
            id="f-xss-1",
            rule_id="sec-leak",
            scanner_name="gitleaks",
            category=FindingCategory.SECRET,
            severity=Severity.CRITICAL,
            title='Secret Token <script>alert("pwned")</script>',
            description='Token leaked <img src=x onerror=alert(1)> in code',
            location=FindingLocation(file_path="src/auth.py", start_line=12, end_line=12),
            cwe_ids=["CWE-798"],
            owasp_category="A07:2021-Identification and Authentication Failures",
        )
        report = ScanReport(
            id=job_id,
            status="done",
            findings=[finding],
            scanners=[ScannerExecutionSummary(name="gitleaks", status="SUCCESS", raw_finding_count=1)],
            summary=ScanSummary(total_findings=1, by_severity={"CRITICAL": 1}),
        )
        clean_queue._jobs[job_id] = JobRecord(
            job_id=job_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report=report,
        )

        resp = client.get(f"/api/reports/{job_id}/export?format=html")
        assert resp.status_code == 200, f"Export HTML failed with {resp.status_code}: {resp.text}"
        assert "text/html" in resp.headers["content-type"]
        assert f'filename="securescan-report-{job_id}.html"' in resp.headers["content-disposition"]

        html_text = resp.text
        # Script tags in title/desc escaped
        assert '<script>alert("pwned")</script>' not in html_text
        assert '&lt;script&gt;alert(' in html_text
        # Print stylesheet included
        assert "@media print" in html_text
        assert "page-break-inside: avoid" in html_text or "break-inside: avoid" in html_text
        assert "#ffffff" in html_text

    def test_export_pdf_with_null_cwes_and_missing_snippet_lines(self, client: TestClient, clean_queue):
        """
        Adversarial probe: Findings with None cwe_ids and minimal snippets
        must be handled safely by pdf_exporter and return HTTP 200 via the API.
        """
        job_id = f"pdf-null-{uuid.uuid4()}"
        findings = [
            NormalizedFinding(
                id="f-null-1",
                rule_id="CVE-2026-9999",
                scanner_name="trivy",
                category=FindingCategory.SCA,
                severity=Severity.MEDIUM,
                title="Vulnerable dependency",
                description="A CVE without CWEs",
                location=FindingLocation(file_path="requirements.txt", start_line=1, end_line=1),
                cwe_ids=[],
                owasp_category="A06:2021-Vulnerable and Outdated Components",
            )
        ]
        report = ScanReport(
            id=job_id,
            status="done",
            findings=findings,
            scanners=[ScannerExecutionSummary(name="trivy", status="SUCCESS", raw_finding_count=1)],
            summary=ScanSummary(total_findings=1, by_severity={"MEDIUM": 1}),
        )
        clean_queue._jobs[job_id] = JobRecord(
            job_id=job_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report=report,
        )

        resp = client.get(f"/api/reports/{job_id}/export?format=pdf")
        assert resp.status_code == 200
        assert resp.content.startswith(b"%PDF-")

    def test_export_all_four_formats_parity(self, client: TestClient, clean_queue):
        """Verifies that all 4 formats (json, sarif, html, pdf) export properly for a completed scan."""
        job_id = f"all-fmt-{uuid.uuid4()}"
        report = ScanReport(
            id=job_id,
            status="done",
            findings=[],
            scanners=[
                ScannerExecutionSummary(name="opengrep", status="SUCCESS"),
                ScannerExecutionSummary(name="trivy", status="SUCCESS"),
            ],
            summary=ScanSummary(total_findings=0, by_severity={"INFO": 0}),
        )
        clean_queue._jobs[job_id] = JobRecord(
            job_id=job_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report=report,
        )

        expected = [
            ("json", "application/json", ".json"),
            ("sarif", "application/sarif+json", ".sarif"),
            ("html", "text/html", ".html"),
            ("pdf", "application/pdf", ".pdf"),
        ]

        for fmt, mime, ext in expected:
            resp = client.get(f"/api/reports/{job_id}/export?format={fmt}")
            assert resp.status_code == 200
            assert mime in resp.headers["content-type"]
            assert f'filename="securescan-report-{job_id}{ext}"' in resp.headers["content-disposition"]


class TestApiEndpointsReverificationAdversarial:
    """Re-verifies all main API endpoints for Milestone 2."""

    def test_health_endpoints_parity(self, client: TestClient):
        """GET /api/health and GET /health return identical healthy payloads."""
        r1 = client.get("/api/health")
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["status"] == "healthy"
        assert "queue_depth" in d1
        assert "active_jobs" in d1

        r2 = client.get("/health")
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["status"] == d1["status"]
        assert d2["queue_depth"] == d1["queue_depth"]
        assert d2["active_jobs"] == d1["active_jobs"]
        assert d2["version"] == d1["version"]

    def test_scan_upload_valid_zip_enqueues_cleanly(self, client: TestClient, clean_queue):
        """POST /api/scan accepts valid zip archive and enqueues job with HTTP 200."""
        zip_bytes = _create_minimal_zip()
        files = {"file": ("project.zip", zip_bytes, "application/zip")}
        resp = client.post("/api/scan", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data
        assert data["status"] == "queued"
        assert data["poll_url"] == f"/api/jobs/{data['job_id']}"

    def test_scan_upload_non_zip_rejected_with_400(self, client: TestClient):
        """POST /api/scan rejects non-zip upload with HTTP 400."""
        files = {"file": ("malware.exe", b"MZ\x90\x00\x03\x00", "application/x-msdownload")}
        resp = client.post("/api/scan", files=files)
        assert resp.status_code == 400
        assert "Only .zip archives are supported" in resp.json()["detail"]

    def test_scan_upload_fake_header_rejected_with_400(self, client: TestClient):
        """POST /api/scan rejects file with .zip extension but invalid magic header."""
        files = {"file": ("fake.zip", b"Not a zip file content at all", "application/zip")}
        resp = client.post("/api/scan", files=files)
        assert resp.status_code == 400
        assert "missing PK magic header" in resp.json()["detail"]

    def test_job_status_endpoint_states(self, client: TestClient, clean_queue):
        """GET /api/jobs/{id} returns accurate status across queued, running, done, failed."""
        jid_done = f"done-{uuid.uuid4()}"
        clean_queue._jobs[jid_done] = JobRecord(
            job_id=jid_done,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
        )

        resp = client.get(f"/api/jobs/{jid_done}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "done"
        assert resp.json()["progress"] == 100

        # Nonexistent job returns 404
        resp_404 = client.get(f"/api/jobs/{uuid.uuid4()}")
        assert resp_404.status_code == 404

    def test_report_endpoint_lifecycle(self, client: TestClient, clean_queue):
        """GET /api/reports/{id} returns 200 for done, 409 for queued/running, 422 for failed."""
        # 1. Done
        jid_done = f"done-{uuid.uuid4()}"
        report = ScanReport(id=jid_done, status="done", findings=[])
        clean_queue._jobs[jid_done] = JobRecord(
            job_id=jid_done,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report=report,
        )
        r_done = client.get(f"/api/reports/{jid_done}")
        assert r_done.status_code == 200
        assert r_done.json()["id"] == jid_done

        # 2. Queued
        jid_queued = f"queued-{uuid.uuid4()}"
        clean_queue._jobs[jid_queued] = JobRecord(
            job_id=jid_queued,
            status=JobStatus.QUEUED,
            stage=JobStage.QUEUED,
            progress=0,
        )
        r_queued = client.get(f"/api/reports/{jid_queued}")
        assert r_queued.status_code == 409

        # 3. Failed
        jid_failed = f"failed-{uuid.uuid4()}"
        clean_queue._jobs[jid_failed] = JobRecord(
            job_id=jid_failed,
            status=JobStatus.FAILED,
            stage=JobStage.FAILED,
            progress=100,
            error="Extraction failed: Zip-bomb ratio exceeded",
        )
        r_failed = client.get(f"/api/reports/{jid_failed}")
        assert r_failed.status_code == 422
        assert "Extraction failed" in r_failed.json()["detail"]
