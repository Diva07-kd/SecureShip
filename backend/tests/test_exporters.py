"""
Unit tests for SecureScan multi-format exporters.
Tests JSON, SARIF 2.1.0, HTML, and PDF exporters under various scenarios.
"""

from __future__ import annotations

import json
import pytest

from app.exporters import export_html, export_json, export_pdf, export_report, export_sarif
from app.models.report import (
    CodeSnippet,
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    ReachabilityVerdict,
    ScanReport,
    ScanSummary,
    Severity,
    SnippetLine,
)


@pytest.fixture
def mock_clean_report() -> dict:
    return {
        "job_id": "clean-job-001",
        "id": "clean-job-001",
        "status": "done",
        "summary": {
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "by_owasp": {},
        },
        "scanners": [{"name": "opengrep", "status": "SUCCESS", "raw_finding_count": 0}],
        "findings": [],
    }


@pytest.fixture
def mock_vulnerable_report() -> dict:
    return {
        "job_id": "vuln-job-002",
        "id": "vuln-job-002",
        "target_name": "app.zip",
        "status": "done",
        "summary": {
            "total_findings": 2,
            "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "by_owasp": {"A07:2021-Identification and Authentication Failures": 1, "A03:2021-Injection": 1},
        },
        "scanners": [
            {"name": "gitleaks", "status": "SUCCESS", "raw_finding_count": 1},
            {"name": "opengrep", "status": "SUCCESS", "raw_finding_count": 1},
        ],
        "findings": [
            {
                "id": "f-1",
                "rule_id": "gitleaks-aws-secret",
                "scanner_name": "gitleaks",
                "category": "SECRET",
                "severity": "CRITICAL",
                "title": "Hardcoded AWS Secret Key",
                "description": "AWS Secret Access Key exposed in backend config",
                "location": {
                    "file_path": "backend/settings.py",
                    "start_line": 15,
                    "end_line": 15,
                },
                "cwe_ids": ["CWE-798"],
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "reachability": "REACHABLE",
                "snippet": {
                    "file_path": "backend/settings.py",
                    "start_line": 10,
                    "end_line": 20,
                    "lines": [
                        {"line_number": 15, "content": "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'", "is_target": True}
                    ]
                }
            },
            {
                "id": "f-2",
                "rule_id": "secureship-py-cmdi",
                "scanner_name": "opengrep",
                "category": "SAST",
                "severity": "HIGH",
                "title": "Command Injection in helper",
                "description": "os.system called with untrusted input",
                "location": {
                    "file_path": "backend/helper.py",
                    "start_line": 42,
                    "end_line": 42,
                },
                "cwe_ids": ["CWE-78"],
                "owasp_category": "A03:2021-Injection",
                "reachability": "REACHABLE",
            }
        ]
    }


@pytest.fixture
def sample_pydantic_report() -> ScanReport:
    snippet = CodeSnippet(
        file_path="src/database.py",
        start_line=20,
        end_line=26,
        target_start=23,
        target_end=23,
        lines=[
            SnippetLine(line_number=21, content="def query_user(user_id):"),
            SnippetLine(line_number=22, content="    query = f'SELECT * FROM users WHERE id = {user_id}'"),
            SnippetLine(line_number=23, content="    cursor.execute(query)", is_target=True),
            SnippetLine(line_number=24, content="    return cursor.fetchone()"),
        ],
        raw_content="cursor.execute(query)",
    )
    finding = NormalizedFinding(
        id="finding-sql-1",
        rule_id="secureship-py-sql-injection",
        scanner_name="opengrep",
        category=FindingCategory.SAST,
        severity=Severity.HIGH,
        title="SQL Injection in Database Query",
        description="User-supplied data concatenated directly into SQL statement.",
        location=FindingLocation(
            file_path="src/database.py",
            start_line=23,
            end_line=23,
            snippet="cursor.execute(query)",
        ),
        cwe_ids=["CWE-89"],
        owasp_category="A03:2021-Injection",
        reachability=ReachabilityVerdict.REACHABLE,
        confidence="HIGH",
        fix_recommendation="Use parameterized queries instead of string concatenation.",
        snippet_context=snippet,
    )
    summary = ScanSummary(
        total_findings=1,
        by_severity={"HIGH": 1},
        by_category={"SAST": 1},
        by_owasp={"A03:2021-Injection": 1},
        by_scanner={"opengrep": 1},
        by_reachability={"REACHABLE": 1},
    )
    return ScanReport(
        id="job-model-001",
        target_name="vulnerable_test.zip",
        status="done",
        duration_ms=1250.0,
        findings=[finding],
        summary=summary,
    )


class TestJsonExporter:
    def test_export_clean_json(self, mock_clean_report: dict):
        result = export_json(mock_clean_report)
        data = json.loads(result)
        assert data["job_id"] == "clean-job-001"
        assert data["id"] == "clean-job-001"
        assert data["summary"]["total_findings"] == 0
        assert data["summary"]["severity_counts"]["CRITICAL"] == 0
        assert data["summary"]["by_severity"]["CRITICAL"] == 0

    def test_export_vulnerable_json(self, mock_vulnerable_report: dict):
        result = export_json(mock_vulnerable_report)
        data = json.loads(result)
        assert data["job_id"] == "vuln-job-002"
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "CRITICAL"
        assert data["findings"][0]["ruleId"] == "gitleaks-aws-secret"
        assert "severity_counts" in data["summary"]
        assert "by_severity" in data["summary"]
        assert "owasp_counts" in data["summary"]

    def test_export_pydantic_model(self, sample_pydantic_report: ScanReport):
        result = export_json(sample_pydantic_report)
        data = json.loads(result)
        assert data["job_id"] == "job-model-001"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["ruleId"] == "secureship-py-sql-injection"


class TestSarifExporter:
    def test_export_sarif_structure(self, mock_vulnerable_report: dict):
        result = export_sarif(mock_vulnerable_report)
        sarif = json.loads(result)
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecureShip"
        assert len(run["results"]) == 2

        # Check severity mapping
        levels = [r["level"] for r in run["results"]]
        assert "error" in levels

        # Check location
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "backend/settings.py"
        assert loc["region"]["startLine"] == 15

    def test_export_sarif_pydantic_model(self, sample_pydantic_report: ScanReport):
        result = export_sarif(sample_pydantic_report)
        sarif = json.loads(result)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "secureship-py-sql-injection"
        assert "CWE-89" in rule["properties"]["tags"]
        assert len(run["results"]) == 1
        assert run["results"][0]["level"] == "error"


class TestHtmlExporter:
    def test_export_html_clean(self, mock_clean_report: dict):
        html = export_html(mock_clean_report)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html and "</html>" in html
        assert "<head" in html and "</head>" in html
        assert "<body" in html and "</body>" in html
        assert "<style>" in html
        assert 'rel="stylesheet" href="http' not in html
        assert '<script src="http' not in html
        assert "No security vulnerabilities detected" in html

    def test_export_html_vulnerable(self, mock_vulnerable_report: dict):
        html = export_html(mock_vulnerable_report)
        assert "Hardcoded AWS Secret Key" in html
        assert "AKIAIOSFODNN7EXAMPLE" in html
        assert "line-highlight" in html
        assert 'rel="stylesheet" href="http' not in html
        assert '<script src="http' not in html

    def test_export_html_pydantic_model(self, sample_pydantic_report: ScanReport):
        html = export_html(sample_pydantic_report)
        assert "<!DOCTYPE html>" in html
        assert "SQL Injection in Database Query" in html
        assert "src/database.py" in html


class TestPdfExporter:
    def test_export_pdf_clean(self, mock_clean_report: dict):
        pdf_bytes = export_pdf(mock_clean_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 200

    def test_export_pdf_vulnerable(self, mock_vulnerable_report: dict):
        pdf_bytes = export_pdf(mock_vulnerable_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000

    def test_export_pdf_pydantic_model(self, sample_pydantic_report: ScanReport):
        pdf_bytes = export_pdf(sample_pydantic_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000


class TestExportReportDispatcher:
    def test_export_report_all_formats(self, mock_vulnerable_report: dict):
        # JSON
        b_json, ct_json, ext_json = export_report(mock_vulnerable_report, "json")
        assert ct_json == "application/json"
        assert ext_json == "json"
        assert b_json.startswith(b"{")

        # SARIF
        b_sarif, ct_sarif, ext_sarif = export_report(mock_vulnerable_report, "sarif")
        assert ct_sarif == "application/sarif+json"
        assert ext_sarif == "sarif"
        assert b_sarif.startswith(b"{")

        # HTML
        b_html, ct_html, ext_html = export_report(mock_vulnerable_report, "html")
        assert "text/html" in ct_html
        assert ext_html == "html"
        assert b_html.startswith(b"<!DOCTYPE html>")

        # PDF
        b_pdf, ct_pdf, ext_pdf = export_report(mock_vulnerable_report, "pdf")
        assert ct_pdf == "application/pdf"
        assert ext_pdf == "pdf"
        assert b_pdf.startswith(b"%PDF-")

    def test_export_report_invalid_format(self, mock_vulnerable_report: dict):
        with pytest.raises(ValueError) as exc_info:
            export_report(mock_vulnerable_report, "docx")
        assert "Unsupported export format" in str(exc_info.value)
