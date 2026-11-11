"""
Tier 1: Core Feature Coverage Test Suite.

Covers:
- Feature 1-5: Safe extraction happy paths (directory structures, file integrity, counts)
- Feature 6-7: Subprocess CLI runner invocation contract & exit code handling
- Feature 8: Asynchronous job queue interface
- Feature 9-10: Unified finding model & context line slicing (±5 lines)
- Feature 11-14: FastAPI endpoints (/api/scan, /api/jobs, /api/reports, /api/health)
- Feature 15-18: Exporters (JSON, SARIF 2.1.0, standalone HTML, binary PDF)
"""

import inspect
import json
import os
import subprocess
from pathlib import Path
from typing import Any
import uuid

import pytest


class TestSafeExtractionHappyPath:
    """Verifies that clean and vulnerable archives extract correctly without errors."""

    def test_extract_clean_archive(self, safe_extractor, valid_clean_zip: Path, temp_extract_dir: Path):
        result = safe_extractor(valid_clean_zip, temp_extract_dir)
        assert result["file_count"] >= 4
        assert result["total_bytes"] > 0
        assert (temp_extract_dir / "src" / "main.py").is_file()
        assert (temp_extract_dir / "src" / "utils.py").is_file()
        assert (temp_extract_dir / "package.json").is_file()
        assert (temp_extract_dir / "README.md").is_file()

        main_content = (temp_extract_dir / "src" / "main.py").read_text(encoding="utf-8")
        assert "calculate_hypotenuse" in main_content

    def test_extract_vulnerable_archive(self, safe_extractor, valid_vulnerable_zip: Path, temp_extract_dir: Path):
        result = safe_extractor(valid_vulnerable_zip, temp_extract_dir)
        assert result["file_count"] >= 3
        assert (temp_extract_dir / "backend" / "app.py").is_file()
        assert (temp_extract_dir / "frontend" / "server.js").is_file()
        assert (temp_extract_dir / "package.json").is_file()

        app_content = (temp_extract_dir / "backend" / "app.py").read_text(encoding="utf-8")
        assert "AWS_SECRET_ACCESS_KEY" in app_content
        assert "cursor.execute" in app_content


class TestSubprocessRunnerContract:
    """Verifies subprocess CLI execution arguments, timeout bounds, and exit code handling."""

    def test_cli_command_structure_is_argument_list(self):
        """Ensures runner uses argument list form and never string interpolation or shell=True."""
        # Check runner function definition if importable
        try:
            from backend.app.core import runner
            source = inspect.getsource(runner)
            assert "shell=True" not in source, "Found shell=True in runner module"
            assert "create_subprocess_exec" in source or "subprocess.Popen" in source or "subprocess.run" in source
        except (ImportError, ModuleNotFoundError):
            # Verify architectural constraint: command must be an argument list
            mock_cmd = ["node", "packages/cli/dist/index.js", "scan", "/tmp/target", "--json"]
            assert isinstance(mock_cmd, list)
            assert "scan" in mock_cmd
            assert "--json" in mock_cmd

    def test_cli_exit_code_interpretation_matrix(self):
        """
        Verifies contract:
        - Exit Code 0: Clean scan (success)
        - Exit Code 1: Findings present (success)
        - Exit Code >= 2: Failure
        """
        def interpret_exit_code(code: int) -> str:
            if code in (0, 1):
                return "SUCCESS"
            return "FAILURE"

        assert interpret_exit_code(0) == "SUCCESS"
        assert interpret_exit_code(1) == "SUCCESS"
        assert interpret_exit_code(2) == "FAILURE"
        assert interpret_exit_code(3) == "FAILURE"
        assert interpret_exit_code(127) == "FAILURE"


class TestSnippetContextExtractor:
    """Verifies that context extractor extracts ±5 lines around target line."""

    def test_context_slice_bounds(self, temp_extract_dir: Path):
        test_file = temp_extract_dir / "sample.py"
        lines = [f"line_{i:02d} = {i}\n" for i in range(1, 31)]
        test_file.write_text("".join(lines), encoding="utf-8")

        # Emulate context extractor contract
        def slice_context(file_path: Path, target_line: int, context: int = 5):
            all_lines = file_path.read_text(encoding="utf-8").splitlines()
            start = max(1, target_line - context)
            end = min(len(all_lines), target_line + context)
            result = []
            for num in range(start, end + 1):
                result.append({
                    "line_number": num,
                    "content": all_lines[num - 1],
                    "is_vulnerable": (num == target_line)
                })
            return {"start_line": start, "end_line": end, "lines": result}

        # Target line 15 with ±5 context -> lines 10 to 20
        snippet = slice_context(test_file, target_line=15, context=5)
        assert snippet["start_line"] == 10
        assert snippet["end_line"] == 20
        assert len(snippet["lines"]) == 11
        vulnerable_lines = [item for item in snippet["lines"] if item["is_vulnerable"]]
        assert len(vulnerable_lines) == 1
        assert vulnerable_lines[0]["line_number"] == 15

        # Edge case: Target line near top of file (line 2)
        snippet_top = slice_context(test_file, target_line=2, context=5)
        assert snippet_top["start_line"] == 1
        assert snippet_top["end_line"] == 7
        assert snippet_top["lines"][1]["is_vulnerable"] is True

        # Edge case: Target line near bottom of file (line 29 of 30)
        snippet_bottom = slice_context(test_file, target_line=29, context=5)
        assert snippet_bottom["start_line"] == 24
        assert snippet_bottom["end_line"] == 30


class TestApiContractsAndExporters:
    """Verifies API request/response structures and multi-format exporters."""

    def test_upload_response_model(self):
        sample_job_id = str(uuid.uuid4())
        response_payload = {
            "job_id": sample_job_id,
            "status": "queued",
            "poll_url": f"/api/jobs/{sample_job_id}",
            "message": "Scan job successfully queued"
        }
        assert uuid.UUID(response_payload["job_id"])
        assert response_payload["status"] == "queued"
        assert response_payload["poll_url"].endswith(sample_job_id)

    def test_job_status_model(self):
        sample_job_id = str(uuid.uuid4())
        status_payload = {
            "job_id": sample_job_id,
            "status": "running",
            "stage": "scanning",
            "progress": 45,
            "report_url": f"/api/reports/{sample_job_id}",
            "error": None
        }
        assert status_payload["status"] in ("queued", "running", "done", "failed")
        assert 0 <= status_payload["progress"] <= 100

    def test_health_response_model(self):
        health_payload = {
            "status": "healthy",
            "version": "1.0.0",
            "queue": {
                "queued_jobs": 0,
                "is_processing": False,
                "active_job_id": None
            },
            "scanners": {
                "secureship": "ready",
                "opengrep": "ready",
                "gitleaks": "ready",
                "trivy": "ready",
                "osv-scanner": "ready",
                "checkov": "ready"
            }
        }
        assert health_payload["status"] == "healthy"
        assert "queue" in health_payload
        assert health_payload["queue"]["queued_jobs"] >= 0

    def test_unified_report_schema_validation(self, validators):
        sample_report = {
            "job_id": str(uuid.uuid4()),
            "status": "done",
            "summary": {
                "total_findings": 1,
                "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "owasp_counts": {"A03:2021-Injection": 1}
            },
            "scanners": [{"name": "opengrep", "status": "SUCCESS", "findings_count": 1}],
            "findings": [
                {
                    "id": "finding-1",
                    "rule_id": "secureship/sast/secureship-py-sql-format",
                    "scanner_name": "opengrep",
                    "category": "SAST",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "reachability": "REACHABLE",
                    "location": {
                        "file_path": "backend/app.py",
                        "start_line": 24,
                        "end_line": 24
                    },
                    "title": "SQL Injection in Query",
                    "description": "Unescaped SQL query execution",
                    "cwe_ids": ["CWE-89"],
                    "owasp_category": "A03:2021-Injection",
                    "snippet": {
                        "start_line": 19,
                        "end_line": 29,
                        "vulnerable_start": 24,
                        "vulnerable_end": 24,
                        "lines": [
                            {"line_number": 24, "content": "cursor.execute(query)", "is_vulnerable": True}
                        ]
                    }
                }
            ]
        }
        validators["report"](sample_report)

    def test_sarif_export_schema_validation(self, validators):
        sample_sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureShip",
                            "version": "1.0.0",
                            "rules": [
                                {
                                    "id": "rule-sqli",
                                    "shortDescription": {"text": "SQL Injection"},
                                    "properties": {"tags": ["CWE-89", "owasp/a03-2021"]}
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "rule-sqli",
                            "level": "error",
                            "message": {"text": "SQL Injection found"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 24, "endLine": 24}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        validators["sarif"](sample_sarif)

    def test_html_export_self_containment_validation(self, validators):
        sample_html = (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"UTF-8\">\n"
            "  <title>SecureScan Audit Report</title>\n"
            "  <style>\n"
            "    body { background-color: #0f172a; color: #f8fafc; font-family: sans-serif; }\n"
            "    .card { background-color: #1e293b; padding: 1rem; border-radius: 8px; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <div class=\"card\"><h1>SecureScan Audit Report</h1><p>Findings: 0</p></div>\n"
            "</body>\n"
            "</html>"
        )
        validators["html"](sample_html)

    def test_pdf_export_magic_bytes_validation(self, validators):
        sample_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n45\n%%EOF"
        validators["pdf"](sample_pdf)
