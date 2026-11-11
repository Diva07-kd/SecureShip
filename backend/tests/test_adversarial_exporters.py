"""
Adversarial test suite for SecureScan multi-format exporters and export endpoints.
Challenger M2-2: Exporters & Format Compliance Adversarial Challenger.
Systematically stress-tests JSON, SARIF 2.1.0, HTML, and PDF exporters and the FastAPI export route.
"""

from __future__ import annotations

import io
import json
import re
import time
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient
import jsonschema

from app.main import app
from app.core.queue import get_job_queue
from app.models.job import JobRecord, JobStatus, JobStage
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
from app.exporters import (
    SUPPORTED_FORMATS,
    export_html,
    export_json,
    export_pdf,
    export_report,
    export_sarif,
    generate_sarif_dict,
    normalize_report_dict,
)

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="session")
def sarif_schema() -> dict[str, Any]:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# =========================================================================
# 1. JSON Exporter Adversarial Tests
# =========================================================================

class TestJsonExporterAdversarial:
    def test_json_bidirectional_field_presence(self):
        """Verify job_id/id and severity_counts/by_severity interoperability."""
        raw_report = {
            "id": "bidir-test-123",
            "status": "done",
            "summary": {
                "total_findings": 1,
                "by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "by_owasp": {"A01:2021-Broken Access Control": 1},
            },
            "findings": [
                {
                    "id": "f-1",
                    "rule_id": "r-1",
                    "severity": "CRITICAL",
                    "location": {"file_path": "a.py", "start_line": 5},
                }
            ],
        }

        output_str = export_json(raw_report)
        data = json.loads(output_str)

        # Root interoperability
        assert "job_id" in data
        assert "id" in data
        assert data["job_id"] == "bidir-test-123"
        assert data["id"] == "bidir-test-123"

        # Summary interoperability
        assert "severity_counts" in data["summary"]
        assert "by_severity" in data["summary"]
        assert data["summary"]["severity_counts"]["CRITICAL"] == 1
        assert data["summary"]["by_severity"]["CRITICAL"] == 1
        assert "owasp_counts" in data["summary"]
        assert "by_owasp" in data["summary"]

    def test_json_round_trip_empty_and_zero_findings(self):
        """Verify serialization and round-trip parsing with 0 findings and empty fields."""
        raw_report = {
            "job_id": "clean-zero-findings",
            "status": "done",
            "summary": {},
            "findings": [],
        }

        output_str = export_json(raw_report)
        data = json.loads(output_str)

        assert data["job_id"] == "clean-zero-findings"
        assert data["id"] == "clean-zero-findings"
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert data["summary"]["severity_counts"][sev] == 0
            assert data["summary"]["by_severity"][sev] == 0

    def test_json_scale_1000_findings(self):
        """Stress-test with 1,200 synthetic findings: round-trip accuracy, memory, latency."""
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings = []
        count = 1200
        for i in range(count):
            sev = severities[i % len(severities)]
            findings.append({
                "id": f"syn-finding-{i:04d}",
                "rule_id": f"synthetic-rule-{(i % 50):02d}",
                "scanner_name": "synthetic-scanner",
                "category": "SAST",
                "severity": sev,
                "title": f"Synthetic Vulnerability #{i}",
                "description": f"Detailed description for synthetic vulnerability {i} with code references.",
                "location": {
                    "file_path": f"src/modules/submodule_{i % 20}/file_{i}.py",
                    "start_line": (i * 7) % 500 + 1,
                    "end_line": (i * 7) % 500 + 3,
                },
                "cwe_ids": [f"CWE-{(i % 100) + 1}"],
                "owasp_category": "A03:2021-Injection",
                "reachability": "REACHABLE" if i % 2 == 0 else "UNREACHABLE",
                "snippet": {
                    "file_path": f"src/modules/submodule_{i % 20}/file_{i}.py",
                    "start_line": (i * 7) % 500 + 1,
                    "end_line": (i * 7) % 500 + 3,
                    "lines": [
                        {"line_number": (i * 7) % 500 + 1, "content": f"data = request.get('{i}')", "is_target": False},
                        {"line_number": (i * 7) % 500 + 2, "content": f"cursor.execute(f'SELECT {i}')", "is_target": True},
                    ],
                    "raw_content": f"cursor.execute(f'SELECT {i}')",
                },
            })

        large_report = {
            "job_id": "scale-test-1200",
            "status": "done",
            "findings": findings,
            "summary": {
                "total_findings": count,
            },
        }

        t0 = time.perf_counter()
        json_output = export_json(large_report)
        duration_s = time.perf_counter() - t0

        # Sub-second serialization for 1,200 findings
        assert duration_s < 2.0, f"Serialization took {duration_s:.3f}s (expected < 2.0s)"

        parsed = json.loads(json_output)
        assert parsed["job_id"] == "scale-test-1200"
        assert len(parsed["findings"]) == count
        assert parsed["summary"]["total_findings"] == count
        assert parsed["findings"][0]["id"] == "syn-finding-0000"
        assert parsed["findings"][count - 1]["id"] == f"syn-finding-{count - 1:04d}"

    def test_json_unicode_and_adversarial_payloads(self):
        """Verify JSON exporter handles unicode, emoji, control chars, and null bytes safely."""
        tricky_report = {
            "job_id": "unicode-payload-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-uni-1",
                    "rule_id": "rule-\u00e9\u00e8\u00e0-\u4e2d\u6587",
                    "title": "SQL Injection \ud83d\udd25 with CJK \u6f0f\u6d1e and symbols \u26a0\ufe0f",
                    "description": "Unicode test: \u0000 null byte, backslash \\, newline \n, tabs \t, quotes \" '",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "../../etc/passwd",
                        "start_line": 1,
                    },
                }
            ],
        }

        json_output = export_json(tricky_report)
        parsed = json.loads(json_output)
        assert "🔥" in parsed["findings"][0]["title"]
        assert "\\\\" in json_output or "\\" in parsed["findings"][0]["description"]


# =========================================================================
# 2. SARIF 2.1.0 Exporter Adversarial Tests
# =========================================================================

class TestSarifExporterAdversarial:
    def test_sarif_oasis_schema_conformance(self, sarif_schema: dict[str, Any]):
        """Validate exported SARIF against official OASIS SARIF 2.1.0 JSON Schema."""
        report = {
            "job_id": "sarif-valid-001",
            "status": "done",
            "scanners": [{"name": "opengrep", "status": "SUCCESS"}],
            "findings": [
                {
                    "id": "f-1",
                    "rule_id": "secureship-py-cmdi",
                    "scanner_name": "opengrep",
                    "category": "SAST",
                    "severity": "CRITICAL",
                    "title": "Command Injection",
                    "description": "Untrusted input passed to subprocess",
                    "location": {
                        "file_path": "backend/app/runner.py",
                        "start_line": 42,
                        "end_line": 45,
                        "start_column": 5,
                        "end_column": 30,
                    },
                    "cwe_ids": ["CWE-78"],
                    "owasp_category": "A03:2021-Injection",
                    "reachability": "REACHABLE",
                    "fix_recommendation": "Use argument list form without shell=True",
                    "snippet": {
                        "file_path": "backend/app/runner.py",
                        "start_line": 40,
                        "end_line": 50,
                        "lines": [
                            {"line_number": 42, "content": "subprocess.run(cmd, shell=True)", "is_target": True}
                        ],
                        "raw_content": "subprocess.run(cmd, shell=True)",
                    },
                }
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        assert sarif_doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif_doc["version"] == "2.1.0"
        assert len(sarif_doc["runs"]) == 1
        run = sarif_doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecureShip"
        assert len(run["results"]) == 1
        res = run["results"][0]
        assert res["level"] == "error"
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "backend/app/runner.py"
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
        assert res["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == "subprocess.run(cmd, shell=True)"

    def test_sarif_clean_report_schema_conformance(self, sarif_schema: dict[str, Any]):
        """Validate 0 findings report adheres to OASIS SARIF 2.1.0 schema."""
        clean_report = {
            "job_id": "clean-sarif-000",
            "status": "done",
            "findings": [],
        }

        sarif_doc = generate_sarif_dict(clean_report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        assert len(sarif_doc["runs"][0]["results"]) == 0
        assert len(sarif_doc["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_sarif_missing_line_numbers_and_missing_location(self, sarif_schema: dict[str, Any]):
        """Findings with None, 0, or missing line numbers should default to valid >= 1 line."""
        report = {
            "job_id": "missing-lines-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-no-line",
                    "rule_id": "rule-no-line",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "Dockerfile",
                        # start_line and end_line omitted
                    },
                },
                {
                    "id": "f-none-line",
                    "rule_id": "rule-none-line",
                    "severity": "MEDIUM",
                    "location": {
                        "file_path": "package.json",
                        "start_line": None,
                        "end_line": None,
                    },
                },
                {
                    "id": "f-zero-line",
                    "rule_id": "rule-zero-line",
                    "severity": "LOW",
                    "location": {
                        "file_path": "README.md",
                        "start_line": 0,
                        "end_line": 0,
                    },
                },
                {
                    "id": "f-none-location",
                    "rule_id": "rule-none-loc",
                    "severity": "INFO",
                    "location": None,
                },
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        results = sarif_doc["runs"][0]["results"]
        assert len(results) == 4
        for r in results:
            region = r["locations"][0]["physicalLocation"]["region"]
            # SARIF requires startLine >= 1
            assert region["startLine"] >= 1
            assert region["endLine"] >= region["startLine"]

    def test_sarif_extreme_line_numbers(self, sarif_schema: dict[str, Any]):
        """Verify handling of extreme line numbers (huge integers, negative values)."""
        report = {
            "job_id": "extreme-lines-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-huge",
                    "rule_id": "r-huge",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "huge.c",
                        "start_line": 2147483647,
                        "end_line": 2147483647,
                    },
                },
                {
                    "id": "f-negative",
                    "rule_id": "r-negative",
                    "severity": "LOW",
                    "location": {
                        "file_path": "neg.py",
                        "start_line": -100,
                        "end_line": -50,
                    },
                },
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        results = sarif_doc["runs"][0]["results"]
        # Negative startLine must be clamped to >= 1 per SARIF schema
        assert results[1]["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1

    def test_sarif_empty_snippet_contexts(self, sarif_schema: dict[str, Any]):
        """Verify findings with empty, null, or whitespace snippets conform to schema."""
        report = {
            "job_id": "empty-snippets-test",
            "status": "done",
            "findings": [
                {"id": "f1", "rule_id": "r1", "location": {"file_path": "a.py"}, "snippet": None},
                {"id": "f2", "rule_id": "r2", "location": {"file_path": "b.py"}, "snippet": {}},
                {"id": "f3", "rule_id": "r3", "location": {"file_path": "c.py"}, "snippet": {"lines": [], "raw_content": ""}},
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        results = sarif_doc["runs"][0]["results"]
        assert len(results) == 3
        for r in results:
            region = r["locations"][0]["physicalLocation"]["region"]
            # If raw_content is empty, snippet object should be omitted from region
            if "snippet" in region:
                assert region["snippet"]["text"] != ""

    def test_sarif_column_order_inverted_bounds_clamped_on_same_line(self, sarif_schema: dict[str, Any]):
        """OASIS SARIF 2.1.0 §3.30.2: When startLine == endLine, endColumn must be >= startColumn."""
        report = {
            "job_id": "inverted-col-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-inv-cols",
                    "rule_id": "r-col-order",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "src/parser.py",
                        "start_line": 42,
                        "end_line": 42,
                        "start_column": 80,
                        "end_column": 15,
                    },
                }
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        region = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert region["endLine"] == 42
        assert region["startColumn"] == 80
        # Invariant: endColumn must be clamped to max(start_column, end_column) == 80
        assert region["endColumn"] >= region["startColumn"]
        assert region["endColumn"] == 80

    def test_sarif_column_bounds_multi_line_retains_end_column(self, sarif_schema: dict[str, Any]):
        """OASIS SARIF 2.1.0 §3.30.2: When startLine < endLine, endColumn is permitted to be < startColumn."""
        report = {
            "job_id": "multi-line-col-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-multi-col",
                    "rule_id": "r-multi-col",
                    "severity": "MEDIUM",
                    "location": {
                        "file_path": "src/multi.py",
                        "start_line": 10,
                        "end_line": 12,
                        "start_column": 50,
                        "end_column": 10,
                    },
                }
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        region = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["endLine"] == 12
        assert region["startColumn"] == 50
        assert region["endColumn"] == 10

    def test_sarif_negative_and_none_column_bounds(self, sarif_schema: dict[str, Any]):
        """Columns <= 0 or None must omit endColumn and clamp startColumn >= 1."""
        report = {
            "job_id": "edge-col-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-neg-col",
                    "rule_id": "r-neg-col",
                    "severity": "LOW",
                    "location": {
                        "file_path": "src/edge.py",
                        "start_line": 5,
                        "end_line": 5,
                        "start_column": -10,
                        "end_column": 0,
                    },
                },
                {
                    "id": "f-none-col",
                    "rule_id": "r-none-col",
                    "severity": "INFO",
                    "location": {
                        "file_path": "src/edge.py",
                        "start_line": 7,
                        "end_line": 7,
                        "start_column": 12,
                        "end_column": None,
                    },
                },
            ],
        }

        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)

        results = sarif_doc["runs"][0]["results"]
        # f-neg-col: startColumn clamped to >= 1, endColumn omitted because <= 0
        reg0 = results[0]["locations"][0]["physicalLocation"]["region"]
        assert reg0["startColumn"] >= 1
        assert "endColumn" not in reg0

        # f-none-col: endColumn omitted
        reg1 = results[1]["locations"][0]["physicalLocation"]["region"]
        assert reg1["startColumn"] == 12
        assert "endColumn" not in reg1


# =========================================================================
# 3. HTML Exporter Adversarial Tests
# =========================================================================

class TestHtmlExporterAdversarial:
    def test_html_air_gapped_self_contained(self):
        """Verify zero external http/https resource URLs (images, fonts, scripts, stylesheets)."""
        report = {
            "job_id": "self-contained-test",
            "status": "done",
            "summary": {"total_findings": 0},
            "findings": [],
        }

        html_str = export_html(report)

        # Must have inline <style>
        assert "<style>" in html_str
        assert "</style>" in html_str

        # Forbidden external resource references
        assert not re.search(r'<link[^>]+href=["\']https?://', html_str, re.IGNORECASE)
        assert not re.search(r'<script[^>]+src=["\']https?://', html_str, re.IGNORECASE)
        assert not re.search(r'url\(["\']?https?://', html_str, re.IGNORECASE)
        assert not re.search(r'<img[^>]+src=["\']https?://', html_str, re.IGNORECASE)

    def test_html_xss_escaping_in_all_fields(self):
        """Probe for XSS vulnerabilities across titles, descriptions, snippets, and rule IDs."""
        xss_payloads = [
            "<script>alert('xss-1')</script>",
            '"><img src=x onerror=alert("xss-2")>',
            "'-alert(1)-'",
            "<svg/onload=alert('xss-3')>",
            "javascript:alert('xss-4')",
            '<iframe src="javascript:alert(1)"></iframe>',
        ]

        report = {
            "job_id": "<script>alert('job')</script>",
            "target_name": '"><svg onload=alert("target")>',
            "status": "done",
            "summary": {
                "total_findings": len(xss_payloads),
                "by_severity": {"HIGH": len(xss_payloads)},
                "by_owasp": {"A03:2021-Injection": len(xss_payloads)},
            },
            "findings": [
                {
                    "id": f"xss-finding-{i}",
                    "rule_id": f"rule-<payload>-{i}",
                    "title": payload,
                    "description": f"Vulnerability detail with malicious payload: {payload}",
                    "severity": "HIGH",
                    "location": {
                        "file_path": f"src/<script>{i}.py",
                        "start_line": 10,
                        "end_line": 12,
                    },
                    "snippet": {
                        "file_path": f"src/<script>{i}.py",
                        "start_line": 8,
                        "end_line": 14,
                        "lines": [
                            {"line_number": 10, "content": f"evil_code({payload})", "is_target": True}
                        ],
                    },
                }
                for i, payload in enumerate(xss_payloads)
            ],
        }

        html_str = export_html(report)

        # Verify no raw unescaped script, img onerror, or svg onload tags exist
        assert "<script>alert(" not in html_str
        assert "<img src=x onerror=" not in html_str
        assert "<svg/onload=" not in html_str
        assert '<iframe src="javascript' not in html_str
        assert "<svg onload=" not in html_str

        # Verify entity escaped versions are present
        assert "&lt;script&gt;alert(" in html_str or "&lt;script&gt;" in html_str
        assert "&quot;&gt;&lt;img" in html_str or "&lt;img" in html_str

    def test_html_xss_in_severity_attribute(self):
        """Adversarial challenge: probe whether unescaped severity values allow HTML attribute breakout."""
        xss_severity_report = {
            "job_id": "xss-sev-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-xss-sev",
                    "rule_id": "r1",
                    "title": "Clean title",
                    "description": "Clean desc",
                    "severity": 'CRITICAL"><script>alert("xss-in-sev")</script>',
                    "location": {"file_path": "a.py", "start_line": 1},
                }
            ],
        }
        html_str = export_html(xss_severity_report)
        # Attribute breakout check
        if '<script>alert("xss-in-sev")</script>' in html_str:
            pytest.fail(
                "XSS injection detected via unescaped finding severity: "
                "html_exporter.py injects sev_badge_cls directly into class attribute without escaping."
            )

    def test_html_responsive_layout(self):
        """Verify HTML report includes responsive CSS media query breakpoints."""
        html_str = export_html({"job_id": "resp-test", "status": "done", "findings": []})
        assert "@media" in html_str
        assert "max-width" in html_str or "min-width" in html_str

    def test_html_print_stylesheet_rules(self):
        """Check for print stylesheet rules (@media print) for printable security audit reports."""
        html_str = export_html({"job_id": "print-test", "status": "done", "findings": []})
        assert "@media print" in html_str
        assert "page-break-inside: avoid" in html_str or "break-inside: avoid" in html_str
        assert "#ffffff" in html_str

    def test_html_xss_in_start_and_end_line(self):
        """Adversarial challenge: verify malicious HTML/script tags in start_line and end_line are escaped."""
        xss_start = "<script>alert(1)</script>"
        xss_end = '"><svg onload=alert(2)>'
        report = {
            "job_id": "xss-lines-job",
            "status": "done",
            "findings": [
                {
                    "id": "f-xss-line",
                    "rule_id": "r-line-xss",
                    "title": "Clean Title",
                    "description": "Clean Description",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "app/core/vuln.py",
                        "start_line": xss_start,
                        "end_line": xss_end,
                    },
                    "snippet": {
                        "file_path": "app/core/vuln.py",
                        "start_line": xss_start,
                        "end_line": xss_end,
                        "lines": [
                            {"line_number": 1, "content": "x = untrusted_input()", "is_target": True}
                        ],
                    },
                }
            ],
        }

        html_str = export_html(report)

        # Raw executable payloads must never appear unescaped in HTML output
        assert "<script>alert(1)</script>" not in html_str
        assert "<svg onload=alert(2)>" not in html_str
        assert "<script>" not in html_str
        assert "<svg" not in html_str

        # Either properly escaped entity or numeric coercion fallback must be present
        assert ("&lt;script&gt;alert(1)&lt;/script&gt;" in html_str or "1" in html_str)

    def test_html_snippet_string_line_numbers(self):
        """Verify snippet line numbers as strings (e.g. '42') or None do not crash the HTML exporter."""
        report = {
            "job_id": "snippet-line-types-job",
            "status": "done",
            "findings": [
                {
                    "id": "f-str-lno",
                    "rule_id": "r-str-lno",
                    "title": "String Line Number Finding",
                    "severity": "HIGH",
                    "location": {"file_path": "test.py", "start_line": "42"},
                    "snippet": {
                        "file_path": "test.py",
                        "start_line": "40",
                        "end_line": "45",
                        "lines": [
                            {"line_number": "42", "content": "vuln_call()", "is_target": True},
                            {"line_number": None, "content": "# line number is None", "is_target": False},
                            {"line_number": "N/A", "content": "# non-numeric string", "is_target": False},
                        ],
                    },
                },
                {
                    "id": "f-raw-lines",
                    "rule_id": "r-raw-lines",
                    "title": "Raw String Line Finding",
                    "severity": "MEDIUM",
                    "location": {"file_path": "plain.py", "start_line": 1},
                    "snippet": {
                        "file_path": "plain.py",
                        "lines": [
                            "raw string line without dict structure",
                        ],
                        "raw_content": "raw string line without dict structure",
                    },
                },
            ],
        }

        # Must generate valid HTML string without raising ValueError or TypeError
        html_str = export_html(report)
        assert isinstance(html_str, str)
        assert len(html_str) > 500
        assert "vuln_call()" in html_str
        assert "String Line Number Finding" in html_str


# =========================================================================
# 4. PDF Exporter Adversarial Tests
# =========================================================================

class TestPdfExporterAdversarial:
    def test_pdf_binary_structure_and_eof(self):
        """Verify binary PDF structure begins with %PDF- and ends with valid %%EOF marker."""
        report = {
            "job_id": "pdf-struct-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-pdf-1",
                    "rule_id": "r-pdf-1",
                    "title": "Sample Finding",
                    "description": "Standard finding description.",
                    "severity": "MEDIUM",
                    "location": {"file_path": "test.py", "start_line": 1},
                }
            ],
        }

        pdf_bytes = export_pdf(report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-"), "PDF does not start with %PDF- header"
        # %%EOF should be within the last 1024 bytes of a conforming PDF
        tail = pdf_bytes[-1024:]
        assert b"%%EOF" in tail, "PDF does not contain valid %%EOF marker in tail"

    def test_pdf_zero_findings_clean_report(self):
        """Verify clean report with 0 findings renders cleanly without error."""
        clean_report = {
            "job_id": "pdf-clean-job",
            "status": "done",
            "summary": {"total_findings": 0},
            "findings": [],
        }

        pdf_bytes = export_pdf(clean_report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 500

    def test_pdf_adversarial_special_characters_and_xml_tags(self):
        """
        Adversarial challenge: Source code and finding descriptions frequently contain
        angle brackets, C++ templates, unclosed tags, or HTML code.
        ReportLab must NOT crash with ValueError (paraparser: syntax error).
        """
        special_strings = [
            "Vector<int> buffer overflow",
            "Consider using std::vector<std::string> or List<T>",
            "Found <script src='foo.js'> injection point",
            "Condition if (a < b && c > d) causes underflow",
            "AT&T & Co <special_vendor>",
            "Tag with unclosed angle bracket <unclosed tag",
            "Malformed <b>mismatched</i> formatting",
            '"><img src=x onerror=alert(1)>',
        ]

        for s in special_strings:
            report = {
                "job_id": "special-char-job",
                "status": "done",
                "findings": [
                    {
                        "id": "f-spec",
                        "rule_id": f"rule-{s[:10]}",
                        "title": f"Title with {s}",
                        "description": f"Description containing {s}",
                        "severity": "HIGH",
                        "location": {"file_path": "module.cpp", "start_line": 10},
                        "snippet": {
                            "file_path": "module.cpp",
                            "start_line": 9,
                            "end_line": 11,
                            "lines": [
                                {"line_number": 10, "content": f"code = {s};", "is_target": True}
                            ],
                        },
                    }
                ],
            }

            try:
                pdf_bytes = export_pdf(report)
                assert pdf_bytes.startswith(b"%PDF-")
            except ValueError as exc:
                pytest.fail(
                    f"ReportLab CRASHED on string {s!r}: {exc}. "
                    f"ReportLab Paragraph strings must escape '<', '>', '&' XML characters."
                )

    def test_pdf_extreme_text_lengths_and_no_wrap_overflow(self):
        """Test PDF table formatting and text flow with extreme unbroken strings and large descriptions."""
        huge_word = "A" * 500
        huge_desc = "Long description block. " * 300
        report = {
            "job_id": "pdf-huge-text",
            "status": "done",
            "findings": [
                {
                    "id": "f-huge",
                    "rule_id": "r-huge",
                    "title": f"Unbroken title {huge_word[:80]}",
                    "description": huge_desc,
                    "severity": "CRITICAL",
                    "location": {
                        "file_path": f"/a/very/deep/nested/path/{'dir/' * 15}vulnerable_file.py",
                        "start_line": 100,
                    },
                }
            ],
        }

        pdf_bytes = export_pdf(report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2000


# =========================================================================
# 5. Export Endpoint Adversarial Tests (/api/reports/{id}/export)
# =========================================================================

class TestExportEndpointAdversarial:
    @pytest.fixture
    def seeded_job_suite(self) -> dict[str, str]:
        queue = get_job_queue()
        ids = {}

        # 1. Done job with findings
        done_id = "test-endpoint-done-001"
        queue._jobs[done_id] = JobRecord(
            job_id=done_id,
            status=JobStatus.DONE,
            stage=JobStage.COMPLETED,
            progress=100,
            report={
                "job_id": done_id,
                "id": done_id,
                "status": "done",
                "summary": {"total_findings": 1, "by_severity": {"HIGH": 1}},
                "findings": [
                    {
                        "id": "f1",
                        "rule_id": "r1",
                        "severity": "HIGH",
                        "title": "SQLi",
                        "description": "SQL injection vulnerability",
                        "location": {"file_path": "db.py", "start_line": 10},
                    }
                ],
            },
        )
        ids["done"] = done_id

        # 2. Queued job
        queued_id = "test-endpoint-queued-002"
        queue._jobs[queued_id] = JobRecord(
            job_id=queued_id,
            status=JobStatus.QUEUED,
            stage=JobStage.QUEUED,
            progress=0,
        )
        ids["queued"] = queued_id

        # 3. Running job
        running_id = "test-endpoint-running-003"
        queue._jobs[running_id] = JobRecord(
            job_id=running_id,
            status=JobStatus.RUNNING,
            stage=JobStage.SCANNING,
            progress=60,
        )
        ids["running"] = running_id

        # 4. Failed job
        failed_id = "test-endpoint-failed-004"
        queue._jobs[failed_id] = JobRecord(
            job_id=failed_id,
            status=JobStatus.FAILED,
            stage=JobStage.FAILED,
            progress=100,
            error="Scanner execution timed out after 300s",
        )
        ids["failed"] = failed_id

        return ids

    def test_export_unknown_format_returns_400(self, client: TestClient, seeded_job_suite: dict[str, str]):
        done_id = seeded_job_suite["done"]
        response = client.get(f"/api/reports/{done_id}/export?format=unknown_format_xyz")
        assert response.status_code == 400
        assert "Unsupported export format" in response.json()["detail"]
        assert "json, sarif, html, pdf" in response.json()["detail"].lower()

    def test_export_case_insensitivity_and_whitespace(self, client: TestClient, seeded_job_suite: dict[str, str]):
        done_id = seeded_job_suite["done"]
        test_variations = [
            ("JSON", "application/json", ".json"),
            ("  sarif  ", "application/sarif+json", ".sarif"),
            ("HtMl", "text/html", ".html"),
            ("PDF", "application/pdf", ".pdf"),
        ]

        for fmt_param, expected_mime, expected_ext in test_variations:
            response = client.get(f"/api/reports/{done_id}/export?format={fmt_param}")
            assert response.status_code == 200, f"Failed on format param '{fmt_param}'"
            assert expected_mime in response.headers["content-type"]
            cd = response.headers["content-disposition"]
            assert f'attachment; filename="securescan-report-{done_id}{expected_ext}"' in cd

    def test_export_in_flight_job_returns_409(self, client: TestClient, seeded_job_suite: dict[str, str]):
        queued_id = seeded_job_suite["queued"]
        running_id = seeded_job_suite["running"]

        res_q = client.get(f"/api/reports/{queued_id}/export?format=json")
        assert res_q.status_code == 409
        assert "not ready" in res_q.json()["detail"].lower()

        res_r = client.get(f"/api/reports/{running_id}/export?format=sarif")
        assert res_r.status_code == 409
        assert "not ready" in res_r.json()["detail"].lower()

    def test_export_non_existent_job_returns_404(self, client: TestClient):
        response = client.get("/api/reports/non-existent-job-uuid-000000/export?format=json")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_export_failed_job_returns_422(self, client: TestClient, seeded_job_suite: dict[str, str]):
        failed_id = seeded_job_suite["failed"]
        response = client.get(f"/api/reports/{failed_id}/export?format=html")
        assert response.status_code == 422
        assert "Scan failed" in response.json()["detail"]

    def test_content_disposition_header_specification(self, client: TestClient, seeded_job_suite: dict[str, str]):
        """Verify RFC 6266 Content-Disposition header with exact quoted filename."""
        done_id = seeded_job_suite["done"]
        for fmt, ext in [("json", "json"), ("sarif", "sarif"), ("html", "html"), ("pdf", "pdf")]:
            res = client.get(f"/api/reports/{done_id}/export?format={fmt}")
            assert res.status_code == 200
            cd = res.headers.get("content-disposition")
            assert cd is not None
            expected = f'attachment; filename="securescan-report-{done_id}.{ext}"'
            assert cd == expected


# =========================================================================
# 6. Multi-Format Cross-Cutting Exporters Adversarial Tests
# =========================================================================

class TestMultiFormatExportersAdversarial:
    def test_exporters_cwe_ids_none_handled_safely(self, sarif_schema: dict[str, Any]):
        """Verify all 4 exporters (JSON, SARIF, HTML, PDF) survive findings with cwe_ids=None."""
        report = {
            "job_id": "none-cwe-job",
            "status": "done",
            "summary": {
                "total_findings": 2,
                "by_severity": {"HIGH": 1, "MEDIUM": 1},
            },
            "findings": [
                {
                    "id": "f-none-cwe",
                    "rule_id": "r-null-cwe",
                    "title": "Finding with None CWE",
                    "description": "Vulnerability without mapped CWE IDs.",
                    "severity": "HIGH",
                    "cwe_ids": None,
                    "location": {"file_path": "src/app.py", "start_line": 15},
                },
                {
                    "id": "f-empty-cwe",
                    "rule_id": "r-empty-cwe",
                    "title": "Finding with Empty CWE List",
                    "severity": "MEDIUM",
                    "cwe_ids": [],
                    "location": {"file_path": "src/util.py", "start_line": 20},
                },
            ],
        }

        # 1. JSON Exporter
        json_str = export_json(report)
        json_data = json.loads(json_str)
        assert json_data["job_id"] == "none-cwe-job"
        assert len(json_data["findings"]) == 2

        # 2. SARIF Exporter
        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        sarif_str = export_sarif(report)
        assert "r-null-cwe" in sarif_str
        assert len(sarif_doc["runs"][0]["results"]) == 2

        # 3. HTML Exporter
        html_str = export_html(report)
        assert isinstance(html_str, str)
        assert "Finding with None CWE" in html_str

        # 4. PDF Exporter
        pdf_bytes = export_pdf(report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_exporters_float_infinity_and_nan_coordinates_survival(self, sarif_schema: dict[str, Any]):
        """Verify all exporters survive float('inf'), -float('inf'), and float('nan') without OverflowError."""
        inf_report = {
            "job_id": "float-inf-stress-test",
            "status": "done",
            "summary": {
                "total_findings": float("inf"),
                "by_severity": {
                    "CRITICAL": float("inf"),
                    "HIGH": -float("inf"),
                    "MEDIUM": float("nan"),
                    "LOW": 0,
                    "INFO": 0,
                },
                "by_owasp": {
                    "A01:2021-Broken Access Control": float("inf"),
                },
            },
            "findings": [
                {
                    "id": "f-inf-coords",
                    "rule_id": "r-inf-coords",
                    "title": "Float Infinity Finding",
                    "description": "Location with positive and negative infinity and NaN numbers.",
                    "severity": "CRITICAL",
                    "location": {
                        "file_path": "math_ops.py",
                        "start_line": float("inf"),
                        "end_line": float("inf"),
                        "start_column": float("inf"),
                        "end_column": float("inf"),
                    },
                    "snippet": {
                        "file_path": "math_ops.py",
                        "start_line": float("inf"),
                        "end_line": float("inf"),
                        "lines": [
                            {"line_number": float("inf"), "content": "res = 1 / 0", "is_target": True},
                            {"line_number": -float("inf"), "content": "# neg inf line", "is_target": False},
                            {"line_number": float("nan"), "content": "# nan line", "is_target": False},
                        ],
                    },
                },
            ],
        }

        # 1. JSON Exporter
        json_str = export_json(inf_report)
        assert isinstance(json_str, str)
        assert "float-inf-stress-test" in json_str

        # 2. SARIF Exporter
        sarif_doc = generate_sarif_dict(inf_report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        region = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["endLine"] >= region["startLine"]
        assert region["startColumn"] >= 1
        if "endColumn" in region:
            assert region["endColumn"] >= region["startColumn"]

        # 3. HTML Exporter
        html_str = export_html(inf_report)
        assert isinstance(html_str, str)
        assert "Float Infinity Finding" in html_str

        # 4. PDF Exporter
        pdf_bytes = export_pdf(inf_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes[-1024:]

    def test_exporters_malformed_snippet_types_and_lines(self, sarif_schema: dict[str, Any]):
        """Verify exporters handle raw string snippets, primitive snippets, non-list lines, and mixed lines."""
        malformed_report = {
            "job_id": "malformed-snippet-test",
            "status": "done",
            "findings": [
                {
                    "id": "f-raw-str-snippet",
                    "rule_id": "r-raw-snippet",
                    "title": "Raw String Snippet Finding",
                    "severity": "HIGH",
                    "location": {"file_path": "raw.py", "start_line": 10},
                    "snippet": "def raw_function():\n    pass",
                },
                {
                    "id": "f-primitive-snippet",
                    "rule_id": "r-prim-snippet",
                    "title": "Primitive Integer Snippet Finding",
                    "severity": "MEDIUM",
                    "location": {"file_path": "prim.py", "start_line": 20},
                    "snippet": 12345,
                },
                {
                    "id": "f-non-list-lines",
                    "rule_id": "r-non-list-lines",
                    "title": "Non-list Lines Finding",
                    "severity": "LOW",
                    "location": {"file_path": "nonlist.py", "start_line": 30},
                    "snippet": {
                        "file_path": "nonlist.py",
                        "lines": 99999,
                    },
                },
                {
                    "id": "f-heterogeneous-lines",
                    "rule_id": "r-hetero-lines",
                    "title": "Heterogeneous Lines Finding",
                    "severity": "INFO",
                    "location": {"file_path": "hetero.py", "start_line": 40},
                    "snippet": {
                        "file_path": "hetero.py",
                        "lines": [
                            "pure string line",
                            1001,
                            None,
                            {"line_number": 42, "content": "valid dict line", "is_target": True},
                            {"line_number": None, "content": "dict with none line_number"},
                            {"unexpected_key": "no content or line_number"},
                        ],
                    },
                },
            ],
        }

        # 1. JSON Exporter
        json_str = export_json(malformed_report)
        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert len(data["findings"]) == 4

        # 2. SARIF Exporter
        sarif_doc = generate_sarif_dict(malformed_report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        assert len(sarif_doc["runs"][0]["results"]) == 4

        # 3. HTML Exporter
        html_str = export_html(malformed_report)
        assert isinstance(html_str, str)
        assert "Raw String Snippet Finding" in html_str
        assert "valid dict line" in html_str

        # 4. PDF Exporter
        pdf_bytes = export_pdf(malformed_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
