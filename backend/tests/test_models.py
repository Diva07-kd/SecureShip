"""
Unit tests for Pydantic Models, CWE Normalization, and OWASP Top 10 (2021) Mapping.
(backend/app/models/report.py and backend/app/models/job.py)
"""

import pytest

from app.models.job import JobRecord, JobStage, JobStatus
from app.models.report import (
    CodeSnippet,
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    OwaspCategory,
    ReachabilityVerdict,
    ScannerExecutionSummary,
    ScannerName,
    ScanReport,
    ScanSummary,
    Severity,
    SnippetLine,
    extract_cwe_ids,
    map_cwe_to_owasp,
    normalize_cwe_id,
    normalize_reachability_verdict,
)


class TestSeverityAndEnums:
    def test_severity_ranking_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.INFO <= Severity.HIGH
        assert Severity.LOW < Severity.HIGH
        assert Severity.MEDIUM >= Severity.LOW

    def test_finding_category_values(self):
        expected = {"SAST", "SCA", "SECRET", "IAC", "SUPPLY_CHAIN"}
        assert set(c.value for c in FindingCategory) == expected

    def test_scanner_name_values(self):
        scanner_values = [s.value for s in ScannerName]
        assert "opengrep" in scanner_values
        assert "gitleaks" in scanner_values
        assert "trivy" in scanner_values
        assert "osv-scanner" in scanner_values
        assert "checkov" in scanner_values


class TestCweNormalization:
    def test_normalize_cwe_variations(self):
        assert normalize_cwe_id("CWE-89") == "CWE-89"
        assert normalize_cwe_id("cwe-89") == "CWE-89"
        assert normalize_cwe_id("CWE:89") == "CWE-89"
        assert normalize_cwe_id("CWE 89") == "CWE-89"
        assert normalize_cwe_id("89") == "CWE-89"
        assert normalize_cwe_id("external/cwe/cwe-328") == "CWE-328"
        assert normalize_cwe_id("CWE-89: SQL Injection") == "CWE-89"
        assert normalize_cwe_id("") is None
        assert normalize_cwe_id(None) is None

    def test_extract_cwe_ids_deduplication_and_sorting(self):
        raw = ["CWE-89", "cwe-78", "89", "CWE:502", "CWE-89: SQL Injection"]
        result = extract_cwe_ids(raw)
        # Must deduplicate 89 and sort numerically: 78, 89, 502
        assert result == ["CWE-78", "CWE-89", "CWE-502"]

    def test_extract_cwe_ids_empty(self):
        assert extract_cwe_ids([]) == []
        assert extract_cwe_ids(None) == []


class TestOwaspMapping:
    def test_authoritative_cwe_mapping(self):
        assert map_cwe_to_owasp(["CWE-22"]) == OwaspCategory.A01_2021.value
        assert map_cwe_to_owasp(["CWE-328"]) == OwaspCategory.A02_2021.value
        assert map_cwe_to_owasp(["CWE-89"]) == OwaspCategory.A03_2021.value
        assert map_cwe_to_owasp(["CWE-209"]) == OwaspCategory.A04_2021.value
        assert map_cwe_to_owasp(["CWE-16"]) == OwaspCategory.A05_2021.value
        assert map_cwe_to_owasp(["CWE-937"]) == OwaspCategory.A06_2021.value
        assert map_cwe_to_owasp(["CWE-798"]) == OwaspCategory.A07_2021.value
        assert map_cwe_to_owasp(["CWE-502"]) == OwaspCategory.A08_2021.value
        assert map_cwe_to_owasp(["CWE-117"]) == OwaspCategory.A09_2021.value
        assert map_cwe_to_owasp(["CWE-918"]) == OwaspCategory.A10_2021.value

    def test_rule_keyword_heuristics(self):
        assert map_cwe_to_owasp([], rule_id="secureship-js-sql-concat") == OwaspCategory.A03_2021.value
        assert map_cwe_to_owasp([], rule_id="secureship-py-pickle-load") == OwaspCategory.A08_2021.value
        assert map_cwe_to_owasp([], rule_id="gitleaks-generic-api-key") == OwaspCategory.A07_2021.value
        assert map_cwe_to_owasp([], description="Potential SSRF in http client") == OwaspCategory.A10_2021.value

    def test_category_fallback(self):
        assert map_cwe_to_owasp([], category=FindingCategory.SECRET) == OwaspCategory.A07_2021.value
        assert map_cwe_to_owasp([], category=FindingCategory.SCA) == OwaspCategory.A06_2021.value
        assert map_cwe_to_owasp([], category=FindingCategory.IAC) == OwaspCategory.A05_2021.value
        assert map_cwe_to_owasp([], category="UNKNOWN") == OwaspCategory.UNKNOWN.value


class TestReachabilityNormalization:
    def test_reachability_normalizer(self):
        assert normalize_reachability_verdict("REACHABLE_CALL_PATH") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("REACHABLE_IMPORT") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("REACHABLE") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("UNREACHABLE") == ReachabilityVerdict.UNREACHABLE
        assert normalize_reachability_verdict("UNKNOWN") == ReachabilityVerdict.UNKNOWN
        assert normalize_reachability_verdict(None) == ReachabilityVerdict.UNKNOWN
        assert normalize_reachability_verdict("") == ReachabilityVerdict.UNKNOWN


class TestPydanticModelSerialization:
    def test_camel_and_snake_interoperability(self):
        raw_cli_data = {
            "id": "f-123",
            "ruleId": "secureship-js-eval",
            "scannerName": "opengrep",
            "category": "SAST",
            "severity": "HIGH",
            "title": "Eval Injection",
            "description": "Dynamic eval execution",
            "location": {
                "filePath": "src/eval.js",
                "startLine": 12,
                "endLine": 12,
            },
            "cweIds": ["CWE-95"],
            "reachability": "REACHABLE_CALL_PATH",
        }
        finding = NormalizedFinding.model_validate(raw_cli_data)
        assert finding.rule_id == "secureship-js-eval"
        assert finding.location.file_path == "src/eval.js"
        assert finding.location.start_line == 12

        # Dump to camelCase for API / frontend JSON
        dumped = finding.model_dump(by_alias=True)
        assert dumped["ruleId"] == "secureship-js-eval"
        assert dumped["location"]["filePath"] == "src/eval.js"

    def test_job_record_serialization(self):
        job = JobRecord(
            job_id="job-abc",
            status=JobStatus.RUNNING,
            stage=JobStage.SCANNING,
            progress=45,
            poll_url="/api/jobs/job-abc",
        )
        assert job.job_id == "job-abc"
        assert job.status == JobStatus.RUNNING
        assert job.stage == JobStage.SCANNING

        dumped = job.model_dump(by_alias=True)
        assert dumped["jobId"] == "job-abc"
        assert dumped["pollUrl"] == "/api/jobs/job-abc"
