"""
Unit tests for Code Context Extractor (backend/app/core/context_extractor.py).
Tests snippet window slicing, boundary clamping, path traversal defense,
UTF-8/Latin-1 encoding fallback, binary rejection, and finding enrichment.
"""

import tempfile
from pathlib import Path

import pytest

from app.core.context_extractor import (
    enrich_findings_with_context,
    enrich_report_with_snippets,
    extract_code_snippet,
)
from app.models.report import (
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    Severity,
)


class TestContextExtractor:
    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            # Create a 20-line source file
            src_file = base / "app.py"
            src_file.write_text("\n".join([f"line_{i}" for i in range(1, 21)]), encoding="utf-8")
            yield base

    def test_standard_context_extraction(self, workspace):
        # Target line 10 -> window lines 5..15 (11 lines total)
        snippet = extract_code_snippet(workspace, "app.py", start_line=10, end_line=10, context_lines=5)
        assert snippet is not None
        assert snippet.start_line == 5
        assert snippet.end_line == 15
        assert len(snippet.lines) == 11

        target_lines = [line for line in snippet.lines if line.is_target]
        assert len(target_lines) == 1
        assert target_lines[0].line_number == 10
        assert target_lines[0].content == "line_10"

    def test_file_start_boundary(self, workspace):
        # Target line 1 -> clamped to lines 1..6
        snippet = extract_code_snippet(workspace, "app.py", start_line=1, end_line=1, context_lines=5)
        assert snippet is not None
        assert snippet.start_line == 1
        assert snippet.end_line == 6
        assert snippet.lines[0].is_target is True

    def test_file_end_boundary(self, workspace):
        # Target line 20 -> clamped to lines 15..20
        snippet = extract_code_snippet(workspace, "app.py", start_line=20, end_line=20, context_lines=5)
        assert snippet is not None
        assert snippet.start_line == 15
        assert snippet.end_line == 20
        assert snippet.lines[-1].is_target is True

    def test_multiline_target_span(self, workspace):
        # Target span lines 10..12 -> window lines 5..17
        snippet = extract_code_snippet(workspace, "app.py", start_line=10, end_line=12, context_lines=5)
        assert snippet is not None
        assert snippet.start_line == 5
        assert snippet.end_line == 17
        targets = [line.line_number for line in snippet.lines if line.is_target]
        assert targets == [10, 11, 12]

    def test_path_traversal_blocked(self, workspace):
        # Path traversal with ../ must return None
        secret_file = workspace.parent / "secret.env"
        secret_file.write_text("SECRET=123", encoding="utf-8")
        try:
            snippet = extract_code_snippet(workspace, "../secret.env", start_line=1, end_line=1)
            assert snippet is None
        finally:
            if secret_file.exists():
                secret_file.unlink()

    def test_encoding_fallback_latin1(self, workspace):
        # File with non-UTF-8 bytes
        latin_file = workspace / "latin.txt"
        latin_file.write_bytes(b"line 1\nCaf\xe9 and na\xefve\nline 3")
        snippet = extract_code_snippet(workspace, "latin.txt", start_line=2, end_line=2)
        assert snippet is not None
        assert "Café and naïve" in snippet.raw_content

    def test_binary_file_rejection(self, workspace):
        # Binary file containing null byte must be rejected
        bin_file = workspace / "binary.bin"
        bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00")
        snippet = extract_code_snippet(workspace, "binary.bin", start_line=1, end_line=1)
        assert snippet is None

    def test_nonexistent_file_handling(self, workspace):
        snippet = extract_code_snippet(workspace, "does_not_exist.py", start_line=1, end_line=1)
        assert snippet is None

    def test_empty_file_handling(self, workspace):
        empty_file = workspace / "empty.py"
        empty_file.write_text("", encoding="utf-8")
        snippet = extract_code_snippet(workspace, "empty.py", start_line=1, end_line=1)
        assert snippet is None

    def test_enrich_findings_batch(self, workspace):
        finding = NormalizedFinding(
            id="test-1",
            rule_id="secureship-js-eval",
            scanner_name="opengrep",
            category=FindingCategory.SAST,
            severity=Severity.HIGH,
            title="Eval",
            description="Eval call",
            location=FindingLocation(file_path="app.py", start_line=10, end_line=10),
        )
        enriched = enrich_findings_with_context([finding], workspace)
        assert enriched[0].snippet_context is not None
        assert enriched[0].snippet_context.start_line == 5
        assert enriched[0].snippet_context.end_line == 15

    def test_enrich_report_with_snippets_dict(self, workspace):
        raw_report = {
            "findings": [
                {
                    "id": "f-dict",
                    "ruleId": "secureship-py-sql",
                    "location": {"filePath": "app.py", "startLine": 10, "endLine": 10},
                    "cweIds": ["CWE-89"],
                    "reachability": "REACHABLE_CALL_PATH",
                }
            ]
        }
        enriched = enrich_report_with_snippets(raw_report, workspace)
        finding = enriched["findings"][0]
        assert "snippetContext" in finding
        assert finding["snippetContext"]["startLine"] == 5
        assert finding["owaspCategory"] == "A03:2021-Injection"
        assert finding["reachability"] == "REACHABLE"
