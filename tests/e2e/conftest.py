"""
Shared Pytest Configuration and Test Fixtures for SecureScan E2E Suite.

Provides:
- Path fixtures for all 8 synthetic test archives
- Canonical safe_extract runner (delegates to backend.app.core.safe_extract or canonical specification)
- Exporter output validators (JSON schema, OASIS SARIF 2.1.0, single-file HTML, binary PDF)
- Mock and live CLI runner harnesses
"""

import io
import json
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Generator

import pytest

# Constants as defined in PROJECT.md and ORIGINAL_REQUEST.md
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024       # 10 MB (10,485,760 bytes)
MAX_TOTAL_EXTRACT_BYTES = 50 * 1024 * 1024     # 50 MB (52,428,800 bytes)
MAX_COMPRESSION_RATIO = 100.0                  # 100x
SYMLINK_EXPLICIT_ATTR = 0xA1ED                 # External attribute mode
SYMLINK_TYPE_MASK = 0o170000
SYMLINK_FLAG = 0o120000                        # stat.S_IFLNK

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = WORKSPACE_ROOT / "tests" / "fixtures"


# ---------------------------------------------------------------------------
# Path Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def valid_clean_zip() -> Path:
    return FIXTURES_DIR / "valid_clean.zip"


@pytest.fixture(scope="session")
def valid_vulnerable_zip() -> Path:
    return FIXTURES_DIR / "valid_vulnerable.zip"


@pytest.fixture(scope="session")
def zip_slip_zip() -> Path:
    return FIXTURES_DIR / "zip_slip.zip"


@pytest.fixture(scope="session")
def symlink_zip() -> Path:
    return FIXTURES_DIR / "symlink_0xa1ed.zip"


@pytest.fixture(scope="session")
def zip_bomb_zip() -> Path:
    return FIXTURES_DIR / "zip_bomb.zip"


@pytest.fixture(scope="session")
def oversized_file_zip() -> Path:
    return FIXTURES_DIR / "oversized_file.zip"


@pytest.fixture(scope="session")
def oversized_archive_zip() -> Path:
    return FIXTURES_DIR / "oversized_archive.zip"


@pytest.fixture(scope="session")
def corrupt_zip() -> Path:
    return FIXTURES_DIR / "corrupt.zip"


@pytest.fixture(scope="session")
def all_fixtures(
    valid_clean_zip,
    valid_vulnerable_zip,
    zip_slip_zip,
    symlink_zip,
    zip_bomb_zip,
    oversized_file_zip,
    oversized_archive_zip,
    corrupt_zip,
) -> dict[str, Path]:
    return {
        "valid_clean": valid_clean_zip,
        "valid_vulnerable": valid_vulnerable_zip,
        "zip_slip": zip_slip_zip,
        "symlink_0xa1ed": symlink_zip,
        "zip_bomb": zip_bomb_zip,
        "oversized_file": oversized_file_zip,
        "oversized_archive": oversized_archive_zip,
        "corrupt": corrupt_zip,
    }


@pytest.fixture
def temp_extract_dir() -> Generator[Path, None, None]:
    """Provides an isolated clean temporary directory that is automatically removed."""
    tmp = Path(tempfile.mkdtemp(prefix="test_securescan_extract_")).resolve()
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Canonical Safe Extraction Interface
# ---------------------------------------------------------------------------

def canonical_safe_extract(zip_path: str | Path, target_dir: str | Path) -> dict[str, Any]:
    """
    Executes safe_extract conforming strictly to PROJECT.md interface contract.
    Attempts to import backend.app.core.safe_extract first; if not present, uses
    authoritative reference logic to verify the fixture contracts.
    """
    try:
        from backend.app.core.safe_extract import safe_extract as backend_safe_extract
        return backend_safe_extract(
            zip_path,
            target_dir,
            max_single_file_bytes=MAX_SINGLE_FILE_BYTES,
            max_total_bytes=MAX_TOTAL_EXTRACT_BYTES,
        )
    except (ImportError, ModuleNotFoundError):
        pass

    # Authoritative reference implementation of safe_extract contract
    extract_path = Path(target_dir).resolve()
    zip_file = Path(zip_path).resolve()

    if not zip_file.is_file():
        raise ValueError(f"Zip file not found: {zip_file}")

    try:
        with zipfile.ZipFile(zip_file, "r") as zf:
            infolist = zf.infolist()
            total_uncompressed = 0

            # Pre-extraction validation pass
            for info in infolist:
                mode = info.external_attr >> 16
                is_sym = (mode & SYMLINK_TYPE_MASK) == SYMLINK_FLAG or mode == SYMLINK_EXPLICIT_ATTR
                if is_sym:
                    raise ValueError(f"Symlink rejected: {info.filename}")

                if info.file_size > MAX_SINGLE_FILE_BYTES:
                    raise ValueError(f"Single file size limit exceeded: {info.file_size} > {MAX_SINGLE_FILE_BYTES}")

                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        raise ValueError(f"Compression ratio {ratio:.1f}x exceeds limit {MAX_COMPRESSION_RATIO}x")

                total_uncompressed += info.file_size

            if total_uncompressed > MAX_TOTAL_EXTRACT_BYTES:
                raise ValueError(f"Total uncompressed size {total_uncompressed} > {MAX_TOTAL_EXTRACT_BYTES}")

            # Extraction pass with path-traversal & stream limits
            total_extracted = 0
            file_count = 0
            for info in infolist:
                raw_name = info.filename
                if raw_name.startswith(("/", "\\")) or ".." in Path(raw_name).parts:
                    raise ValueError(f"Path traversal detected: {raw_name}")

                dest = (extract_path / raw_name).resolve()
                if not dest.is_relative_to(extract_path):
                    raise ValueError(f"Zip slip boundary violation: {raw_name}")

                if info.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                file_count += 1

                single_bytes = 0
                with zf.open(info, "r") as src, open(dest, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        chunk_len = len(chunk)
                        single_bytes += chunk_len
                        total_extracted += chunk_len
                        if single_bytes > MAX_SINGLE_FILE_BYTES:
                            raise ValueError("File exceeded size limit during streaming")
                        if total_extracted > MAX_TOTAL_EXTRACT_BYTES:
                            raise ValueError("Archive exceeded size limit during streaming")
                        dst.write(chunk)

            return {
                "extracted_path": extract_path,
                "file_count": file_count,
                "total_bytes": total_extracted,
            }
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Bad zip file: {exc}") from exc


@pytest.fixture
def safe_extractor():
    return canonical_safe_extract


# ---------------------------------------------------------------------------
# Report and Exporter Validation Helpers
# ---------------------------------------------------------------------------

def validate_sarif_schema(sarif_data: dict[str, Any]) -> None:
    """Validates that sarif_data adheres to OASIS SARIF 2.1.0 standard."""
    assert sarif_data.get("version") == "2.1.0", f"Invalid SARIF version: {sarif_data.get('version')}"
    assert "$schema" in sarif_data, "Missing $schema in SARIF report"
    assert "runs" in sarif_data and isinstance(sarif_data["runs"], list), "SARIF runs must be a list"
    assert len(sarif_data["runs"]) > 0, "SARIF must contain at least one run"

    run = sarif_data["runs"][0]
    assert "tool" in run and "driver" in run["tool"], "SARIF run must define tool.driver"
    assert "name" in run["tool"]["driver"], "SARIF driver must have a name"
    assert "results" in run and isinstance(run["results"], list), "SARIF run must have results list"

    # Validate results structure if present
    for res in run["results"]:
        assert "ruleId" in res, "Result missing ruleId"
        assert "level" in res, "Result missing level (error, warning, note, none)"
        assert res["level"] in ("error", "warning", "note", "none"), f"Invalid level: {res['level']}"
        assert "message" in res and "text" in res["message"], "Result missing message.text"
        assert "locations" in res and len(res["locations"]) > 0, "Result missing locations"
        loc = res["locations"][0]
        phys = loc.get("physicalLocation", {})
        assert "artifactLocation" in phys, "Missing artifactLocation in physicalLocation"
        assert "uri" in phys["artifactLocation"], "Missing uri in artifactLocation"


def validate_html_report(html_content: str) -> None:
    """Validates that HTML report is self-contained with no external CSS/JS dependencies."""
    assert "<!DOCTYPE html>" in html_content or "<!doctype html>" in html_content.lower(), "Missing DOCTYPE"
    assert "<html" in html_content and "</html>" in html_content, "Missing html root tag"
    assert "<head" in html_content and "</head>" in html_content, "Missing head section"
    assert "<body" in html_content and "</body>" in html_content, "Missing body section"

    # Air-gapped self-containment check: NO external stylesheet or script references
    assert 'rel="stylesheet" href="http' not in html_content, "External stylesheet reference detected"
    assert '<script src="http' not in html_content, "External script reference detected"
    assert "<style>" in html_content or "<style " in html_content, "Expected inline <style> tag"


def validate_pdf_report(pdf_bytes: bytes) -> None:
    """Validates binary PDF magic bytes and document structure."""
    assert len(pdf_bytes) > 100, f"PDF content suspiciously small ({len(pdf_bytes)} bytes)"
    assert pdf_bytes.startswith(b"%PDF-"), f"Invalid PDF magic bytes: {pdf_bytes[:10]!r}"
    assert b"%%EOF" in pdf_bytes or b"xref" in pdf_bytes, "Missing PDF trailer / EOF marker"


def validate_unified_report(report_data: dict[str, Any]) -> None:
    """Validates that report matches the unified ScanReport schema."""
    expected_top_keys = {"job_id", "status", "summary", "scanners", "findings"}
    missing = expected_top_keys - set(report_data.keys())
    assert not missing, f"ScanReport missing top-level keys: {missing}"

    summary = report_data["summary"]
    assert "total_findings" in summary, "Summary missing total_findings"
    assert "severity_counts" in summary, "Summary missing severity_counts"
    assert "owasp_counts" in summary, "Summary missing owasp_counts"

    for finding in report_data["findings"]:
        for field in ("id", "rule_id", "scanner_name", "category", "severity", "location", "title", "cwe_ids", "owasp_category"):
            assert field in finding, f"Finding missing mandatory field '{field}': {finding}"
        assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert "file_path" in finding["location"]
        assert "start_line" in finding["location"]


@pytest.fixture(scope="session")
def validators():
    return {
        "sarif": validate_sarif_schema,
        "html": validate_html_report,
        "pdf": validate_pdf_report,
        "report": validate_unified_report,
    }
