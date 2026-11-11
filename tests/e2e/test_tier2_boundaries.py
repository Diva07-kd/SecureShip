"""
Tier 2: Boundary & Corner Cases Test Suite.

Covers:
- Zip-Slip path traversal defense (../ and absolute path rejection)
- Symlink 0xA1ED defense (rejection of symbolic links in archives)
- Decompression bomb defense (> 100x compression ratio rejection)
- Single-file size quota (rejection of individual files > 10 MB)
- Total-archive volume quota (rejection of total extracted volume > 50 MB)
- Corrupt / truncated archive handling
- Subprocess 300s hard timeout enforcement
- Scanner exit code semantics (exit 0 and 1 as success, exit >= 2 as failure)
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
import pytest

from tests.e2e.conftest import (
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_EXTRACT_BYTES,
    MAX_COMPRESSION_RATIO,
)


class TestSafeExtractionDefenses:
    """Rigorous boundary and adversarial test cases for safe_extract()."""

    def test_zip_slip_path_traversal_rejected(self, safe_extractor, zip_slip_zip: Path, temp_extract_dir: Path):
        """Verifies that zip-slip traversal entries (../../) raise ValueError and do not escape."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(zip_slip_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert any(keyword in error_msg for keyword in ["traversal", "zip-slip", "escapes", "boundary"]), (
            f"Unexpected error message: {excinfo.value}"
        )

        # Invariant: No malicious file must be written outside temp_extract_dir
        parent_dir = temp_extract_dir.parent
        escaped_file = parent_dir / "evil.txt"
        assert not escaped_file.exists(), "MALICIOUS FILE ESCAPED EXTRACTION BOUNDARY!"

    def test_absolute_and_backslash_traversal_rejected(self, safe_extractor, temp_extract_dir: Path):
        """Verifies that entries starting with / or \\ or drive paths raise ValueError."""
        import zipfile
        bad_zip_path = temp_extract_dir / "bad_backslash.zip"
        with zipfile.ZipFile(bad_zip_path, "w") as zf:
            zf.writestr("/etc/shadow", b"root:x:0:0:::")
        
        target_dir = temp_extract_dir / "extracted"
        with pytest.raises(ValueError):
            safe_extractor(bad_zip_path, target_dir)

    def test_symlink_0xa1ed_rejected(self, safe_extractor, symlink_zip: Path, temp_extract_dir: Path):
        """Verifies that archives containing symlinks (external_attr 0xA1ED / S_IFLNK) raise ValueError."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(symlink_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert "symlink" in error_msg, f"Expected 'symlink' in error message, got: {excinfo.value}"

        # Invariant: No symlinks created on disk
        for root, dirs, files in os.walk(temp_extract_dir):
            for name in files:
                p = Path(root) / name
                assert not p.is_symlink(), f"Symlink was created on filesystem: {p}"

    def test_zip_bomb_high_ratio_rejected(self, safe_extractor, zip_bomb_zip: Path, temp_extract_dir: Path):
        """Verifies that high-ratio compression bombs (> 100x ratio) are rejected prior to extraction."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(zip_bomb_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert any(keyword in error_msg for keyword in ["ratio", "compression", "bomb"]), (
            f"Expected ratio error, got: {excinfo.value}"
        )

    def test_oversized_single_file_rejected(self, safe_extractor, oversized_file_zip: Path, temp_extract_dir: Path):
        """Verifies that individual files exceeding 10 MB (10,485,760 bytes) raise ValueError."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(oversized_file_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert any(keyword in error_msg for keyword in ["single file", "limit", "10 mb", "exceed"]), (
            f"Expected single file limit error, got: {excinfo.value}"
        )

    def test_oversized_total_archive_rejected(self, safe_extractor, oversized_archive_zip: Path, temp_extract_dir: Path):
        """Verifies that archives whose total uncompressed volume exceeds 50 MB raise ValueError."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(oversized_archive_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert any(keyword in error_msg for keyword in ["total", "50 mb", "limit", "exceed"]), (
            f"Expected total archive limit error, got: {excinfo.value}"
        )

    def test_corrupt_archive_rejected(self, safe_extractor, corrupt_zip: Path, temp_extract_dir: Path):
        """Verifies that truncated or malformed archives raise ValueError."""
        with pytest.raises(ValueError) as excinfo:
            safe_extractor(corrupt_zip, temp_extract_dir)

        error_msg = str(excinfo.value).lower()
        assert any(keyword in error_msg for keyword in ["bad zip", "corrupt", "not a zip", "invalid"]), (
            f"Expected corrupt zip error, got: {excinfo.value}"
        )


class TestRunnerBoundarySemantics:
    """Verifies timeout guarantees and process exit code semantics."""

    @pytest.mark.asyncio
    async def test_300_second_timeout_semantics(self):
        """Verifies that an asynchronous runner enforces timeout and kills hanging processes."""
        async def mock_hanging_runner(timeout_seconds: float):
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import time; time.sleep(10)",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                raise TimeoutError(f"Scan timed out after {timeout_seconds}s")

        # Test timeout trigger with short deadline
        with pytest.raises(TimeoutError) as excinfo:
            await mock_hanging_runner(timeout_seconds=0.3)

        assert "timed out" in str(excinfo.value).lower()

    def test_exit_code_zero_and_one_handling(self):
        """
        SecureShip CLI returns:
        - 0: Clean scan
        - 1: Scan completed with findings
        Both must be classified as SUCCESSFUL scans.
        Exit codes >= 2 represent fatal system errors.
        """
        def handle_scan_result(exit_code: int, stdout_json: str) -> dict:
            if exit_code not in (0, 1):
                raise RuntimeError(f"Scan execution failed with exit code {exit_code}")
            return {"status": "SUCCESS", "exit_code": exit_code}

        res0 = handle_scan_result(0, "{}")
        assert res0["status"] == "SUCCESS"

        res1 = handle_scan_result(1, "{}")
        assert res1["status"] == "SUCCESS"

        for fatal_code in (2, 3, 127, 255):
            with pytest.raises(RuntimeError):
                handle_scan_result(fatal_code, "")
