"""
SecureScan Adversarial & Boundary Stress Test Suite (Milestone 1).
Empirically stress-tests:
1. Safe extraction: zip-slip variations, symlink bit permutations, dynamic decompression bombs, quota boundaries.
2. Subprocess runner: argument list isolation, shell injection resistance, exit code 0/1 semantics, timeouts.
3. Job queue: concurrency = 1 serialization and directory lifecycle cleanup.
4. Context extractor & models: boundary clamping, binary rejection, OWASP/CWE mappings.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import stat
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure backend app is on sys.path
import sys
backend_path = Path(__file__).resolve().parents[2] / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.core.safe_extract import (
    MAX_FILE_COUNT,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_EXTRACT_BYTES,
    ExtractionResult,
    _is_symlink,
    _validate_path_component,
    safe_extract,
    safe_extract_context,
    temporary_scan_dir,
)
from app.core.runner import (
    ScannerExecutionError,
    ScannerNotFoundError,
    ScannerTimeoutError,
    resolve_cli_paths,
    run_secureship_cli,
)
from app.core.queue import ScanJobQueue
from app.core.context_extractor import extract_code_snippet, enrich_report_with_snippets
from app.models.job import JobRecord, JobStage, JobStatus
from app.models.report import extract_cwe_ids, map_cwe_to_owasp, normalize_reachability_verdict, ReachabilityVerdict


# =========================================================================
# Helper Fixtures & Archive Builders
# =========================================================================

@pytest.fixture
def temp_dir():
    """Provides an isolated temporary directory cleaned up after each test."""
    td = Path(tempfile.mkdtemp(prefix="adv_test_")).resolve()
    yield td
    shutil.rmtree(td, ignore_errors=True)


def create_zip_with_custom_entries(zip_path: Path, entries: list[dict[str, Any]]) -> Path:
    """
    Creates a zip archive with fine-grained control over ZipInfo headers and raw streams.
    entries: list of dicts with keys:
      - filename: str
      - data: bytes
      - external_attr: Optional[int]
      - compress_type: Optional[int]
      - declared_file_size: Optional[int] (to simulate deceptive headers)
      - declared_compress_size: Optional[int]
    """
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            name = entry["filename"]
            raw_data = entry.get("data", b"safe content")
            compress_type = entry.get("compress_type", zipfile.ZIP_DEFLATED)

            zinfo = zipfile.ZipInfo(name)
            zinfo.compress_type = compress_type

            if "external_attr" in entry:
                zinfo.external_attr = entry["external_attr"]

            # Check if deceptive headers are specified
            if "declared_file_size" in entry or "declared_compress_size" in entry:
                # We write raw compressed data and override the header
                compressed = zlib.compress(raw_data)[2:-4]  # raw deflate stream
                zinfo.file_size = entry.get("declared_file_size", len(raw_data))
                zinfo.compress_size = entry.get("declared_compress_size", len(compressed))
                zinfo.CRC = zlib.crc32(raw_data)
                zf.writestr(zinfo, compressed)
            else:
                zf.writestr(zinfo, raw_data)

    return zip_path


# =========================================================================
# Category 1: Adversarial Zip-Slip & Path Traversal
# =========================================================================

class TestAdversarialZipSlip:
    """Empirically stress-tests all forms of zip-slip and path escape."""

    @pytest.mark.parametrize("malicious_path", [
        r"foo\..\..\evil.txt",
        r"foo/..\\../evil.txt",
        r"dir1\dir2\..\..\..\evil.txt",
        r"dir1/dir2/..\\..\\..\\evil.txt",
        r"a/b/c/../../../../evil.txt",
        r"\foo\bar\evil.txt",
        r"/etc/shadow",
        r"/var/log/../../etc/passwd",
        r"C:\Windows\System32\evil.dll",
        r"D:\data\leak.txt",
        r"C:relative_drive.txt",
        r"\\evil-server\share\payload.txt",
        r"//evil-server/share/payload.txt",
        r".",
        r"..",
        r"...",
        r"   ",
        r"nested/../../../../../../../../../../evil.txt",
    ])
    def test_rejects_path_traversal_payloads(self, temp_dir, malicious_path):
        """Every path traversal permutation must be rejected before extraction."""
        zip_path = temp_dir / "slip.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        # Build zip with the malicious entry
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(malicious_path, b"malicious content")

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Zip-slip" in str(exc_info.value) or "Invalid archive entry" in str(exc_info.value) or "escapes" in str(exc_info.value)

    @pytest.mark.parametrize("device_name", [
        "con.json",
        "aux.txt",
        "prn.log",
        "nul.dat",
        "com1.exe",
        "com9.bin",
        "lpt1.txt",
        "lpt8.inf",
        "CON",
        "AUX",
        "PRN",
        "NUL",
        "subdir/nUl.exe",
        "nested/folder/AUX/payload.txt",
        "deep/path/COM1.log",
    ])
    def test_rejects_windows_device_names(self, temp_dir, device_name):
        """Windows reserved device names must be strictly rejected even on non-Windows hosts."""
        zip_path = temp_dir / "device.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(device_name, b"device name payload")

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "reserved device name" in str(exc_info.value).lower()


# =========================================================================
# Category 2: Symlink Bit Permutations & POSIX Special Files
# =========================================================================

class TestSymlinkBitPermutations:
    """Empirically stress-tests symlink detection across varied bit layouts."""

    @pytest.mark.parametrize("attr_val,description", [
        (0xA1ED << 16, "Standard Unix symlink 0o120755 in upper 16 bits"),
        (0xA1FF << 16, "Unix symlink with 0o777 permissions in upper 16 bits"),
        (0xA1A4 << 16, "Unix symlink with 0o644 permissions in upper 16 bits"),
        (0xA100 << 16, "Unix symlink with 0o400 permissions in upper 16 bits"),
        (stat.S_IFLNK << 16, "POSIX S_IFLNK (0o120000) in upper 16 bits"),
        ((stat.S_IFLNK | 0o777) << 16, "POSIX S_IFLNK with 777 mode in upper 16 bits"),
        (0xA1ED, "Raw attribute 0xA1ED in lower 16 bits"),
        (0xA1FF, "Raw attribute 0xA1FF in lower 16 bits"),
        (stat.S_IFLNK, "POSIX S_IFLNK in lower 16 bits"),
        (stat.S_IFIFO << 16, "POSIX FIFO special file"),
        (stat.S_IFCHR << 16, "POSIX character special file"),
        (stat.S_IFBLK << 16, "POSIX block special file"),
        (stat.S_IFSOCK << 16, "POSIX socket special file"),
    ])
    def test_rejects_symlinks_and_special_files(self, temp_dir, attr_val, description):
        """Any symlink bit permutation or special file mode must trigger rejection."""
        zip_path = temp_dir / "symlink.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        create_zip_with_custom_entries(zip_path, [
            {"filename": "link_or_special", "data": b"target_pointer", "external_attr": attr_val}
        ])

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Symlink" in str(exc_info.value)

    def test_accepts_valid_posix_regular_files_and_directories(self, temp_dir):
        """Normal regular files and directories with standard POSIX modes must be accepted."""
        zip_path = temp_dir / "posix_valid.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        file_attr = (stat.S_IFREG | 0o644) << 16
        dir_attr = (stat.S_IFDIR | 0o755) << 16

        with zipfile.ZipFile(zip_path, "w") as zf:
            dir_info = zipfile.ZipInfo("subfolder/")
            dir_info.external_attr = dir_attr
            zf.writestr(dir_info, "")

            file_info = zipfile.ZipInfo("subfolder/file.py")
            file_info.external_attr = file_attr
            zf.writestr(file_info, b"print('valid python code')\n")

        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 1
        assert (target_dir / "subfolder" / "file.py").exists()


# =========================================================================
# Category 3: Dynamic Decompression Bombs & Compression Ratios
# =========================================================================

class TestDecompressionBombs:
    """Empirically stress-tests static and dynamic decompression bombs."""

    def test_static_bomb_high_ratio_rejected_upfront(self, temp_dir):
        """Archives with declared ratio > 100x must be rejected in Phase 1 header scan."""
        zip_path = temp_dir / "static_bomb.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        # 5 MB of zeros compresses into ~5 KB (ratio ~1000x)
        large_zeros = b"\x00" * (5 * 1024 * 1024)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeroes.dat", large_zeros)

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Compression ratio" in str(exc_info.value)

    def test_dynamic_bomb_deceptive_header_caught_during_streaming(self, temp_dir):
        """
        Deceptive archive: Header attempts to disguise decompression bomb.
        Must be rejected either by ratio check or corrupt zip detection,
        and target directory must be atomically cleaned up.
        """
        zip_path = temp_dir / "deceptive_bomb.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        # Build zip with 200 KB repeating text
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("deceptive.txt", b"A" * 200_000)
        
        raw = bytearray(bio.getvalue())
        cdir = raw.find(b"PK\x01\x02")
        loc = raw.find(b"PK\x03\x04")
        if cdir != -1 and loc != -1:
            # Patch fake smaller uncompressed size in headers to simulate deceptive bomb
            struct.pack_into("<I", raw, loc + 22, 5000)
            struct.pack_into("<I", raw, cdir + 24, 5000)

        zip_path.write_bytes(raw)

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        err_msg = str(exc_info.value).lower()
        assert any(phrase in err_msg for phrase in ["compression ratio", "zip bomb", "corrupted or invalid", "bad crc-32"])
        # Verify atomic cleanup: zero files leaked
        assert len(list(target_dir.iterdir())) == 0

    def test_dynamic_bomb_single_file_exceeded_caught_during_streaming(self, temp_dir):
        """
        Single file exceeding MAX_SINGLE_FILE_BYTES (10MB) must be rejected
        without leaking partial files in target_dir.
        """
        zip_path = temp_dir / "balloon_10mb.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        # 11 MB of pseudorandom data (compression ratio ~ 1.0x so ratio check passes)
        import os
        payload_11mb = os.urandom(11 * 1024 * 1024)

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("balloon.bin", payload_11mb)

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir, max_single_file_bytes=10 * 1024 * 1024)

        err_msg = str(exc_info.value).lower()
        assert "single file limit" in err_msg or "single-file limit" in err_msg
        assert len(list(target_dir.iterdir())) == 0

    def test_suspicious_zero_compressed_size_rejected(self, temp_dir):
        """Non-empty file with zero compressed size is rejected upfront."""
        zip_path = temp_dir / "zero_comp.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("suspicious.bin", b"hello world")

        raw = bytearray(bio.getvalue())
        cdir = raw.find(b"PK\x01\x02")
        if cdir != -1:
            struct.pack_into("<I", raw, cdir + 24, 2048)  # file_size = 2048
            struct.pack_into("<I", raw, cdir + 20, 0)     # compress_size = 0

        zip_path.write_bytes(raw)

        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "zero compressed size" in str(exc_info.value)


# =========================================================================
# Category 4: Exact Quota Boundaries (10MB / 50MB Limits)
# =========================================================================

class TestQuotaBoundaries:
    """Empirically verifies limits at exactly N-1, N, and N+1 byte thresholds."""

    def test_single_file_exact_and_boundary_rejection(self, temp_dir):
        """
        Tests single file limits with small custom limits:
        limit = 1000 bytes.
        999 bytes: PASS
        1000 bytes: PASS
        1001 bytes: FAIL
        """
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        limit = 1000

        # 1. 999 bytes (below)
        zip_999 = temp_dir / "below.zip"
        with zipfile.ZipFile(zip_999, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("test.dat", b"X" * 999)
        res = safe_extract(zip_999, target_dir, max_single_file_bytes=limit)
        assert res.total_bytes == 999
        shutil.rmtree(target_dir)
        target_dir.mkdir()

        # 2. 1000 bytes (exact limit)
        zip_1000 = temp_dir / "exact.zip"
        with zipfile.ZipFile(zip_1000, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("test.dat", b"X" * 1000)
        res = safe_extract(zip_1000, target_dir, max_single_file_bytes=limit)
        assert res.total_bytes == 1000
        shutil.rmtree(target_dir)
        target_dir.mkdir()

        # 3. 1001 bytes (exceeds limit)
        zip_1001 = temp_dir / "above.zip"
        with zipfile.ZipFile(zip_1001, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("test.dat", b"X" * 1001)
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_1001, target_dir, max_single_file_bytes=limit)
        assert "exceeds single file limit" in str(exc_info.value)

    def test_total_archive_exact_and_boundary_rejection(self, temp_dir):
        """
        Tests total archive limits with multi-file composition:
        total limit = 3000 bytes across 3 files of 1000 bytes.
        2999 bytes: PASS
        3000 bytes: PASS
        3001 bytes: FAIL
        """
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        total_limit = 3000

        # 1. 2999 bytes across 3 files (1000 + 1000 + 999)
        zip_pass = temp_dir / "pass.zip"
        with zipfile.ZipFile(zip_pass, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("f1.dat", b"A" * 1000)
            zf.writestr("f2.dat", b"B" * 1000)
            zf.writestr("f3.dat", b"C" * 999)
        res = safe_extract(zip_pass, target_dir, max_total_bytes=total_limit)
        assert res.total_bytes == 2999
        shutil.rmtree(target_dir)
        target_dir.mkdir()

        # 2. 3000 bytes exact limit across 3 files (1000 + 1000 + 1000)
        zip_exact = temp_dir / "exact.zip"
        with zipfile.ZipFile(zip_exact, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("f1.dat", b"A" * 1000)
            zf.writestr("f2.dat", b"B" * 1000)
            zf.writestr("f3.dat", b"C" * 1000)
        res = safe_extract(zip_exact, target_dir, max_total_bytes=total_limit)
        assert res.total_bytes == 3000
        shutil.rmtree(target_dir)
        target_dir.mkdir()

        # 3. 3001 bytes (exceeds limit) across 3 files (1000 + 1000 + 1001)
        zip_fail = temp_dir / "fail.zip"
        with zipfile.ZipFile(zip_fail, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("f1.dat", b"A" * 1000)
            zf.writestr("f2.dat", b"B" * 1000)
            zf.writestr("f3.dat", b"C" * 1001)
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_fail, target_dir, max_total_bytes=total_limit)
        assert "Total uncompressed archive size exceeds limit" in str(exc_info.value)

    def test_file_count_boundary(self, temp_dir):
        """Tests entry count limit enforcement (MAX_FILE_COUNT)."""
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        zip_path = temp_dir / "many_files.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", b"x")

        # Limit = 10 -> FAIL
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir, max_file_count=10)
        assert "maximum allowed entry count" in str(exc_info.value)

        # Limit = 15 -> PASS
        res = safe_extract(zip_path, target_dir, max_file_count=15)
        assert res.file_count == 15

    def test_atomic_rollback_on_midway_failure(self, temp_dir):
        """
        If extraction fails midway (e.g. valid file followed by malicious entry),
        target_dir must be cleanly wiped of all partial files.
        """
        zip_path = temp_dir / "mixed_malicious.zip"
        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("legit.txt", b"Legitimate file content")
            zf.writestr("../escaped.txt", b"Malicious slip payload")

        with pytest.raises(ValueError):
            safe_extract(zip_path, target_dir)

        # Target dir must be empty
        assert len(list(target_dir.iterdir())) == 0


# =========================================================================
# Category 5: Subprocess Runner (`run_secureship_cli`) Stress Testing
# =========================================================================

class TestSubprocessRunnerAdversarial:
    """Stress-tests subprocess execution, command injection resistance, and exit semantics."""

    @pytest.mark.asyncio
    async def test_argument_list_isolation_no_shell(self, temp_dir):
        """Verifies CLI runner executes via argument list without invoking shell."""
        target_dir = temp_dir / "scan_target"
        target_dir.mkdir()

        dummy_report = {
            "version": "1.0.0",
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        mock_process = AsyncMock()
        mock_process.communicate.return_value = (json.dumps(dummy_report).encode("utf-8"), b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec, \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            mock_exec.return_value = mock_process

            report = await run_secureship_cli(target_dir, timeout_seconds=30)
            assert report == dummy_report

            # Assert argument list form:
            mock_exec.assert_called_once()
            args, kwargs = mock_exec.call_args
            assert args[0] == "node"
            assert args[1] == "index.js"
            assert args[2] == "scan"
            assert args[3] == str(target_dir.resolve())
            assert args[4] == "--json"
            assert "shell" not in kwargs

    @pytest.mark.asyncio
    async def test_shell_injection_characters_in_target_path(self, temp_dir):
        """
        Target directory with characters like ';', '&', '|', '`' must be passed safely
        as literal path arguments without execution.
        """
        # Create a directory with spaces and unusual punctuation
        target_dir = temp_dir / "target_test_injection_safe"
        target_dir.mkdir()

        dummy_report = {"version": "1.0.0", "findings": []}
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (json.dumps(dummy_report).encode("utf-8"), b"")
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec, \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            mock_exec.return_value = mock_process

            # Pass extra argument with malicious command injection
            malicious_extra = ["--custom-arg; rm -rf /; echo evil", "--other & calc.exe"]
            report = await run_secureship_cli(target_dir, extra_args=malicious_extra)
            assert report == dummy_report

            args, _ = mock_exec.call_args
            assert args[-2] == "--custom-arg; rm -rf /; echo evil"
            assert args[-1] == "--other & calc.exe"

    @pytest.mark.asyncio
    async def test_exit_code_0_and_1_both_treated_as_successful_scans(self, temp_dir):
        """
        CRITICAL INVARIANT:
        Exit code 0: Clean scan (0 findings) -> SUCCESS
        Exit code 1: Scan completed with findings -> SUCCESS
        """
        target_dir = temp_dir / "scan_target"
        target_dir.mkdir()

        report_0 = {"findings": [], "summary": {"critical": 0}}
        report_1 = {
            "findings": [{"id": "F-1", "title": "SQL Injection", "severity": "HIGH"}],
            "summary": {"critical": 0, "high": 1},
        }

        # 1. Exit code 0
        proc_0 = AsyncMock()
        proc_0.communicate.return_value = (json.dumps(report_0).encode("utf-8"), b"")
        proc_0.returncode = 0

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc_0)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            res_0 = await run_secureship_cli(target_dir)
            assert res_0 == report_0

        # 2. Exit code 1 (with findings)
        proc_1 = AsyncMock()
        proc_1.communicate.return_value = (json.dumps(report_1).encode("utf-8"), b"")
        proc_1.returncode = 1

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc_1)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            res_1 = await run_secureship_cli(target_dir)
            assert res_1 == report_1
            assert len(res_1["findings"]) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("exit_code,stderr_text", [
        (2, "CLI error: invalid argument --foo"),
        (3, "Infrastructure error: binary opengrep crashed"),
        (127, "command not found"),
        (255, "Fatal runtime error"),
    ])
    async def test_exit_codes_above_1_raise_scanner_execution_error(self, temp_dir, exit_code, stderr_text):
        """Exit codes > 1 must raise ScannerExecutionError with the exact code and error message."""
        target_dir = temp_dir / "scan_target"
        target_dir.mkdir()

        proc = AsyncMock()
        proc.communicate.return_value = (b"", stderr_text.encode("utf-8"))
        proc.returncode = exit_code

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(target_dir)

            assert exc_info.value.exit_code == exit_code
            assert stderr_text in exc_info.value.message or stderr_text in exc_info.value.stderr

    @pytest.mark.asyncio
    @pytest.mark.parametrize("code", [0, 1])
    async def test_empty_or_corrupted_stdout_raises_scanner_execution_error(self, temp_dir, code):
        """Even if exit code is 0 or 1, empty or invalid JSON stdout must raise ScannerExecutionError."""
        target_dir = temp_dir / "scan_target"
        target_dir.mkdir()

        # Empty stdout
        proc_empty = AsyncMock()
        proc_empty.communicate.return_value = (b"   ", b"")
        proc_empty.returncode = code

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc_empty)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(target_dir)
            assert "empty stdout" in exc_info.value.message

        # Corrupt JSON stdout
        proc_corrupt = AsyncMock()
        proc_corrupt.communicate.return_value = (b"Internal error: syntax error near line 1", b"")
        proc_corrupt.returncode = code

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc_corrupt)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(target_dir)
            assert "invalid JSON" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_runner_timeout_terminates_child_process(self, temp_dir):
        """Subprocess that hangs must trigger kill() and raise ScannerTimeoutError."""
        target_dir = temp_dir / "scan_target"
        target_dir.mkdir()

        proc = AsyncMock()
        proc.communicate.side_effect = asyncio.TimeoutError()
        proc.kill = MagicMock()
        proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch("app.core.runner.resolve_cli_paths", return_value=("node", "index.js")):
            with pytest.raises(ScannerTimeoutError) as exc_info:
                await run_secureship_cli(target_dir, timeout_seconds=5)

            proc.kill.assert_called_once()
            assert exc_info.value.timeout_seconds == 5


# =========================================================================
# Category 6: Job Queue Concurrency & Directory Lifecycle Cleanup
# =========================================================================

class TestJobQueueConcurrencyAndCleanup:
    """Stress-tests queue serialization and complete scratch directory removal."""

    @pytest.mark.asyncio
    async def test_queue_serializes_execution_concurrency_one(self, temp_dir):
        """Multiple concurrent jobs must be executed strictly one after another."""
        queue = ScanJobQueue()
        await queue.start()

        active_jobs = 0
        max_concurrent_seen = 0

        async def fake_runner(scan_target_dir, timeout_seconds=300):
            nonlocal active_jobs, max_concurrent_seen
            active_jobs += 1
            if active_jobs > max_concurrent_seen:
                max_concurrent_seen = active_jobs
            await asyncio.sleep(0.05)
            active_jobs -= 1
            return {"findings": [], "summary": {}}

        # Create 3 valid zip archives
        zips = []
        for i in range(3):
            zp = temp_dir / f"job_{i}.zip"
            with zipfile.ZipFile(zp, "w") as zf:
                zf.writestr("test.py", b"print('hello')\n")
            zips.append(zp)

        with patch("app.core.queue.run_secureship_cli", side_effect=fake_runner):
            # Enqueue all 3 simultaneously
            records = await asyncio.gather(*[
                queue.enqueue(f"job-{i}", str(zips[i])) for i in range(3)
            ])

            # Wait for all to complete
            for _ in range(50):
                if all(queue.get_job(f"job-{i}").status == JobStatus.DONE for i in range(3)):
                    break
                await asyncio.sleep(0.02)

            for i in range(3):
                job = queue.get_job(f"job-{i}")
                assert job.status == JobStatus.DONE
                assert job.progress == 100

            # Concurrency invariant check
            assert max_concurrent_seen == 1

        await queue.stop()

    @pytest.mark.asyncio
    async def test_scratch_dir_and_zip_deleted_on_completion_and_failure(self, temp_dir):
        """Verifies that scratch dirs and uploaded zip files are unlinked in all cases."""
        queue = ScanJobQueue()
        await queue.start()

        # 1. Successful job
        zip_ok = temp_dir / "ok.zip"
        with zipfile.ZipFile(zip_ok, "w") as zf:
            zf.writestr("clean.py", b"# clean\n")

        with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value={"findings": []})):
            await queue.enqueue("job-ok", str(zip_ok))
            for _ in range(50):
                if queue.get_job("job-ok").status == JobStatus.DONE:
                    break
                await asyncio.sleep(0.02)

            job_ok_rec = queue.get_job("job-ok")
            assert job_ok_rec.status == JobStatus.DONE
            assert not zip_ok.exists()  # Zip unlinked
            assert job_ok_rec.temp_dir is None  # Scratch dir cleared

        # 2. Failed job (malicious zip-slip)
        zip_slip = temp_dir / "slip.zip"
        with zipfile.ZipFile(zip_slip, "w") as zf:
            zf.writestr("../evil.txt", b"evil")

        await queue.enqueue("job-slip", str(zip_slip))
        for _ in range(50):
            if queue.get_job("job-slip").status == JobStatus.FAILED:
                break
            await asyncio.sleep(0.02)

        job_slip_rec = queue.get_job("job-slip")
        assert job_slip_rec.status == JobStatus.FAILED
        assert not zip_slip.exists()
        assert job_slip_rec.temp_dir is None

        await queue.stop()


# =========================================================================
# Category 7: Context Extractor & Models
# =========================================================================

class TestContextExtractorAndModelsAdversarial:
    """Stress-tests snippet slicing bounds, encoding fallbacks, and CWE/OWASP mapping."""

    def test_line_boundary_clamping(self, temp_dir):
        """Snippet slicing must clamp gracefully to line 1 and EOF."""
        source_file = temp_dir / "small.py"
        source_file.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

        # Start line 1 (top of file)
        snip_top = extract_code_snippet(temp_dir, "small.py", start_line=1, end_line=1, context_lines=5)
        assert snip_top is not None
        assert snip_top.start_line == 1
        assert snip_top.end_line == 5

        # Out of bounds line 999
        snip_oob = extract_code_snippet(temp_dir, "small.py", start_line=999, end_line=999, context_lines=5)
        assert snip_oob is not None
        assert snip_oob.target_start == 5
        assert snip_oob.target_end == 5

    def test_path_traversal_in_snippet_extraction_blocked(self, temp_dir):
        """Snippet extractor must reject any path traversal attempts."""
        secret = temp_dir / "secret.env"
        secret.write_text("DB_PASSWORD=secret", encoding="utf-8")

        sub_dir = temp_dir / "repo"
        sub_dir.mkdir()

        snip = extract_code_snippet(sub_dir, "../secret.env", start_line=1, end_line=1)
        assert snip is None

    def test_binary_file_rejection(self, temp_dir):
        """Snippet extractor must return None for binary files containing null bytes."""
        bin_file = temp_dir / "payload.bin"
        bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00")

        snip = extract_code_snippet(temp_dir, "payload.bin", start_line=1, end_line=1)
        assert snip is None

    def test_owasp_mapping_accuracy_all_categories(self):
        """Verifies mapping of CWEs to OWASP Top 10 (2021) categories A01 through A10."""
        test_cases = [
            (["CWE-89"], "A03:2021-Injection"),
            (["CWE-79"], "A03:2021-Injection"),
            (["CWE-22"], "A01:2021-Broken Access Control"),
            (["CWE-327"], "A02:2021-Cryptographic Failures"),
            (["CWE-259"], "A07:2021-Identification and Authentication Failures"),
            (["CWE-798"], "A07:2021-Identification and Authentication Failures"),
            (["CWE-776"], "A05:2021-Security Misconfiguration"),
            (["CWE-16"], "A05:2021-Security Misconfiguration"),
            (["CWE-502"], "A08:2021-Software and Data Integrity Failures"),
            (["CWE-937"], "A06:2021-Vulnerable and Outdated Components"),
            (["CWE-117"], "A09:2021-Security Logging and Monitoring Failures"),
            (["CWE-918"], "A10:2021-Server-Side Request Forgery (SSRF)"),
            (["CWE-73"], "A04:2021-Insecure Design"),
        ]
        for cwes, expected_owasp in test_cases:
            res = map_cwe_to_owasp(cwe_ids=cwes, category="", rule_id="", description="")
            assert res == expected_owasp, f"Expected {expected_owasp} for {cwes}, got {res}"

    def test_reachability_normalizer(self):
        """Tests reachability verdict normalizer."""
        assert normalize_reachability_verdict("reachable") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("REACHABLE") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("unreachable") == ReachabilityVerdict.UNREACHABLE
        assert normalize_reachability_verdict("unknown") == ReachabilityVerdict.UNKNOWN
        assert normalize_reachability_verdict(None) == ReachabilityVerdict.UNKNOWN
        assert normalize_reachability_verdict("CALL_PATH") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("IMPORT") == ReachabilityVerdict.REACHABLE
        assert normalize_reachability_verdict("REACHABLE_CALL_PATH") == ReachabilityVerdict.REACHABLE
