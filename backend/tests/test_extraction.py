"""
Unit tests for Safe Archive Extraction (backend/app/core/safe_extract.py).
Tests all 5 security defenses: Zip-slip, symlinks, zip bombs, size quotas, and atomic cleanup.
"""

import io
import stat
import zipfile
from pathlib import Path
from typing import Optional

import pytest

from app.core.safe_extract import (
    ExtractionResult,
    safe_extract,
    safe_extract_context,
    temporary_scan_dir,
)


def create_in_memory_zip(
    dest_path: Path,
    entries: list[tuple[str, bytes, Optional[int]]],
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    """Helper to create ZIP archives with customizable filenames and external_attr."""
    with zipfile.ZipFile(dest_path, "w", compression=compression) as zf:
        for item in entries:
            name, data = item[0], item[1]
            attr = item[2] if len(item) > 2 else None
            info = zipfile.ZipInfo(filename=name)
            info.compress_type = compression
            if attr is not None:
                info.external_attr = attr
            zf.writestr(info, data)
    return dest_path


class TestZipSlipDefense:
    def test_reject_parent_directory_traversal(self, tmp_path):
        zip_path = tmp_path / "traversal.zip"
        create_in_memory_zip(zip_path, [("../../evil.txt", b"evil content", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, target_dir)

    def test_reject_nested_parent_traversal(self, tmp_path):
        zip_path = tmp_path / "nested_traversal.zip"
        create_in_memory_zip(zip_path, [("subdir/../../evil.txt", b"evil content", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, target_dir)

    def test_reject_absolute_path_posix(self, tmp_path):
        zip_path = tmp_path / "abs_posix.zip"
        create_in_memory_zip(zip_path, [("/etc/passwd", b"root:x:0:0:", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="absolute path forbidden"):
            safe_extract(zip_path, target_dir)

    def test_reject_windows_drive_letter(self, tmp_path):
        zip_path = tmp_path / "win_drive.zip"
        create_in_memory_zip(zip_path, [("C:/Windows/System32/evil.dll", b"payload", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="absolute path forbidden"):
            safe_extract(zip_path, target_dir)

    def test_reject_leading_backslash(self, tmp_path):
        zip_path = tmp_path / "leading_backslash.zip"
        create_in_memory_zip(zip_path, [("\\Windows\\System32\\cmd.exe", b"payload", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="absolute path forbidden"):
            safe_extract(zip_path, target_dir)

    @pytest.mark.parametrize("dev_name", ["CON", "PRN", "AUX", "NUL", "COM1", "nul.txt", "aux.json"])
    def test_reject_windows_reserved_device_names(self, tmp_path, dev_name):
        zip_path = tmp_path / f"reserved_{dev_name}.zip"
        create_in_memory_zip(zip_path, [(f"src/{dev_name}", b"payload", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Windows reserved device name forbidden"):
            safe_extract(zip_path, target_dir)

    def test_reject_empty_filename(self, tmp_path):
        zip_path = tmp_path / "empty_name.zip"
        create_in_memory_zip(zip_path, [("", b"payload", None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="cannot be empty"):
            safe_extract(zip_path, target_dir)


class TestSymlinkDefense:
    def test_reject_symlink_unix_attr_0xA1ED(self, tmp_path):
        zip_path = tmp_path / "symlink_0xa1ed.zip"
        # Standard Unix symlink: 0xA1ED in upper 16 bits (0xA1ED << 16)
        create_in_memory_zip(zip_path, [("link.txt", b"/etc/passwd", 0xA1ED << 16)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, target_dir)

    def test_reject_symlink_posix_s_iflnk(self, tmp_path):
        zip_path = tmp_path / "symlink_iflnk.zip"
        # POSIX S_IFLNK (0o120000 | 0o777) in upper 16 bits
        symlink_mode = (stat.S_IFLNK | 0o777) << 16
        create_in_memory_zip(zip_path, [("secret_link", b"../secret", symlink_mode)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, target_dir)

    def test_reject_symlink_raw_0xA1ED(self, tmp_path):
        zip_path = tmp_path / "symlink_raw.zip"
        # Explicit unshifted 0xA1ED
        create_in_memory_zip(zip_path, [("raw_link", b"/etc/shadow", 0xA1ED)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, target_dir)

    def test_reject_fifo_special_file(self, tmp_path):
        zip_path = tmp_path / "fifo.zip"
        fifo_mode = (stat.S_IFIFO | 0o644) << 16
        create_in_memory_zip(zip_path, [("my_pipe", b"", fifo_mode)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, target_dir)

    def test_accept_regular_unix_file(self, tmp_path):
        zip_path = tmp_path / "regular.zip"
        reg_mode = (stat.S_IFREG | 0o644) << 16
        create_in_memory_zip(zip_path, [("index.js", b"console.log('hello');", reg_mode)])
        target_dir = tmp_path / "extracted"

        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 1
        assert (target_dir / "index.js").exists()
        assert (target_dir / "index.js").read_text() == "console.log('hello');"


class TestZipBombDefense:
    def test_reject_high_compression_ratio_upfront(self, tmp_path):
        zip_path = tmp_path / "zipbomb.zip"
        # 500 KB of zeros compresses to ~500 bytes (ratio ~1000x)
        large_zero_data = b"\x00" * (500 * 1024)
        create_in_memory_zip(zip_path, [("huge.bin", large_zero_data, None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Compression ratio"):
            safe_extract(zip_path, target_dir)

    def test_accept_normal_compression_ratio(self, tmp_path):
        zip_path = tmp_path / "normal.zip"
        source_code = b"const x = 1;\nconsole.log(x);\n" * 20
        create_in_memory_zip(zip_path, [("code.js", source_code, None)])
        target_dir = tmp_path / "extracted"

        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 1
        assert result.total_bytes == len(source_code)

    def test_reject_streaming_ratio_with_configured_threshold(self, tmp_path):
        zip_path = tmp_path / "strict_ratio.zip"
        # Data that compresses with 5x ratio
        repeating_data = b"abcdefghij12345" * 200
        create_in_memory_zip(zip_path, [("test.txt", repeating_data, None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Compression ratio"):
            # Set ratio ceiling to 2.0x
            safe_extract(zip_path, target_dir, max_compression_ratio=2.0)


class TestSizeQuotas:
    def test_reject_single_file_exceeds_quota_configured(self, tmp_path):
        zip_path = tmp_path / "single_file_quota.zip"
        data = b"X" * 1500
        create_in_memory_zip(zip_path, [("data.txt", data, None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="exceeds single file limit"):
            safe_extract(zip_path, target_dir, max_single_file_bytes=1000)

    def test_reject_total_archive_exceeds_quota_configured(self, tmp_path):
        zip_path = tmp_path / "total_quota.zip"
        data1 = b"A" * 800
        data2 = b"B" * 800
        create_in_memory_zip(zip_path, [("f1.txt", data1, None), ("f2.txt", data2, None)])
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="Total uncompressed archive size exceeds limit"):
            safe_extract(zip_path, target_dir, max_total_bytes=1000)

    def test_reject_excessive_file_count(self, tmp_path):
        zip_path = tmp_path / "too_many_files.zip"
        entries = [(f"file_{i}.txt", b"x", None) for i in range(15)]
        create_in_memory_zip(zip_path, entries)
        target_dir = tmp_path / "extracted"

        with pytest.raises(ValueError, match="exceeds maximum allowed entry count"):
            safe_extract(zip_path, target_dir, max_file_count=10)


class TestAtomicCleanup:
    def test_temporary_scan_dir_cleanup_on_success(self):
        created_path = None
        with temporary_scan_dir() as sdir:
            created_path = sdir
            assert sdir.exists()
            (sdir / "test.txt").write_text("ok")
        assert not created_path.exists()

    def test_temporary_scan_dir_cleanup_on_exception(self):
        created_path = None
        with pytest.raises(RuntimeError):
            with temporary_scan_dir() as sdir:
                created_path = sdir
                assert sdir.exists()
                raise RuntimeError("Simulated failure inside context")
        assert not created_path.exists()

    def test_safe_extract_atomic_rollback_on_failure(self, tmp_path):
        zip_path = tmp_path / "mixed.zip"
        # First entry is valid, second entry has traversal
        create_in_memory_zip(
            zip_path,
            [
                ("valid.txt", b"valid content", None),
                ("../../evil.txt", b"traversal content", None),
            ],
        )
        target_dir = tmp_path / "rollback_target"

        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, target_dir)

        # Target dir must be empty after rollback
        if target_dir.exists():
            remaining_files = list(target_dir.iterdir())
            assert len(remaining_files) == 0, f"Expected 0 files after rollback, found: {remaining_files}"


class TestFunctionalCases:
    def test_valid_archive_full_extraction(self, tmp_path):
        zip_path = tmp_path / "project.zip"
        create_in_memory_zip(
            zip_path,
            [
                ("package.json", b'{"name": "test"}', None),
                ("src/index.js", b'console.log("main");', None),
                ("src/utils/math.js", b'module.exports = { add: (a,b) => a+b };', None),
            ],
        )
        target_dir = tmp_path / "extracted_project"

        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 3
        assert result.total_bytes > 0
        assert (target_dir / "package.json").is_file()
        assert (target_dir / "src" / "index.js").is_file()
        assert (target_dir / "src" / "utils" / "math.js").is_file()

    def test_empty_zip_archive(self, tmp_path):
        zip_path = tmp_path / "empty.zip"
        create_in_memory_zip(zip_path, [])
        target_dir = tmp_path / "extracted_empty"

        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 0
        assert result.total_bytes == 0

    def test_reject_corrupt_non_zip(self, tmp_path):
        corrupt_path = tmp_path / "corrupt.zip"
        corrupt_path.write_bytes(b"NOT_A_ZIP_HEADER_JUST_RANDOM_DATA_1234567890")
        target_dir = tmp_path / "extracted_corrupt"

        with pytest.raises(ValueError, match="Corrupted or invalid zip file"):
            safe_extract(corrupt_path, target_dir)

    def test_reject_missing_zip_file(self, tmp_path):
        missing_path = tmp_path / "does_not_exist.zip"
        target_dir = tmp_path / "extracted_missing"

        with pytest.raises(ValueError, match="Zip file not found"):
            safe_extract(missing_path, target_dir)

    def test_safe_extract_context_manager(self, tmp_path):
        zip_path = tmp_path / "context.zip"
        create_in_memory_zip(zip_path, [("readme.txt", b"Documentation", None)])

        extracted_dir = None
        with safe_extract_context(zip_path) as res:
            extracted_dir = res.extracted_path
            assert extracted_dir.exists()
            assert res.file_count == 1
            assert (extracted_dir / "readme.txt").read_text() == "Documentation"

        assert not extracted_dir.exists(), "Extracted directory must be automatically purged after context exit"
