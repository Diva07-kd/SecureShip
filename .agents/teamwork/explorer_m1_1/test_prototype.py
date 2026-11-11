# Unit test suite verifying prototype_safe_extract.py
import io
import os
import stat
import zipfile
import tempfile
import pytest
from pathlib import Path

from prototype_safe_extract import (
    safe_extract,
    temporary_scan_dir,
    ExtractionResult,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_EXTRACT_BYTES,
    MAX_COMPRESSION_RATIO,
)


def create_in_memory_zip(entries: dict[str, tuple[bytes, int]], compress: bool = True) -> bytes:
    """
    Helper to construct in-memory zip bytes.
    entries maps filename -> (file_content_bytes, external_attr_int)
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as zf:
        for name, (data, attr) in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
            if attr:
                info.external_attr = attr
            zf.writestr(info, data)
    return buf.getvalue()


@pytest.fixture
def temp_zip(tmp_path: Path):
    """Factory fixture to write zip bytes to a temporary zip file."""
    def _create(data: bytes) -> Path:
        p = tmp_path / "test.zip"
        p.write_bytes(data)
        return p
    return _create


# =========================================================================
# Defense 1: Path Traversal / Zip-Slip Tests
# =========================================================================

class TestZipSlipDefense:
    def test_reject_parent_directory_traversal(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"../../evil.txt": (b"pwned", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, extract_dir)

    def test_reject_nested_parent_traversal(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"subdir/../../evil.txt": (b"pwned", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, extract_dir)

    def test_reject_absolute_path_posix(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"/etc/passwd": (b"root:x:0:0:", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip-slip violation.*absolute path"):
            safe_extract(zip_path, extract_dir)

    def test_reject_windows_drive_letter(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"C:/Windows/System32/evil.dll": (b"pwned", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip-slip violation.*absolute path"):
            safe_extract(zip_path, extract_dir)

    def test_reject_leading_backslash(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"\\Windows\\System32\\cmd.exe": (b"pwned", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip-slip violation"):
            safe_extract(zip_path, extract_dir)

    def test_reject_windows_reserved_device_names(self, temp_zip, tmp_path):
        for name in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1", "nul.txt", "con.py"]:
            data = create_in_memory_zip({f"dir/{name}": (b"device", 0)})
            zip_path = temp_zip(data)
            extract_dir = tmp_path / "target"
            with pytest.raises(ValueError, match="Windows reserved device name"):
                safe_extract(zip_path, extract_dir)

    def test_reject_empty_filename(self, temp_zip, tmp_path):
        data = create_in_memory_zip({"": (b"data", 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="cannot be empty"):
            safe_extract(zip_path, extract_dir)


# =========================================================================
# Defense 2: Symlink Defense Tests
# =========================================================================

class TestSymlinkDefense:
    def test_reject_symlink_unix_attr_0xA1ED(self, temp_zip, tmp_path):
        # 0xA1ED in upper 16 bits = 0xA1ED << 16
        data = create_in_memory_zip({"link": (b"/etc/passwd", 0xA1ED << 16)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, extract_dir)

    def test_reject_symlink_posix_s_iflnk(self, temp_zip, tmp_path):
        # stat.S_IFLNK (0o120000 | 0o755) in upper 16 bits
        symlink_mode = (stat.S_IFLNK | 0o755) << 16
        data = create_in_memory_zip({"link2": (b"../../secret", symlink_mode)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, extract_dir)

    def test_reject_symlink_raw_0xA1ED(self, temp_zip, tmp_path):
        # Attribute stored without shift
        data = create_in_memory_zip({"link3": (b"/target", 0xA1ED)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, extract_dir)

    def test_reject_fifo_special_file(self, temp_zip, tmp_path):
        # stat.S_IFIFO in upper 16 bits
        fifo_mode = (stat.S_IFIFO | 0o644) << 16
        data = create_in_memory_zip({"my_fifo": (b"", fifo_mode)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, extract_dir)

    def test_accept_regular_unix_file(self, temp_zip, tmp_path):
        # stat.S_IFREG | 0o644 in upper 16 bits
        reg_mode = (stat.S_IFREG | 0o644) << 16
        data = create_in_memory_zip({"normal.txt": (b"clean content", reg_mode)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        result = safe_extract(zip_path, extract_dir)
        assert result.file_count == 1
        assert (extract_dir / "normal.txt").read_text() == "clean content"


# =========================================================================
# Defense 3: Compression Bomb / Ratio Defense Tests
# =========================================================================

class TestZipBombDefense:
    def test_reject_high_compression_ratio_upfront(self, temp_zip, tmp_path):
        # 500 KB of zeros deflates to ~500 bytes -> ratio ~1000x > 100x
        bomb_data = b"0" * (500 * 1024)
        data = create_in_memory_zip({"bomb.txt": (bomb_data, 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Compression ratio.*exceeds maximum"):
            safe_extract(zip_path, extract_dir)

    def test_accept_normal_compression_ratio(self, temp_zip, tmp_path):
        # Diverse data (source code) has modest compression ratio (~2x - 3x)
        code = (b"def hello():\n    print('world')\n" * 50)
        data = create_in_memory_zip({"hello.py": (code, 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        result = safe_extract(zip_path, extract_dir)
        assert result.file_count == 1
        assert result.total_bytes == len(code)

    def test_reject_streaming_ratio_with_small_threshold(self, temp_zip, tmp_path):
        # Test streaming check with configured ratio threshold
        bomb_data = b"A" * 10000
        data = create_in_memory_zip({"bomb_stream.txt": (bomb_data, 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        # Set max_compression_ratio=2.0 -> will fail
        with pytest.raises(ValueError, match="Compression ratio.*exceeds maximum"):
            safe_extract(zip_path, extract_dir, max_compression_ratio=2.0)


# =========================================================================
# Defense 4: Size Quotas Tests
# =========================================================================

class TestSizeQuotas:
    def test_reject_single_file_exceeds_quota_configured(self, temp_zip, tmp_path):
        content = b"X" * 2000
        data = create_in_memory_zip({"large.txt": (content, 0)})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="exceeds single file limit"):
            safe_extract(zip_path, extract_dir, max_single_file_bytes=1000)

    def test_reject_total_archive_exceeds_quota_configured(self, temp_zip, tmp_path):
        data = create_in_memory_zip({
            "f1.txt": (b"123456", 0),
            "f2.txt": (b"abcdef", 0),
        })
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Total uncompressed archive size exceeds limit"):
            safe_extract(zip_path, extract_dir, max_total_bytes=10)

    def test_reject_excessive_file_count(self, temp_zip, tmp_path):
        entries = {f"file_{i}.txt": (b"data", 0) for i in range(15)}
        data = create_in_memory_zip(entries)
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Archive exceeds maximum allowed entry count"):
            safe_extract(zip_path, extract_dir, max_file_count=10)


# =========================================================================
# Defense 5: Atomic Extraction & Lifecycle Cleanup Tests
# =========================================================================

class TestAtomicExtractionAndLifecycleCleanup:
    def test_temporary_scan_dir_cleanup_on_success(self):
        created_path = None
        with temporary_scan_dir() as temp_dir:
            created_path = temp_dir
            assert created_path.exists()
            (created_path / "scan_file.txt").write_text("scanning...")
        assert not created_path.exists()

    def test_temporary_scan_dir_cleanup_on_exception(self):
        created_path = None
        with pytest.raises(RuntimeError, match="Simulated scan crash"):
            with temporary_scan_dir() as temp_dir:
                created_path = temp_dir
                assert created_path.exists()
                (created_path / "payload.txt").write_text("test")
                raise RuntimeError("Simulated scan crash")
        assert not created_path.exists()

    def test_safe_extract_atomic_rollback_on_failure(self, temp_zip, tmp_path):
        # Create an archive where file1 is valid, but file2 is a symlink
        entries = {
            "valid.txt": (b"legitimate content", 0),
            "evil_link": (b"/etc/passwd", 0xA1ED << 16),
        }
        data = create_in_memory_zip(entries)
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        extract_dir.mkdir()

        with pytest.raises(ValueError, match="Symlink detected"):
            safe_extract(zip_path, extract_dir)

        # Invariant: extract_dir must contain NO partially extracted files
        assert list(extract_dir.iterdir()) == []


# =========================================================================
# Functional & Edge Case Tests
# =========================================================================

class TestFunctionalAndEdgeCases:
    def test_valid_archive_full_extraction(self, temp_zip, tmp_path):
        entries = {
            "src/index.ts": (b"console.log('hi');", 0),
            "src/utils/math.ts": (b"export const add = (a, b) => a + b;", 0),
            "package.json": (b'{"name": "test"}', 0),
        }
        data = create_in_memory_zip(entries)
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"

        result = safe_extract(zip_path, extract_dir)
        assert isinstance(result, ExtractionResult)
        assert result.file_count == 3
        assert (extract_dir / "src/index.ts").exists()
        assert (extract_dir / "src/utils/math.ts").exists()
        assert (extract_dir / "package.json").exists()
        assert result.total_bytes == sum(len(v[0]) for v in entries.values())

    def test_empty_zip_archive(self, temp_zip, tmp_path):
        data = create_in_memory_zip({})
        zip_path = temp_zip(data)
        extract_dir = tmp_path / "target"
        result = safe_extract(zip_path, extract_dir)
        assert result.file_count == 0
        assert result.total_bytes == 0

    def test_reject_corrupt_non_zip(self, temp_zip, tmp_path):
        corrupt_file = tmp_path / "corrupt.zip"
        corrupt_file.write_bytes(b"THIS_IS_NOT_A_VALID_ZIP_ARCHIVE_DATA")
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Corrupted or invalid zip file"):
            safe_extract(corrupt_file, extract_dir)

    def test_reject_missing_zip_file(self, tmp_path):
        missing_file = tmp_path / "does_not_exist.zip"
        extract_dir = tmp_path / "target"
        with pytest.raises(ValueError, match="Zip file not found"):
            safe_extract(missing_file, extract_dir)
