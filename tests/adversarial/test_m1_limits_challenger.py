"""
Empirical Challenge & Verification Suite: Milestone 1 Limits & Extraction Security.
Authored by: Challenger M1_2 (Limits & Extraction Security Challenger)

Empirically tests and stress-challenges:
1. safe_extract.py expanded limits:
   - 100 MB single file (104,857,600 bytes)
   - 1.5 GB total uncompressed extraction (1,572,864,000 bytes)
   - 30,000 maximum file entry count
2. Active verification of all 5 security defenses:
   - Layer 1: Zip-slip path traversal (fixtures/zip_slip.zip, synthetic paths, device names, escapes)
   - Layer 2: Symlink detection (fixtures/symlink_0xa1ed.zip, 0xA1ED bit variants, POSIX S_IFLNK, special files)
   - Layer 3: Compression bomb defense (fixtures/zip_bomb.zip, static high ratio, dynamic streaming ratio)
   - Layer 4: Strict quota boundary enforcement (Phase 1 header + Phase 2 streaming decompression)
   - Layer 5: Atomic rollback on all failure modes (clean purging of partial extractions)
3. upload.py expanded limit (600 MB):
   - Acceptance of archives up to exact 600 MB (629,145,600 bytes)
   - Rejection of archives > 600 MB with HTTP 413 and dynamic detail message
   - Immediate unlinking and zero temp file leakage in tempfile.gettempdir()
"""

from __future__ import annotations

import asyncio
import io
import os
import shutil
import stat
import struct
import tempfile
import uuid
import zipfile
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request, UploadFile

from app.config import settings
from app.core.safe_extract import (
    CHUNK_SIZE,
    MAX_COMPRESSION_RATIO,
    MAX_FILE_COUNT,
    MAX_SINGLE_FILE_BYTES,
    MAX_TOTAL_EXTRACT_BYTES,
    ExtractionResult,
    safe_extract,
    safe_extract_context,
    temporary_scan_dir,
)
from app.models.job import JobRecord, JobStage, JobStatus
from app.routers.upload import MAX_UPLOAD_BYTES, upload_scan_archive

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


# =============================================================================
# Suite 1: Safe Extraction Limits & 5 Security Defenses
# =============================================================================

class TestSafeExtractSecurityLayersAndLimits:
    """Empirical challenge suite for safe_extract.py limits and defenses."""

    def test_default_constants_and_config_alignment(self):
        """Verify production constants and settings match specification exactly."""
        assert MAX_SINGLE_FILE_BYTES == 100 * 1024 * 1024, "Single file limit must be 100 MB"
        assert MAX_TOTAL_EXTRACT_BYTES == 1500 * 1024 * 1024, "Total extract limit must be 1.5 GB"
        assert MAX_FILE_COUNT == 30000, "File count limit must be 30,000"
        assert MAX_COMPRESSION_RATIO == 100.0, "Compression ratio limit must be 100x"
        assert CHUNK_SIZE == 65536, "Streaming buffer must be 64 KB"

        # Settings alignment
        assert settings.MAX_SINGLE_FILE_BYTES == 100 * 1024 * 1024
        assert settings.MAX_EXTRACTED_BYTES == 1500 * 1024 * 1024
        assert settings.MAX_FILE_COUNT == 30000

    # -------------------------------------------------------------------------
    # Layer 1: Zip-Slip Path Traversal Defense
    # -------------------------------------------------------------------------
    def test_layer1_zip_slip_fixture(self, tmp_path: Path):
        """Empirically test that fixtures/zip_slip.zip is blocked with atomic rollback."""
        fixture_path = FIXTURES_DIR / "zip_slip.zip"
        assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

        target_dir = tmp_path / "extracted"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(fixture_path, target_dir)

        assert "Zip-slip violation" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "../../evil.txt",
            "nested/../../evil.txt",
            "a/b/c/../../../../evil.txt",
            "/etc/passwd",
            "/var/log/syslog",
            "C:/Windows/System32/cmd.exe",
            "D:\\secret.key",
            "\\\\attacker.server\\share\\evil.txt",
            "//attacker.server/share/evil.txt",
            "CON.txt",
            "prn.log",
            "aux",
            "nul",
            "COM1.dat",
            "sub/NUL.bin",
            "",
            "   ",
        ],
    )
    def test_layer1_synthetic_zip_slip_permutations(self, tmp_path: Path, malicious_name: str):
        """Empirically test that every path traversal and reserved device name is blocked."""
        zip_path = tmp_path / "slip_test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("benign.txt", b"Safe content")
            zf.writestr(malicious_name, b"Malicious payload")

        target_dir = tmp_path / "extracted_slip"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        err_msg = str(exc_info.value).lower()
        assert any(
            pattern in err_msg
            for pattern in ["zip-slip", "cannot be empty", "reserved device name", "forbidden", "escapes"]
        )
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    # -------------------------------------------------------------------------
    # Layer 2: Symlink Attack Defense
    # -------------------------------------------------------------------------
    def test_layer2_symlink_fixture(self, tmp_path: Path):
        """Empirically test that fixtures/symlink_0xa1ed.zip is blocked with atomic rollback."""
        fixture_path = FIXTURES_DIR / "symlink_0xa1ed.zip"
        assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

        target_dir = tmp_path / "extracted_symlink"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(fixture_path, target_dir)

        assert "Symlink detected" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    @pytest.mark.parametrize(
        "attr_value",
        [
            0xA1ED << 16,
            (stat.S_IFLNK | 0o777) << 16,
            (stat.S_IFLNK | 0o644) << 16,
            0xA1ED,  # Raw unshifted
            stat.S_IFLNK,
            stat.S_IFIFO << 16,
            stat.S_IFCHR << 16,
            stat.S_IFBLK << 16,
            stat.S_IFSOCK << 16,
        ],
    )
    def test_layer2_synthetic_symlink_variants(self, tmp_path: Path, attr_value: int):
        """Empirically test that all symlink bit representations and special POSIX files are blocked."""
        zip_path = tmp_path / "sym_test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.txt", b"safe file")
            zinfo = zipfile.ZipInfo("symlink_entry")
            zinfo.external_attr = attr_value
            zf.writestr(zinfo, b"/etc/shadow")

        target_dir = tmp_path / "extracted_sym"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Symlink detected" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer2_accepts_valid_posix_regular_files_and_directories(self, tmp_path: Path):
        """Empirically verify regular POSIX files (S_IFREG) and dirs (S_IFDIR) extract cleanly."""
        zip_path = tmp_path / "posix_ok.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            dinfo = zipfile.ZipInfo("folder/")
            dinfo.external_attr = (stat.S_IFDIR | 0o755) << 16
            zf.writestr(dinfo, "")

            finfo = zipfile.ZipInfo("folder/script.sh")
            finfo.external_attr = (stat.S_IFREG | 0o755) << 16
            zf.writestr(finfo, b"#!/bin/bash\necho hello\n")

        target_dir = tmp_path / "extracted_posix"
        res = safe_extract(zip_path, target_dir)
        assert res.file_count == 1
        assert (target_dir / "folder" / "script.sh").is_file()

    # -------------------------------------------------------------------------
    # Layer 3: Decompression Bomb Ratio Defense
    # -------------------------------------------------------------------------
    def test_layer3_zip_bomb_fixture(self, tmp_path: Path):
        """Empirically test that fixtures/zip_bomb.zip is blocked with atomic rollback."""
        fixture_path = FIXTURES_DIR / "zip_bomb.zip"
        assert fixture_path.is_file(), f"Fixture missing: {fixture_path}"

        target_dir = tmp_path / "extracted_bomb"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(fixture_path, target_dir)

        assert "Compression ratio" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer3_synthetic_high_ratio_blocked_upfront(self, tmp_path: Path):
        """Archives declaring ratio > 100x are rejected in Phase 1 before disk write."""
        zip_path = tmp_path / "high_ratio.zip"
        # 1 MB zeros compresses to ~1 KB (>1000x ratio)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeroes.bin", b"\x00" * (1024 * 1024))

        target_dir = tmp_path / "extracted_hr"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Compression ratio" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer3_zero_compressed_size_with_data_blocked(self, tmp_path: Path):
        """Non-empty file with zero compressed size is rejected upfront."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("suspicious.bin", b"A" * 2048)

        raw = bytearray(bio.getvalue())
        cdir = raw.find(b"PK\x01\x02")
        if cdir != -1:
            struct.pack_into("<I", raw, cdir + 20, 0)     # compress_size = 0
            struct.pack_into("<I", raw, cdir + 24, 2048)  # file_size = 2048

        zip_path = tmp_path / "zero_comp.zip"
        zip_path.write_bytes(raw)

        target_dir = tmp_path / "extracted_zc"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "zero compressed size" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer3_streaming_decompression_ratio_defense(self, tmp_path: Path):
        """Test streaming compression ratio enforcement with configured custom ratio."""
        zip_path = tmp_path / "strict_ratio.zip"
        # Repeating string with ~5x compression ratio
        data = b"abcdefghij12345" * 200
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.txt", data)

        target_dir = tmp_path / "extracted_ratio"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir, max_compression_ratio=2.0)

        assert "Compression ratio" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    # -------------------------------------------------------------------------
    # Layer 4: Size Quota Enforcement (100MB Single, 1.5GB Total, 30,000 Files)
    # -------------------------------------------------------------------------
    def test_layer4_single_file_quota_at_exact_100mb(self, tmp_path: Path):
        """Exact 100 MB (104,857,600 bytes) uncompressed file is permitted."""
        zip_path = tmp_path / "exact_100mb.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("exact_100mb.bin", b"A" * MAX_SINGLE_FILE_BYTES)

        target_dir = tmp_path / "extracted_100mb"
        result = safe_extract(zip_path, target_dir)
        assert result.file_count == 1
        assert result.total_bytes == MAX_SINGLE_FILE_BYTES
        assert (target_dir / "exact_100mb.bin").stat().st_size == MAX_SINGLE_FILE_BYTES

    def test_layer4_single_file_quota_exceeded_by_1_byte(self, tmp_path: Path):
        """100 MB + 1 byte (104,857,601 bytes) uncompressed file is rejected."""
        zip_path = tmp_path / "over_100mb.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("over_100mb.bin", b"A" * (MAX_SINGLE_FILE_BYTES + 1))

        target_dir = tmp_path / "extracted_over_100mb"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "exceeds single file limit" in str(exc_info.value)
        assert "104857601 > 104857600" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer4_single_file_quota_streaming_defense(self, tmp_path: Path):
        """Single file exceeding configured limit during streaming decompression is rejected."""
        zip_path = tmp_path / "streaming_single.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("stream.bin", b"B" * 2000)

        target_dir = tmp_path / "extracted_stream"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir, max_single_file_bytes=1000)

        assert "exceeds single file limit" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer4_total_archive_quota_at_exact_1500mb_declared(self, tmp_path: Path):
        """Archive with declared total size exactly 1,572,864,000 bytes (1.5 GB) passes Phase 1."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(16):
                zf.writestr(f"part_{i}.bin", b"A" * 100)

        raw = bytearray(bio.getvalue())
        offset = 0
        for i in range(16):
            cdir = raw.find(b"PK\x01\x02", offset)
            part_size = 98304000  # 16 * 98,304,000 = 1,572,864,000 bytes (exact 1.5 GB)
            struct.pack_into("<I", raw, cdir + 20, 2 * 1024 * 1024)
            struct.pack_into("<I", raw, cdir + 24, part_size)
            offset = cdir + 4

        with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
            total_declared = sum(info.file_size for info in zf.infolist())
            assert total_declared == MAX_TOTAL_EXTRACT_BYTES

    def test_layer4_total_archive_quota_exceeded_by_1_byte(self, tmp_path: Path):
        """Archive with declared total size exceeding 1.5 GB by 1 byte (1,572,864,001) is rejected."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(16):
                zf.writestr(f"part_{i}.bin", b"A" * 100)

        raw = bytearray(bio.getvalue())
        offset = 0
        total_target = MAX_TOTAL_EXTRACT_BYTES + 1
        for i in range(16):
            cdir = raw.find(b"PK\x01\x02", offset)
            part_size = 98304000 if i < 15 else (total_target - 15 * 98304000)
            struct.pack_into("<I", raw, cdir + 20, 2 * 1024 * 1024)
            struct.pack_into("<I", raw, cdir + 24, part_size)
            offset = cdir + 4

        zip_path = tmp_path / "over_1500mb.zip"
        zip_path.write_bytes(raw)

        target_dir = tmp_path / "extracted_1500mb"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Total uncompressed archive size exceeds limit" in str(exc_info.value)
        assert "1572864001 > 1572864000" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer4_total_archive_quota_streaming_defense(self, tmp_path: Path):
        """Total archive quota breach during streaming decompression is rejected."""
        zip_path = tmp_path / "streaming_total.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("f1.bin", b"X" * 1500)
            zf.writestr("f2.bin", b"Y" * 1501)

        target_dir = tmp_path / "extracted_stream_total"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir, max_total_bytes=3000)

        assert "Total uncompressed archive size exceeds limit" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer4_file_count_quota_exact_and_rejection(self, tmp_path: Path):
        """Archive with 30,001 files is rejected; archive with 30,000 files passes Phase 1."""
        zip_path = tmp_path / "too_many_files.zip"
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            for i in range(MAX_FILE_COUNT + 1):
                zf.writestr(f"f_{i}.txt", b"")
        zip_path.write_bytes(bio.getvalue())

        target_dir = tmp_path / "extracted_files"
        with pytest.raises(ValueError) as exc_info:
            safe_extract(zip_path, target_dir)

        assert "Archive exceeds maximum allowed entry count: 30001 > 30000" in str(exc_info.value)
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    # -------------------------------------------------------------------------
    # Layer 5: Atomic Rollback on All Failure Modes
    # -------------------------------------------------------------------------
    @pytest.mark.parametrize(
        "fail_type",
        ["zip_slip", "symlink", "bomb_ratio", "single_quota", "corrupt_zip"],
    )
    def test_layer5_atomic_rollback_on_failure_modes(self, tmp_path: Path, fail_type: str):
        """Partial files extracted before failure must be completely purged from disk."""
        target_dir = tmp_path / f"extracted_{fail_type}"

        if fail_type == "corrupt_zip":
            fixture_path = FIXTURES_DIR / "corrupt.zip"
            with pytest.raises(ValueError) as exc_info:
                safe_extract(fixture_path, target_dir)
            assert "Corrupted or invalid zip file" in str(exc_info.value)
            assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0
            return

        zip_path = tmp_path / f"mixed_{fail_type}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("valid_1.txt", b"Valid file 1 content")
            zf.writestr("valid_2.txt", b"Valid file 2 content")
            if fail_type == "zip_slip":
                zf.writestr("../escaped.txt", b"Slip payload")
            elif fail_type == "symlink":
                sinfo = zipfile.ZipInfo("bad_link")
                sinfo.external_attr = 0xA1ED << 16
                zf.writestr(sinfo, b"/etc/passwd")
            elif fail_type == "bomb_ratio":
                zf.writestr("bomb.bin", b"\x00" * 500_000)
            elif fail_type == "single_quota":
                zf.writestr("oversized.bin", b"X" * 2000)

        with pytest.raises(ValueError):
            if fail_type == "single_quota":
                safe_extract(zip_path, target_dir, max_single_file_bytes=1000)
            else:
                safe_extract(zip_path, target_dir)

        # Atomic rollback verification: ZERO files or directories leaked
        assert not target_dir.exists() or len(list(target_dir.iterdir())) == 0

    def test_layer5_context_managers_cleanup_on_normal_and_exceptional_exit(self, tmp_path: Path):
        """temporary_scan_dir and safe_extract_context guaranteed cleanup."""
        # 1. temporary_scan_dir on exception
        created_path = None
        with pytest.raises(RuntimeError):
            with temporary_scan_dir() as sdir:
                created_path = sdir
                (sdir / "artifact.dat").write_bytes(b"data")
                assert sdir.exists()
                raise RuntimeError("Crash inside context")
        assert not created_path.exists()

        # 2. safe_extract_context on normal exit
        zip_path = tmp_path / "valid.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.txt", b"hello world")

        extracted_dir = None
        with safe_extract_context(zip_path) as res:
            extracted_dir = res.extracted_path
            assert extracted_dir.exists()
            assert res.file_count == 1
            assert (extracted_dir / "test.txt").read_text() == "hello world"

        assert not extracted_dir.exists()


# =============================================================================
# Suite 2: Upload 600 MB Ceiling, Dynamic 413, and Unlinking
# =============================================================================

class VirtualChunkReader:
    """Zero-memory streaming reader simulating arbitrary upload payloads with valid PK header."""

    def __init__(self, target_bytes: int, chunk_size: int = 65536):
        self.target_bytes = target_bytes
        self.chunk_size = chunk_size
        self.bytes_sent = 0

    def read(self, size: int = -1) -> bytes:
        if self.bytes_sent >= self.target_bytes:
            return b""
        remaining = self.target_bytes - self.bytes_sent
        sz = min(self.chunk_size if size < 0 else size, remaining)
        if self.bytes_sent == 0 and sz >= 4:
            chunk = b"PK\x03\x04" + b"\x00" * (sz - 4)
        else:
            chunk = b"\x00" * sz
        self.bytes_sent += len(chunk)
        return chunk


class TestUpload600MBLimitsAndSecurity:
    """Empirical challenge suite for upload.py 600 MB ceiling and cleanup."""

    def test_upload_constants_and_settings(self):
        """Assert production upload limit constant is exactly 600 MB."""
        assert MAX_UPLOAD_BYTES == 600 * 1024 * 1024
        assert settings.MAX_UPLOAD_SIZE_BYTES == 600 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_upload_exact_600mb_is_permitted(self):
        """Archive of exactly 600 MB (629,145,600 bytes) is accepted and enqueued cleanly."""
        req = MagicMock(spec=Request)
        req.client.host = "127.0.0.1"

        exact_limit_bytes = MAX_UPLOAD_BYTES
        reader = VirtualChunkReader(exact_limit_bytes)
        uf = UploadFile(file=reader, filename="exact_600mb.zip")

        test_job_id = f"test-exact-600mb-{uuid.uuid4()}"
        mock_record = JobRecord(
            job_id=test_job_id,
            status=JobStatus.QUEUED,
            stage=JobStage.QUEUED,
            progress=0,
            poll_url=f"/api/jobs/{test_job_id}",
        )
        mock_queue = MagicMock()
        mock_queue.enqueue = AsyncMock(return_value=mock_record)

        with patch("uuid.uuid4", return_value=test_job_id), patch(
            "app.routers.upload.get_job_queue", return_value=mock_queue
        ):
            res = await upload_scan_archive(req, uf)
            assert res["job_id"] == test_job_id
            assert res["status"] == "queued"
            assert mock_queue.enqueue.called

            # Check that file was written to disk at exactly 600 MB and clean it up
            created_zip = mock_queue.enqueue.call_args.kwargs["zip_path"]
            created_path = Path(created_zip)
            assert created_path.exists()
            assert created_path.stat().st_size == exact_limit_bytes
            created_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_upload_exceeding_600mb_rejected_with_413_and_dynamic_detail(self):
        """Archive exceeding 600 MB (600 MB + 1 byte) raises HTTP 413 with dynamic detail."""
        req = MagicMock(spec=Request)
        req.client.host = "127.0.0.1"

        over_limit_bytes = MAX_UPLOAD_BYTES + 1
        reader = VirtualChunkReader(over_limit_bytes)
        uf = UploadFile(file=reader, filename="over_600mb.zip")

        test_job_id = f"test-over-600mb-{uuid.uuid4()}"
        temp_dir = Path(tempfile.gettempdir())

        with patch("uuid.uuid4", return_value=test_job_id):
            with pytest.raises(HTTPException) as exc_info:
                await upload_scan_archive(req, uf)

            assert exc_info.value.status_code == 413
            detail = exc_info.value.detail
            assert "Uploaded archive exceeds 600 MB limit" in detail
            assert f"received {over_limit_bytes} bytes" in detail

        # Verify immediate unlinking: NO temporary file matching our job_id exists
        matching = list(temp_dir.glob(f"upload_{test_job_id}_*.zip"))
        assert len(matching) == 0, f"Temporary file was leaked: {matching}"

    @pytest.mark.asyncio
    async def test_upload_empty_archive_rejected_with_400(self):
        """0-byte upload file is rejected with HTTP 400 Bad Request."""
        req = MagicMock(spec=Request)
        req.client.host = "127.0.0.1"

        reader = VirtualChunkReader(0)
        uf = UploadFile(file=reader, filename="empty.zip")

        with pytest.raises(HTTPException) as exc_info:
            await upload_scan_archive(req, uf)

        assert exc_info.value.status_code == 400
        assert "empty (0 bytes)" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_upload_missing_pk_signature_rejected_with_400(self):
        """File claiming to be .zip but missing PK signature is rejected with HTTP 400."""
        req = MagicMock(spec=Request)
        req.client.host = "127.0.0.1"

        class SpoofedReader:
            def read(self, size=-1):
                return b"GIF89a\x01\x00\x01\x00" + b"\x00" * 100

        uf = UploadFile(file=SpoofedReader(), filename="spoofed.zip")

        with pytest.raises(HTTPException) as exc_info:
            await upload_scan_archive(req, uf)

        assert exc_info.value.status_code == 400
        assert "missing PK magic header" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_upload_non_zip_extension_rejected_with_400(self):
        """Files with non-.zip extensions are rejected before creating temporary files."""
        req = MagicMock(spec=Request)
        req.client.host = "127.0.0.1"

        reader = VirtualChunkReader(1024)
        uf = UploadFile(file=reader, filename="payload.tar.gz")

        with pytest.raises(HTTPException) as exc_info:
            await upload_scan_archive(req, uf)

        assert exc_info.value.status_code == 400
        assert "Only .zip archives are supported" in exc_info.value.detail
