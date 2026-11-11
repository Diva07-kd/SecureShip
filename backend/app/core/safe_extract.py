"""
SecureShip-IDE: Secure Archive Extraction Module.
Enforces strict security invariants against zip-slip, symlinks,
zip-bombs, size quota breaches, and directory contamination.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Union

# =========================================================================
# Security Limits & Constants
# =========================================================================

MAX_SINGLE_FILE_BYTES: int = 100 * 1024 * 1024      # 100 MB (104,857,600 bytes)
MAX_TOTAL_EXTRACT_BYTES: int = 1500 * 1024 * 1024   # 1500 MB / 1.5 GB (1,572,864,000 bytes)
MAX_COMPRESSION_RATIO: float = 100.0                # 100x max ratio
MAX_FILE_COUNT: int = 30000                         # Inode limit: max 30000 files
CHUNK_SIZE: int = 65536                             # 64 KB streaming buffer

# POSIX File Mode Constants for ZIP external attributes
POSIX_MODE_MASK: int = 0o170000
POSIX_SYMLINK_FLAG: int = stat.S_IFLNK              # 0o120000
POSIX_REGULAR_FLAG: int = stat.S_IFREG              # 0o100000
POSIX_DIR_FLAG: int = stat.S_IFDIR                  # 0o040000
SYMLINK_EXPLICIT_ATTR: int = 0xA1ED                 # Standard Unix symlink (0o120755)

# Windows Reserved Device Names
WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
})


@dataclass(frozen=True)
class ExtractionResult:
    """Immutable result contract returned upon successful safe extraction."""
    extracted_path: Path
    file_count: int
    total_bytes: int

    def __getitem__(self, key: str):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def keys(self):
        return ("extracted_path", "file_count", "total_bytes")

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def items(self):
        return [
            ("extracted_path", self.extracted_path),
            ("file_count", self.file_count),
            ("total_bytes", self.total_bytes),
        ]


def _handle_remove_readonly(func, path, exc_info) -> None:
    """Fallback handler to remove Windows read-only flags during directory cleanup."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def _cleanup_partial_extraction(target_dir: Path) -> None:
    """Removes all items within target_dir to guarantee atomic rollback."""
    if not target_dir.exists():
        return
    for item in target_dir.iterdir():
        if item.is_dir():
            shutil.rmtree(item, onerror=_handle_remove_readonly)
        else:
            try:
                os.chmod(item, stat.S_IWRITE)
                item.unlink(missing_ok=True)
            except Exception:
                pass


@contextmanager
def temporary_scan_dir(prefix: str = "securescan_") -> Generator[Path, None, None]:
    """
    Context manager creating an isolated temporary directory.
    Guarantees recursive deletion of the directory upon exit or failure.
    """
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, onerror=_handle_remove_readonly)


def _validate_path_component(raw_name: str, target_dir: Path) -> Path:
    """
    Defense 1: Validates that a member filename does not escape target_dir.
    Raises ValueError on zip-slip, traversal, absolute paths, or reserved device names.
    """
    if not raw_name or not raw_name.strip():
        raise ValueError("Invalid archive entry: filename cannot be empty")

    norm_name = raw_name.replace("\\", "/")

    # Reject leading slashes or Windows drive letters
    if norm_name.startswith("/") or re.match(r"^[a-zA-Z]:", norm_name):
        raise ValueError(f"Zip-slip violation: absolute path forbidden: '{raw_name}'")

    # Reject directory traversal components
    parts = Path(norm_name).parts
    if ".." in parts:
        raise ValueError(f"Zip-slip violation: traversal sequence '..' detected: '{raw_name}'")
    if "." in parts and len(parts) == 1:
        raise ValueError(f"Zip-slip violation: self-referential '.' entry: '{raw_name}'")

    # Reject Windows reserved device names
    for part in parts:
        stem = part.split(".")[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            raise ValueError(
                f"Zip-slip violation: Windows reserved device name forbidden: '{part}' in '{raw_name}'"
            )

    # Path resolution boundary check
    dest_path = (target_dir / norm_name).resolve()
    if not dest_path.is_relative_to(target_dir.resolve()):
        raise ValueError(
            f"Zip-slip violation: path '{raw_name}' escapes target directory {target_dir}"
        )
    if dest_path == target_dir.resolve():
        raise ValueError(
            f"Zip-slip violation: path '{raw_name}' matches target directory root"
        )

    return dest_path


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    """
    Defense 2: Checks whether a ZipInfo member represents a symlink or special file.
    """
    attr = info.external_attr
    mode_upper = attr >> 16
    mode_lower = attr & 0xFFFF

    # Check explicit 0xA1ED attribute
    if mode_upper == SYMLINK_EXPLICIT_ATTR or mode_lower == SYMLINK_EXPLICIT_ATTR or attr == SYMLINK_EXPLICIT_ATTR:
        return True

    # Check POSIX S_IFLNK bit (0o120000)
    if (mode_upper & POSIX_MODE_MASK) == POSIX_SYMLINK_FLAG or (mode_lower & POSIX_MODE_MASK) == POSIX_SYMLINK_FLAG:
        return True

    # Reject non-standard special files (FIFOs, character/block devices, sockets)
    if mode_upper > 0:
        file_type = mode_upper & POSIX_MODE_MASK
        if file_type not in (POSIX_REGULAR_FLAG, POSIX_DIR_FLAG, 0):
            return True

    return False


def safe_extract(
    zip_path: Path | str,
    target_dir: Path | str,
    max_single_file_bytes: int | None = None,
    max_total_bytes: int | None = None,
    max_compression_ratio: float | None = None,
    max_file_count: int | None = None,
) -> ExtractionResult:
    """
    Extracts a zip archive enforcing strict security invariants:
    - Path traversal rejection: any member containing '..' or resolving outside target_dir raises ValueError.
    - Symlink rejection: any member with external_attr >> 16 == 0xA1ED or S_IFLNK raises ValueError.
    - Zip-bomb defense: compression ratio (uncompressed / compressed) > 100 raises ValueError.
    - Size limits: single uncompressed file > 100MB or total archive > 1.5GB raises ValueError.
    - Atomic rollback: partial files in target_dir are cleanly purged on any exception.
    - Returns ExtractionResult(extracted_path=target_dir, file_count=N, total_bytes=M).
    """
    if max_single_file_bytes is None:
        max_single_file_bytes = MAX_SINGLE_FILE_BYTES
    if max_total_bytes is None:
        max_total_bytes = MAX_TOTAL_EXTRACT_BYTES
    if max_compression_ratio is None:
        max_compression_ratio = MAX_COMPRESSION_RATIO
    if max_file_count is None:
        max_file_count = MAX_FILE_COUNT
    zip_file = Path(zip_path).resolve()
    target_path = Path(target_dir).resolve()

    if not zip_file.is_file():
        raise ValueError(f"Zip file not found: {zip_file}")

    target_path.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_file, "r") as zf:
            infolist = zf.infolist()

            # Quota: Entry count
            if len(infolist) > max_file_count:
                raise ValueError(
                    f"Archive exceeds maximum allowed entry count: {len(infolist)} > {max_file_count}"
                )

            # Phase 1: Upfront header validation scan
            total_declared_uncompressed = 0
            for info in infolist:
                # Defense 2: Symlink detection
                if _is_symlink(info):
                    raise ValueError(
                        f"Symlink detected in archive entry '{info.filename}' (external_attr: 0x{info.external_attr:08X})"
                    )

                # Defense 1: Upfront path traversal check
                _validate_path_component(info.filename, target_path)

                # Defense 4: Single file size declared limit
                if info.file_size > max_single_file_bytes:
                    raise ValueError(
                        f"Entry '{info.filename}' exceeds single file limit: "
                        f"{info.file_size} > {max_single_file_bytes} bytes"
                    )

                # Defense 3: Compression bomb ratio check
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > max_compression_ratio:
                        raise ValueError(
                            f"Compression ratio for '{info.filename}' ({ratio:.1f}x) "
                            f"exceeds maximum allowed ratio ({max_compression_ratio:.1f}x)"
                        )
                elif info.file_size > 1024:
                    raise ValueError(
                        f"Suspicious entry '{info.filename}': non-empty file ({info.file_size} bytes) "
                        "with zero compressed size"
                    )

                total_declared_uncompressed += info.file_size

            # Defense 4: Total archive declared size limit
            if total_declared_uncompressed > max_total_bytes:
                raise ValueError(
                    f"Total uncompressed archive size exceeds limit: "
                    f"{total_declared_uncompressed} > {max_total_bytes} bytes"
                )

            # Phase 2: Streaming decompression and atomic write
            extracted_count = 0
            total_extracted_bytes = 0

            for info in infolist:
                dest = _validate_path_component(info.filename, target_path)

                if info.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)

                single_file_bytes = 0
                with zf.open(info, "r") as src, open(dest, "wb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        chunk_len = len(chunk)
                        single_file_bytes += chunk_len
                        total_extracted_bytes += chunk_len

                        # Streaming Defense 4: Single file limit
                        if single_file_bytes > max_single_file_bytes:
                            raise ValueError(
                                f"Extracted file '{info.filename}' exceeded single-file limit of "
                                f"{max_single_file_bytes} bytes during streaming decompression"
                            )

                        # Streaming Defense 4: Total size limit
                        if total_extracted_bytes > max_total_bytes:
                            raise ValueError(
                                f"Total extracted archive exceeded limit of "
                                f"{max_total_bytes} bytes during streaming decompression"
                            )

                        # Streaming Defense 3: Compression ratio check
                        if single_file_bytes > 1024 and info.compress_size > 0:
                            current_ratio = single_file_bytes / info.compress_size
                            if current_ratio > max_compression_ratio:
                                raise ValueError(
                                    f"Extracted file '{info.filename}' exceeded compression ratio limit "
                                    f"({current_ratio:.1f}x > {max_compression_ratio:.1f}x) during decompression"
                                )

                        dst.write(chunk)

                extracted_count += 1

            return ExtractionResult(
                extracted_path=target_path,
                file_count=extracted_count,
                total_bytes=total_extracted_bytes,
            )

    except zipfile.BadZipFile as e:
        _cleanup_partial_extraction(target_path)
        raise ValueError(f"Corrupted or invalid zip file: {e}") from e
    except Exception:
        _cleanup_partial_extraction(target_path)
        raise


@contextmanager
def safe_extract_context(
    zip_path: Path | str,
    prefix: str = "securescan_",
) -> Generator[ExtractionResult, None, None]:
    """
    Combined context manager creating an isolated temporary directory and
    safely extracting the zip archive into it. Automatically purges the directory on exit.
    """
    with temporary_scan_dir(prefix=prefix) as temp_dir:
        result = safe_extract(zip_path, temp_dir)
        yield result
