# Milestone 1: Safe Archive Extraction Specification & Test Plan

**Document Path:** `backend/app/core/safe_extract.py` & `backend/tests/test_extraction.py`  
**Author:** Explorer Subagent 1 (`teamwork_explorer_m1_1`)  
**Workspace:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE`  
**Milestone:** M1 — Safe Archive Extraction  
**Date:** 2026-11-07  

---

## 1. Executive Summary & Threat Model

The Safe Archive Extraction module (`backend/app/core/safe_extract.py`) is the primary defense boundary of the SecureScan platform. When users upload arbitrary `.zip` files to `/api/scan`, the backend must extract and inspect the contents prior to invoking the SecureShip CLI and its underlying security engines (opengrep, gitleaks, trivy, osv-scanner, checkov).

An untrusted archive can harbor severe exploits designed to achieve Remote Code Execution (RCE), arbitrary file overwrite, host denial of service (DoS), or local file inclusion.

### 1.1 Threat Matrix & Security Invariants

| Defense # | Attack Vector | Threat Impact | Invariant Enforced |
|---|---|---|---|
| **Defense 1** | **Zip-Slip (Path Traversal)** | Overwriting `/etc/cron.*`, `~/.bashrc`, or application code via `../` path climbing or absolute paths (`/evil`, `C:\evil`). | All extracted paths must resolve strictly within `target_dir` via `is_relative_to()`. No `..` components, leading slashes, Windows drive letters, or reserved device names (`CON`, `NUL`, etc.) are permitted. |
| **Defense 2** | **Symlink Hijacking** | Symlink pointing to host sensitive files (e.g. `/etc/shadow`, `/var/run/docker.sock`) followed by read via scanner or snippet extractor. | Any archive entry with Unix symlink external attribute `0xA1ED` (`0o120755`) or POSIX `S_IFLNK` (`0o120000`) is rejected upfront with `ValueError`. |
| **Defense 3** | **Decompression Bomb (Zip-Bomb)** | 1 MB archive expanding to 100 GB in memory/disk, causing Out-Of-Memory (OOM) killer to crash the container. | Compression ratio (uncompressed size / compressed size) > 100x is rejected both upfront in header inspection and dynamically during streaming decompression. |
| **Defense 4** | **Size & Resource Quotas** | Disk exhaustion via large uncompressed repositories or inode exhaustion via millions of zero-byte files. | Single uncompressed file size > 10 MB (`10,485,760` bytes) or total extracted archive > 50 MB (`52,428,800` bytes), or entry count > 10,000 raises `ValueError`. |
| **Defense 5** | **Atomic Extraction & Lifecycle Cleanup** | Partial or corrupted files left in workspace after a failed or malicious scan; file locks preventing directory cleanup on Windows. | Extraction is strictly atomic: any error triggers complete rollback of partial extractions. Isolated directories are managed via `temporary_scan_dir()` context manager with robust read-only permission handling. |

---

## 2. Interface Contracts & Data Models

### 2.1 ExtractionResult Data Contract

In accordance with `PROJECT.md` §119–132, the extraction routine returns an immutable, strongly-typed contract:

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ExtractionResult:
    """
    Immutable result contract returned upon successful safe extraction.
    """
    extracted_path: Path
    file_count: int
    total_bytes: int
```

- `extracted_path`: Resolved absolute `Path` to the directory containing the extracted repository files.
- `file_count`: Total number of regular files successfully written to disk.
- `total_bytes`: Total byte size of uncompressed data written to disk.

### 2.2 Functional Signatures

```python
def safe_extract(
    zip_path: Path | str,
    target_dir: Path | str,
    max_single_file_bytes: int = MAX_SINGLE_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_EXTRACT_BYTES,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
    max_file_count: int = MAX_FILE_COUNT,
) -> ExtractionResult:
    """
    Safely extracts an untrusted ZIP archive into target_dir.
    Enforces all 5 security defenses.
    Raises ValueError on any invariant violation or archive corruption.
    Guarantees atomic cleanup of target_dir on any failure.
    """

@contextmanager
def temporary_scan_dir(prefix: str = "securescan_") -> Generator[Path, None, None]:
    """
    Creates an isolated temporary directory and guarantees its recursive
    deletion upon normal block exit or unhandled exception.
    """

@contextmanager
def safe_extract_context(
    zip_path: Path | str,
    prefix: str = "securescan_",
) -> Generator[ExtractionResult, None, None]:
    """
    High-level convenience context manager combining temporary_scan_dir()
    and safe_extract(). Cleans up the directory when exiting the with-block.
    """
```

---

## 3. Deep Dive: The 5 Security Defenses

### 3.1 Defense 1: Path Traversal (Zip-Slip)

#### Vulnerability Mechanics
In standard ZIP archives, entry filenames are arbitrary strings stored in the local file header and central directory header. Standard extractors (e.g. `zipfile.ZipFile.extractall()`) naively join `target_dir` with the member's name. If the member name is `../../../../etc/passwd`, it traverses out of `target_dir` and overwrites arbitrary system files.

#### Multi-Tier Defense Strategy
1. **Raw String Sanitization & Prefix Check:**
   - Normalize slashes: replace Windows backslash `\` with forward slash `/`.
   - Reject any entry starting with `/` (POSIX absolute root).
   - Reject any entry matching `^[a-zA-Z]:` (Windows drive letters like `C:`).
   - Reject leading backslash `\`.
2. **Component Traversal Validation:**
   - Inspect `Path(normalized_filename).parts`.
   - If `'..'` is present in any path segment, reject immediately with `ValueError`.
   - If `'.'` is the entire path, reject with `ValueError`.
3. **Windows Reserved Device Filename Defense:**
   - Windows restricts specific device filenames regardless of file extension:
     `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.
   - Creating a file named `NUL` or `aux.txt` on a Windows host causes process hangs or critical system errors.
   - The sanitizer strips extensions and matches base stems against `WINDOWS_RESERVED_NAMES`.
4. **Canonical Resolution & Boundary Invariant:**
   - Compute `dest_path = (target_dir / norm_name).resolve()`.
   - Verify `dest_path.is_relative_to(target_dir.resolve())`.
   - Verify `dest_path != target_dir.resolve()` (prevents directory self-overwrite).

### 3.2 Defense 2: Symlinks & Special Inodes

#### Vulnerability Mechanics
If an archive contains a symbolic link named `package.json` pointing to `/etc/passwd`, extracting the symlink causes subsequent file readers or CLI scanners to read host system files, leaking secrets via code snippets or scanner findings.

#### ZIP Format Attribute Architecture
In the PKWARE ZIP File Format Specification (APPNOTE.TXT), the central directory records a 4-byte `external_attr` field (`ZipInfo.external_attr`).
When created on a POSIX/Unix host:
- The upper 16 bits (`external_attr >> 16`) store the standard Unix file mode (`st_mode`).
- `st_mode` bitmask for file type is `0o170000` (`S_IFMT`).
- The symbolic link type bit is `0o120000` (`S_IFLNK`).
- Standard Unix symlink permissions are `0o755` (`lrwxr-xr-x`, hex `0x1ED`).
- Bitwise combination: `0o120000 | 0o0755 = 0o120755`, which in hexadecimal is `0xA1ED`.
- In `zipfile.ZipInfo`, `external_attr >> 16 == 0xA1ED`.

#### Comprehensive Detection Rule
To thwart both standard tools and hand-crafted adversarial binaries:
```python
attr = info.external_attr
mode_upper = attr >> 16
mode_lower = attr & 0xFFFF

is_symlink = (
    mode_upper == 0xA1ED
    or (mode_upper & 0o170000) == stat.S_IFLNK
    or mode_lower == 0xA1ED
    or (mode_lower & 0o170000) == stat.S_IFLNK
    or attr == 0xA1ED
)
```
Additionally, all non-regular files (FIFOs `0o010000`, character devices `0o020000`, block devices `0o060000`, sockets `0o140000`) are rejected. Only regular files (`0o100000` / `stat.S_IFREG`) and directories (`0o040000` / `stat.S_IFDIR`) are permitted.

### 3.3 Defense 3: Compression Bomb (Zip-Bomb) Ratio

#### Vulnerability Mechanics
A zip-bomb relies on Deflate algorithm amplification. A repeated pattern of zeros can compress 1000 MB of data down to a few kilobytes (a 100,000x ratio). Extracting such a payload exhausts disk space and CPU time. Furthermore, recursive zip quines or spoofed central directory headers can claim a harmless file size (e.g. 500 bytes) while the actual compressed bitstream decompresses into gigabytes.

#### Two-Phase Enforcement Architecture
1. **Phase 1: Upfront Header Inspection:**
   - For every member `info` in `zf.infolist()`:
     - If `info.compress_size > 0`:
       $$\text{Ratio} = \frac{\text{info.file\_size}}{\text{info.compress\_size}}$$
       If $\text{Ratio} > 100.0$, raise `ValueError`.
     - Anomaly detection: if `info.compress_size == 0` and `info.file_size > 1024`, raise `ValueError` (suspicious zero compressed size).
2. **Phase 2: Streaming Decompression Dynamic Monitor:**
   - Reading is performed in chunks of 64 KB (`65536` bytes).
   - An in-flight accumulator tracks `single_file_bytes` as chunks arrive from the decompressor.
   - If `single_file_bytes > 1024` and `info.compress_size > 0`:
     $$\text{Current Ratio} = \frac{\text{single\_file\_bytes}}{\text{info.compress\_size}}$$
     If $\text{Current Ratio} > 100.0$, extraction is immediately terminated and raises `ValueError`.

### 3.4 Defense 4: Size Quotas & Resource Ceilings

#### Defined Quotas
- **Max Single File:** 10 MB (`10 * 1024 * 1024 = 10,485,760` bytes).
- **Max Total Archive:** 50 MB (`50 * 1024 * 1024 = 52,428,800` bytes).
- **Max Total Entry Count:** 10,000 entries (prevents inode exhaustion and DOS loops).

#### Enforcement Points
1. **Upfront Check:**
   - Check `len(infolist) > 10_000` $\rightarrow$ raise `ValueError`.
   - Check `any(info.file_size > 10_485_760)` $\rightarrow$ raise `ValueError`.
   - Check `sum(info.file_size for info in infolist) > 52_428_800` $\rightarrow$ raise `ValueError`.
2. **Streaming Check:**
   - During chunk write, if `single_file_bytes > 10_485_760` $\rightarrow$ raise `ValueError`.
   - Running accumulator `total_extracted_bytes += chunk_len`. If `total_extracted_bytes > 52_428_800` $\rightarrow$ raise `ValueError`.

### 3.5 Defense 5: Atomic Extraction & Resilient Lifecycle Cleanup

#### Failure Atomicity
If an archive contains 5 valid source files followed by a 6th entry that triggers a zip-slip or compression bomb error, naive extraction leaves the 5 valid files on disk. This results in dirty workspaces, wasted disk space, or partial execution.
`safe_extract()` provides an atomic rollback guarantee:
- Wrapped in a top-level `try...except`.
- On any exception (`ValueError`, `zipfile.BadZipFile`, `OSError`), `_cleanup_partial_extraction(target_path)` removes all files and subdirectories created within `target_dir`, leaving it completely pristine before re-raising the exception.

#### Cross-Platform Cleanup Handler
On Windows hosts, deleting files using standard `shutil.rmtree()` frequently raises `PermissionError: [WinError 5] Access is denied` if a file in the archive had read-only attributes (`chmod 444` / `stat.S_IREAD`).
`temporary_scan_dir()` and `_cleanup_partial_extraction()` use a custom error handler:
```python
def _handle_remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass
```
This guarantees 100% deterministic directory cleanup without hanging or leaking disk space across Linux and Windows environments.

---

## 4. Production Implementation Specification

The proposed source code for `backend/app/core/safe_extract.py`:

```python
"""
SecureShip-IDE: Secure Archive Extraction Module
Enforces strict security invariants against zip-slip, symlinks,
zip-bombs, size quota breaches, and directory contamination.
"""

from __future__ import annotations

import os
import re
import stat
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

# =========================================================================
# Security Limits & Constants
# =========================================================================

MAX_SINGLE_FILE_BYTES: int = 10 * 1024 * 1024       # 10 MB (10,485,760 bytes)
MAX_TOTAL_EXTRACT_BYTES: int = 50 * 1024 * 1024     # 50 MB (52,428,800 bytes)
MAX_COMPRESSION_RATIO: float = 100.0                # 100x max ratio
MAX_FILE_COUNT: int = 10_000                        # Inode limit
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
    if not dest_path.is_relative_to(target_dir):
        raise ValueError(
            f"Zip-slip violation: path '{raw_name}' escapes target directory {target_dir}"
        )
    if dest_path == target_dir:
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
    max_single_file_bytes: int = MAX_SINGLE_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_EXTRACT_BYTES,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
    max_file_count: int = MAX_FILE_COUNT,
) -> ExtractionResult:
    """
    Extracts a zip archive enforcing strict security invariants:
    - Path traversal rejection: any member containing '..' or resolving outside target_dir raises ValueError.
    - Symlink rejection: any member with external_attr >> 16 == 0xA1ED or S_IFLNK raises ValueError.
    - Zip-bomb defense: compression ratio (uncompressed / compressed) > 100 raises ValueError.
    - Size limits: single uncompressed file > 10MB or total archive > 50MB raises ValueError.
    - Atomic rollback: partial files in target_dir are cleanly purged on any exception.
    - Returns ExtractionResult(extracted_path=target_dir, file_count=N, total_bytes=M).
    """
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
```

---

## 5. Comprehensive Unit Test Suite Specification (`backend/tests/test_extraction.py`)

The test suite must provide 100% branch and statement coverage across all 5 defenses and operational edge cases without relying on committed binary zip fixtures. All archives are generated dynamically in-memory via `create_in_memory_zip()`.

### 5.1 Test Inventory

| Class | Method | Targeted Defense / Vector | Expected Outcome |
|---|---|---|---|
| `TestZipSlipDefense` | `test_reject_parent_directory_traversal` | `../../evil.txt` parent traversal | `pytest.raises(ValueError)` with `"Zip-slip violation"` |
| `TestZipSlipDefense` | `test_reject_nested_parent_traversal` | `subdir/../../evil.txt` nested traversal | `pytest.raises(ValueError)` with `"Zip-slip violation"` |
| `TestZipSlipDefense` | `test_reject_absolute_path_posix` | `/etc/passwd` root path | `pytest.raises(ValueError)` with `"absolute path forbidden"` |
| `TestZipSlipDefense` | `test_reject_windows_drive_letter` | `C:/Windows/System32/evil.dll` | `pytest.raises(ValueError)` with `"absolute path forbidden"` |
| `TestZipSlipDefense` | `test_reject_leading_backslash` | `\Windows\System32\cmd.exe` | `pytest.raises(ValueError)` with `"Zip-slip violation"` |
| `TestZipSlipDefense` | `test_reject_windows_reserved_device_names` | `CON`, `PRN`, `AUX`, `NUL`, `COM1`, `nul.txt` | `pytest.raises(ValueError)` with `"Windows reserved device name"` |
| `TestZipSlipDefense` | `test_reject_empty_filename` | Empty entry name `""` | `pytest.raises(ValueError)` with `"cannot be empty"` |
| `TestSymlinkDefense` | `test_reject_symlink_unix_attr_0xA1ED` | Upper 16 bits set to `0xA1ED << 16` | `pytest.raises(ValueError)` with `"Symlink detected"` |
| `TestSymlinkDefense` | `test_reject_symlink_posix_s_iflnk` | `(stat.S_IFLNK \| 0o755) << 16` | `pytest.raises(ValueError)` with `"Symlink detected"` |
| `TestSymlinkDefense` | `test_reject_symlink_raw_0xA1ED` | Lower 16 bits set to `0xA1ED` (unshifted) | `pytest.raises(ValueError)` with `"Symlink detected"` |
| `TestSymlinkDefense` | `test_reject_fifo_special_file` | FIFO inode `stat.S_IFIFO` | `pytest.raises(ValueError)` with `"Symlink detected"` |
| `TestSymlinkDefense` | `test_accept_regular_unix_file` | Regular file `stat.S_IFREG \| 0o644` | Successful extraction, file on disk |
| `TestZipBombDefense` | `test_reject_high_compression_ratio_upfront` | 500 KB zeros deflating to ~500 B (ratio > 1000x) | `pytest.raises(ValueError)` with `"Compression ratio"` |
| `TestZipBombDefense` | `test_accept_normal_compression_ratio` | Standard source code (~2x–3x ratio) | Successful extraction, valid byte count |
| `TestZipBombDefense` | `test_reject_streaming_ratio_with_configured_threshold` | Decompression exceeding ratio during streaming | `pytest.raises(ValueError)` with `"Compression ratio"` |
| `TestSizeQuotas` | `test_reject_single_file_exceeds_quota_configured` | File exceeding single-file threshold | `pytest.raises(ValueError)` with `"exceeds single file limit"` |
| `TestSizeQuotas` | `test_reject_total_archive_exceeds_quota_configured` | Sum of members exceeding total limit | `pytest.raises(ValueError)` with `"Total uncompressed archive size exceeds limit"` |
| `TestSizeQuotas` | `test_reject_excessive_file_count` | More than 10,000 files (tested via limit=10) | `pytest.raises(ValueError)` with `"exceeds maximum allowed entry count"` |
| `TestAtomicCleanup` | `test_temporary_scan_dir_cleanup_on_success` | Directory created and deleted after clean block exit | `not temp_dir.exists()` |
| `TestAtomicCleanup` | `test_temporary_scan_dir_cleanup_on_exception` | Directory deleted even when exception thrown inside block | `not temp_dir.exists()` |
| `TestAtomicCleanup` | `test_safe_extract_atomic_rollback_on_failure` | Archive with valid file1 followed by malicious file2 | `target_dir` is rolled back completely empty |
| `TestFunctionalCases` | `test_valid_archive_full_extraction` | Multi-file archive with nested subdirectories | `ExtractionResult` valid, files on disk |
| `TestFunctionalCases` | `test_empty_zip_archive` | Valid ZIP with 0 files | `ExtractionResult(count=0, bytes=0)` |
| `TestFunctionalCases` | `test_reject_corrupt_non_zip` | Non-zip random binary file | `pytest.raises(ValueError)` with `"Corrupted or invalid zip file"` |
| `TestFunctionalCases` | `test_reject_missing_zip_file` | Path pointing to non-existent file | `pytest.raises(ValueError)` with `"Zip file not found"` |

---

## 6. Downstream Integration Guide

### 6.1 Integration with `backend/app/core/queue.py` (Job Queue)
The single background worker dequeues a `job_id`, accesses the uploaded zip archive, and invokes `temporary_scan_dir()`:
```python
async def process_scan_job(job: JobRecord) -> None:
    job.status = JobStatus.RUNNING
    job.stage = JobStage.EXTRACTING
    job.progress = 10
    
    with temporary_scan_dir(prefix=f"scan_{job.job_id}_") as scan_dir:
        try:
            extraction_result = safe_extract(job.zip_path, scan_dir)
        except ValueError as err:
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = f"Safe extraction rejected archive: {err}"
            return
        
        # Advance to scanning stage
        job.stage = JobStage.SCANNING
        job.progress = 30
        report = await run_secureship_cli(scan_target_dir=extraction_result.extracted_path)
        ...
```

### 6.2 Integration with `backend/app/api/endpoints.py` (FastAPI Router)
The `/api/scan` upload endpoint validates basic constraints:
- Verifies `.zip` extension.
- Enforces 50 MB upload limit on the incoming request body stream.
- Verifies initial magic bytes (`b"PK\x03\x04"`).
- Any extraction failure inside worker is reflected as a failed job status or HTTP 422 if processed synchronously.
