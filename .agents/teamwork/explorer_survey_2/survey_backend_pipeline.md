# SecureScan Backend API & Scanner Pipeline Survey & Specification (R1 & R2)

**Author:** Explorer Subagent 2 (`teamwork_explorer`)  
**Workspace:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE`  
**Target:** Heyram Infrastructure Placement Assessment — SecureScan Web Platform  
**Date:** 2026-11-07  

---

## 1. Executive Summary & Architectural Overview

SecureScan is a high-assurance web platform wrapping the SecureShip security engine (`@secureship/cli`) into an accessible developer service. It enables developers and security engineers to upload repository archives (.zip), scan them concurrently using an asynchronous single-worker queue, inspect findings enriched with source snippets and standard taxonomies (CWE and OWASP Top 10), and export audit reports in JSON, SARIF 2.1.0, standalone single-file HTML, and binary PDF formats.

```
                           +------------------------------------------------+
                           |              React Dashboard (UI)              |
                           +------------------------------------------------+
                                   |                         ^
                        POST /api/scan (zip)        GET /api/jobs/{id}
                                   |                GET /api/reports/{id}
                                   v                GET /api/reports/{id}/export
+-----------------------------------------------------------------------------------------+
|                              FastAPI Backend Service                                    |
|                                                                                         |
|  +--------------------+    +--------------------+    +-------------------------------+  |
|  | safe_extract()     | -> | asyncio.Queue      | -> | Single Concurrency Worker     |  |
|  | - Zip-slip         |    | (FIFO, Max Con=1)  |    | - Status State Machine        |  |
|  | - Symlinks (0xA1ED)|    +--------------------+    |   (queued->running->done/fail)|  |
|  | - Bomb ratio >100x |                              +-------------------------------+  |
|  | - Single >10MB     |                                              |                  |
|  | - Total >50MB      |                                              v                  |
|  +--------------------+                             +--------------------------------+  |
|            |                                        | Subprocess Runner              |  |
|            v (Isolated Scratch Dir)                 | - secureship scan <dir> --json |  |
|  +--------------------+                             | - Arg-list form (no shell)     |  |
|  | Temp Workspace     |                             | - 300s hard timeout            |  |
|  | /tmp/securescan_** |                             | - Exit 0 & 1 treated as OK     |  |
|  +--------------------+                             +--------------------------------+  |
|            ^                                                         |                  |
|            | Context Snippet Extraction                              v                  |
|            +-------------------------------------- +---------------------------------+  |
|                                                    | Report Enrichment & Taxonomies  |  |
|                                                    | - CWE & OWASP Top 10 Mapping    |  |
|                                                    | - Reachability Normalization    |  |
|                                                    | - Snippet Extraction (±5 lines) |  |
|                                                    +---------------------------------+  |
|                                                                      |                  |
|                                                                      v                  |
|                                                    +---------------------------------+  |
|                                                    | Multi-Format Exporter           |  |
|                                                    | - JSON (Full ScanReport)        |  |
|                                                    | - SARIF 2.1.0 (OASIS compliant) |  |
|                                                    | - HTML (Single-file inline CSS) |  |
|                                                    | - PDF (Binary via ReportLab)    |  |
|                                                    +---------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. FastAPI Backend Architecture & API Endpoints

### 2.1 Service Directory Layout
The backend will be structured under `backend/` adhering to modern Python / FastAPI best practices:

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                   # FastAPI app instance, CORS middleware, lifespan
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py             # Endpoints: /api/scan, /api/jobs, /api/reports, /api/health
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py             # App configurations, resource limits, paths
│   │   ├── safe_extract.py       # safe_extract() implementation with 5 security controls
│   │   ├── queue.py              # asyncio.Queue and background job worker
│   │   ├── runner.py             # SecureShip CLI subprocess runner (arg-list, 300s timeout)
│   │   ├── snippet.py            # ±5 lines source snippet extractor
│   │   ├── mapper.py             # CWE and OWASP Top 10 (2021) taxonomy mapping
│   │   └── models.py             # Pydantic schemas for requests, responses, findings, reports
│   └── exporters/
│       ├── __init__.py
│       ├── json_exporter.py      # Direct ScanReport JSON serializer
│       ├── sarif_exporter.py     # OASIS SARIF 2.1.0 schema compliant serializer
│       ├── html_exporter.py      # Standalone single-file HTML report with embedded CSS
│       └── pdf_exporter.py       # Binary PDF generator using ReportLab
├── tests/
│   ├── test_safe_extract.py      # Zip-slip, symlink, zip-bomb, size limit tests
│   ├── test_queue.py             # Queue concurrency 1 and state lifecycle tests
│   ├── test_runner.py            # Subprocess execution, exit code 0/1, timeout tests
│   ├── test_mapper.py            # CWE and OWASP mapping tests
│   ├── test_snippet.py           # Context line slicing tests
│   ├── test_api.py               # FastAPI TestClient endpoint integration tests
│   └── test_exporters.py         # JSON, SARIF, HTML, and PDF export validations
├── requirements.txt
└── Dockerfile
```

### 2.2 FastAPI Application Lifespan & Concurrency
The application uses the modern FastAPI `@asynccontextmanager` lifespan protocol.
- **On Startup:**
  - Validates `secureship` CLI presence and runs initial health check.
  - Spawns the single background worker task `asyncio.create_task(queue_worker())`.
- **On Shutdown:**
  - Cancels the queue worker gracefully.
  - Empties any remaining temporary directories.

### 2.3 Detailed Endpoint Specifications

#### 1. `POST /api/scan`
- **Description:** Accepts a `.zip` archive upload up to 50 MB, verifies format, creates an asynchronous scan job, and queues it for execution.
- **Request:**
  - Content-Type: `multipart/form-data`
  - Body: `file: UploadFile`
- **Validation Rules:**
  - Must have a `.zip` filename extension.
  - Upload size must not exceed 50 MB (`50 * 1024 * 1024` bytes). Monitored during streaming chunks; if exceeded, raises HTTP 413 (Payload Too Large).
  - File header magic bytes must match ZIP signature (`PK\x03\x04`).
- **Response (200 OK):**
  ```json
  {
    "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "queued",
    "poll_url": "/api/jobs/f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "message": "Scan job successfully queued"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Invalid file extension or not a zip file.
  - `413 Payload Too Large`: Uploaded file exceeds 50 MB limit.
  - `422 Unprocessable Entity`: Archive is corrupted or fails initial magic byte validation.

#### 2. `GET /api/jobs/{id}`
- **Description:** Returns the real-time execution status and progress of a scan job.
- **Path Parameter:** `id` (string, UUID)
- **Response (200 OK):**
  ```json
  {
    "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "status": "running",
    "stage": "scanning",
    "progress": 55,
    "created_at": "2026-11-07T06:20:00Z",
    "started_at": "2026-11-07T06:20:02Z",
    "completed_at": null,
    "report_url": "/api/reports/f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "error": null
  }
  ```
- **Status Enum:** `queued` | `running` | `done` | `failed`
- **Stage Enum:** `queued` | `extracting` | `scanning` | `enriching` | `completed` | `failed`
- **Error Responses:**
  - `404 Not Found`: Job ID does not exist.

#### 3. `GET /api/reports/{id}`
- **Description:** Retrieves the full, enriched ScanReport JSON containing summary metrics, scanner execution details, and unified findings with snippet context and OWASP Top 10 mappings.
- **Path Parameter:** `id` (string, UUID)
- **Response (200 OK):** Complete unified ScanReport JSON (see Section 6 for full schema).
- **Error Responses:**
  - `404 Not Found`: Job ID does not exist.
  - `409 Conflict`: Scan is still in progress (`queued` or `running`).
  - `422 Unprocessable Entity`: Job failed (details returned in error message).

#### 4. `GET /api/reports/{id}/export?format={json|sarif|html|pdf}`
- **Description:** Exports the scan report in the specified format with appropriate headers for browser download.
- **Query Parameter:** `format` (`json` | `sarif` | `html` | `pdf`), default: `json`
- **Response Headers & Types:**
  - `format=json`:
    - Content-Type: `application/json; charset=utf-8`
    - Content-Disposition: `attachment; filename="secureship-report-{id}.json"`
  - `format=sarif`:
    - Content-Type: `application/sarif+json; charset=utf-8`
    - Content-Disposition: `attachment; filename="secureship-report-{id}.sarif"`
  - `format=html`:
    - Content-Type: `text/html; charset=utf-8`
    - Content-Disposition: `attachment; filename="secureship-report-{id}.html"`
  - `format=pdf`:
    - Content-Type: `application/pdf`
    - Content-Disposition: `attachment; filename="secureship-report-{id}.pdf"`
- **Error Responses:**
  - `400 Bad Request`: Unsupported export format requested.
  - `404 Not Found`: Job ID does not exist.
  - `409 Conflict`: Report not ready yet.

#### 5. `GET /api/health`
- **Description:** Readiness and liveness probe reporting service status, active queue length, and installed scanner binaries.
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "queue": {
      "queued_jobs": 0,
      "is_processing": false,
      "active_job_id": null
    },
    "scanners": {
      "secureship": "ready",
      "opengrep": "ready",
      "gitleaks": "ready",
      "trivy": "ready",
      "osv-scanner": "ready",
      "checkov": "ready"
    },
    "limits": {
      "max_upload_size_mb": 50,
      "max_extracted_size_mb": 50,
      "max_single_file_mb": 10,
      "max_compression_ratio": 100,
      "scan_timeout_seconds": 300
    }
  }
  ```

---

## 3. Safe Extraction (`safe_extract`) Specification

The safe extraction routine is the first line of defense against malicious archive attacks. It strictly rejects malicious archives with clear `ValueError` exceptions before any scanner or child process can touch the files.

### 3.1 Five Core Security Controls

| # | Attack Vector | Security Policy / Limit | Detection & Enforcement Mechanism |
|---|---------------|-------------------------|-----------------------------------|
| 1 | **Zip-Slip (Path Traversal)** | No files outside extract directory | Inspect `member.filename`: reject if starts with `/`, `\`, contains `..` components, or if `(target_dir / member.filename).resolve()` does not satisfy `.is_relative_to(target_dir)`. |
| 2 | **Symlink Hijacking** | Zero symlinks allowed | Inspect `member.external_attr >> 16`: Check Unix mode for `0xA1ED` or `(mode & 0o170000) == 0o120000` (`S_IFLNK`). If matched, reject immediately. |
| 3 | **Decompression Bomb** | Max 100x compression ratio | Check `member.file_size / max(member.compress_size, 1) > 100`. Also track uncompressed bytes during streaming write. |
| 4 | **Single File Exhaustion** | Max 10 MB per individual file | Check `member.file_size > 10 * 1024 * 1024` (10,485,760 bytes). Stop write if streaming bytes exceed 10 MB. |
| 5 | **Total Volume Exhaustion** | Max 50 MB total extracted size | Pre-sum `sum(m.file_size for m in members) > 50 * 1024 * 1024`. Enforce running sum during write across all members. |

### 3.2 Symlink Technical Background: External Attribute `0xA1ED`
In the ZIP file format specification (APPNOTE.TXT), external attributes in the central directory header store host OS file metadata in the upper 16 bits.
Under Unix/POSIX systems:
- File type bits are defined by `sys/stat.h`.
- The mask for file type is `S_IFMT` (`0o170000`).
- The symbolic link type is `S_IFLNK` (`0o120000`, which in hex is `0xA000`).
- Standard symlink permissions are typically `0o755` (`lrwxr-xr-x`, hex `0x1ED`).
- Combined: `0xA000 | 0x1ED = 0xA1ED`.
- In `zipfile.ZipInfo`, `member.external_attr >> 16` equals `0xA1ED`.
- **Enforcement:**
  ```python
  unix_mode = member.external_attr >> 16
  is_symlink = (unix_mode & 0o170000) == 0o120000 or unix_mode == 0xA1ED
  if is_symlink:
      raise ValueError(f"Symlink rejected in archive entry: {member.filename}")
  ```

### 3.3 Complete Python Reference Implementation (`safe_extract`)
```python
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024      # 10 MB
MAX_TOTAL_EXTRACT_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_COMPRESSION_RATIO = 100.0                 # 100x
SYMLINK_UNIX_MODE_MASK = 0o170000
SYMLINK_TYPE_FLAG = 0o120000                  # S_IFLNK
SYMLINK_EXPLICIT_ATTR = 0xA1ED                # Standard POSIX symlink attribute

def safe_extract(zip_path: str | Path, extract_dir: str | Path) -> None:
    """
    Safely extracts a zip archive to extract_dir with complete validation.
    Raises ValueError on zip-slip, symlinks, zip-bombs, or size limit breaches.
    """
    extract_path = Path(extract_dir).resolve()
    zip_path = Path(zip_path).resolve()

    if not zip_path.is_file():
        raise ValueError(f"Zip file not found: {zip_path}")

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            infolist = zf.infolist()

            # 1. Pre-extraction scan: check declared sizes and symlinks
            total_declared_uncompressed = 0
            for info in infolist:
                # Defense 2: Symlink detection
                unix_mode = info.external_attr >> 16
                if (unix_mode & SYMLINK_UNIX_MODE_MASK) == SYMLINK_TYPE_FLAG or unix_mode == SYMLINK_EXPLICIT_ATTR:
                    raise ValueError(f"Symlink detected in entry '{info.filename}' (attribute: 0x{info.external_attr:08X})")

                # Defense 4: Single file size declared limit
                if info.file_size > MAX_SINGLE_FILE_BYTES:
                    raise ValueError(
                        f"Entry '{info.filename}' exceeds single file limit: {info.file_size} > {MAX_SINGLE_FILE_BYTES} bytes"
                    )

                # Defense 3: Compression ratio declared check
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        raise ValueError(
                            f"Compression ratio for '{info.filename}' ({ratio:.1f}x) exceeds maximum allowed ({MAX_COMPRESSION_RATIO}x)"
                        )
                elif info.file_size > 1024:  # 0 compress_size but non-trivial uncompressed size
                    raise ValueError(f"Suspicious zero compressed size for '{info.filename}'")

                total_declared_uncompressed += info.file_size

            # Defense 5: Total declared size check
            if total_declared_uncompressed > MAX_TOTAL_EXTRACT_BYTES:
                raise ValueError(
                    f"Total uncompressed archive size exceeds limit: {total_declared_uncompressed} > {MAX_TOTAL_EXTRACT_BYTES} bytes"
                )

            # 2. Extraction loop: defend against path traversal & header spoofing
            total_extracted_bytes = 0
            for info in infolist:
                # Defense 1: Path Traversal (Zip-Slip)
                raw_filename = info.filename
                # Disallow absolute paths, Windows drive letters, and parent traversal
                if raw_filename.startswith(('/', '\\')) or '..' in Path(raw_filename).parts:
                    raise ValueError(f"Zip-slip path traversal detected: '{raw_filename}'")

                target_dest = (extract_path / raw_filename).resolve()
                if not target_dest.is_relative_to(extract_path):
                    raise ValueError(f"Zip-slip boundary violation: '{raw_filename}' escapes extraction directory")

                # If entry is a directory, create it safely
                if info.is_dir():
                    target_dest.mkdir(parents=True, exist_ok=True)
                    continue

                # Ensure parent directory exists
                target_dest.parent.mkdir(parents=True, exist_ok=True)

                # Stream extraction to prevent memory spikes and catch spoofed file_size
                single_file_bytes = 0
                with zf.open(info, 'r') as src, open(target_dest, 'wb') as dst:
                    while True:
                        chunk = src.read(65536)  # 64 KB chunks
                        if not chunk:
                            break
                        chunk_len = len(chunk)
                        single_file_bytes += chunk_len
                        total_extracted_bytes += chunk_len

                        if single_file_bytes > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"Extracted file '{raw_filename}' exceeded 10 MB during stream write")
                        if total_extracted_bytes > MAX_TOTAL_EXTRACT_BYTES:
                            raise ValueError(f"Total extracted bytes exceeded 50 MB during archive extraction")

                        dst.write(chunk)

    except zipfile.BadZipFile as e:
        raise ValueError(f"Corrupted or invalid zip file: {e}") from e

@contextmanager
def temporary_scan_dir() -> Generator[Path, None, None]:
    """
    Creates an isolated temporary directory and guarantees its deletion on exit or failure.
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="securescan_")).resolve()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
```

---

## 4. Job Queue & Lifecycle Specification (`asyncio.Queue`)

### 4.1 Single Concurrency Guarantee
To operate safely within the container's 3G memory and 1.5 CPU quota, the backend executes at most **one** scan job at a time.
- Uses `asyncio.Queue[str]()` containing pending `job_id` strings.
- A single async background worker loop processes jobs sequentially.
- If multiple uploads arrive simultaneously, they are queued with status `queued` and processed strictly in FIFO order.

### 4.2 Job State Machine & Progress Model

```
+------------+       Worker Dequeues       +-------------+
|   QUEUED   |  =======================>   |   RUNNING   |
| (Prog: 0%) |                             | (Prog: 10%) | [Extracting safe_extract()]
+------------+                             +-------------+
                                                  |
                                                  v
                                           [Scanning CLI]
                                           (Prog: 30% -> 80%)
                                                  |
                                                  v
                                           [Enriching Snippets/OWASP]
                                           (Prog: 90%)
                                                  |
                      +---------------------------+---------------------------+
                      |                                                       |
                      v (CLI exit 0 or 1, Report OK)                          v (Exception / Timeout / Exit >1)
               +-------------+                                         +-------------+
               |    DONE     |                                         |   FAILED    |
               | (Prog:100%) |                                         | (Prog:100%) |
               +-------------+                                         +-------------+
```

### 4.3 Job Storage & Data Structure
Jobs are stored in an in-memory dictionary `dict[str, Job]` with thread-safe async access:

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any

class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

class JobStage(str, Enum):
    QUEUED = "queued"
    EXTRACTING = "extracting"
    SCANNING = "scanning"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class JobRecord:
    job_id: str
    zip_path: str
    status: JobStatus = JobStatus.QUEUED
    stage: JobStage = JobStage.QUEUED
    progress: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    report: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    temp_dir: Optional[str] = None
```

---

## 5. Subprocess Execution & CLI Semantics

### 5.1 CLI Invocation Contract
The worker executes the SecureShip CLI using Python's `asyncio.create_subprocess_exec` in **argument list form**.
- **Forbidden:** Shell string concatenation or `shell=True`.
- **Command Structure:**
  ```python
  cmd = [
      "secureship",
      "scan",
      str(target_extract_dir),
      "--json",
      "--output",
      str(report_output_file),
      "--gate2",
      "annotate"
  ]
  ```
- **Fallback / Local Dev Mode:** If `secureship` is not in the system `PATH` (e.g. running outside Docker during dev), the runner locates `packages/cli/dist/index.js` and invokes `["node", "packages/cli/dist/index.js", "scan", ...]`.

### 5.2 300-Second Hard Timeout
Scans run with a hard 300-second (5 minutes) timeout using `asyncio.wait_for`.
```python
try:
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(target_extract_dir)
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300.0)
except asyncio.TimeoutError:
    try:
        process.kill()
        await process.wait()
    except Exception:
        pass
    raise TimeoutError("Scan execution exceeded 300 seconds hard timeout")
```

### 5.3 Exit Code Handling Matrix
As verified directly in `packages/cli/src/commands/scan.ts` lines 501–534:

| CLI Exit Code | CLI Meaning | Runner Interpretation | Action |
|---------------|-------------|-----------------------|--------|
| **`0`** | Clean scan: no findings above fail threshold. | **SUCCESS** | Parse JSON report, enrich with snippets, transition to `DONE`. |
| **`1`** | Findings found: vulnerabilities detected. | **SUCCESS** | Parse JSON report, enrich with snippets, transition to `DONE`. |
| **`2`** | Usage error: invalid arguments or missing config. | **FAILED** | Record stderr message, transition to `FAILED`. |
| **`3`** | Infrastructure failure: missing scanner or offline violation. | **FAILED** | Record stderr message, transition to `FAILED`. |
| **`>3` / Signal** | Process killed or crash. | **FAILED** | Record failure, transition to `FAILED`. |

---

## 6. Unified Finding Model & Security Taxonomies

### 6.1 Unified Finding Schema
SecureShip CLI outputs findings conforming to `NormalizedFindingSchema` (`@secureship/contracts`). The backend enriches this data into a comprehensive unified model:

```json
{
  "id": "finding-f8a1c3d2-4b5a-4911-8d27-97eb105389c7",
  "fingerprint": "a3b2c1d0e4f5...64 hex chars...",
  "rule_id": "secureship/sast/secureship-py-sql-format",
  "scanner_name": "opengrep",
  "category": "SAST",
  "severity": "HIGH",
  "confidence": "HIGH",
  "reachability": "REACHABLE",
  "reachability_verdict": "REACHABLE",
  "location": {
    "file_path": "backend/app/db.py",
    "start_line": 42,
    "end_line": 42,
    "start_column": 12,
    "end_column": 48
  },
  "title": "SQL Injection in Query Execution",
  "description": "SQL query constructed via string formatting or f-strings before execution. Use parameterized queries.",
  "cwe_ids": ["CWE-89"],
  "owasp_category": "A03:2021-Injection",
  "snippet": {
    "start_line": 37,
    "end_line": 47,
    "vulnerable_start": 42,
    "vulnerable_end": 42,
    "lines": [
      {"line_number": 37, "content": "def get_user_by_name(cursor, username: str):", "is_vulnerable": false},
      {"line_number": 38, "content": "    \"\"\"Fetches user records from database.\"\"\"", "is_vulnerable": false},
      {"line_number": 39, "content": "    if not username:", "is_vulnerable": false},
      {"line_number": 40, "content": "        return None", "is_vulnerable": false},
      {"line_number": 41, "content": "    ", "is_vulnerable": false},
      {"line_number": 42, "content": "    cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")", "is_vulnerable": true},
      {"line_number": 43, "content": "    result = cursor.fetchone()", "is_vulnerable": false},
      {"line_number": 44, "content": "    return result", "is_vulnerable": false},
      {"line_number": 45, "content": "", "is_vulnerable": false},
      {"line_number": 46, "content": "def update_user_email(cursor, user_id, email):", "is_vulnerable": false},
      {"line_number": 47, "content": "    cursor.execute(\"UPDATE users SET email = %s WHERE id = %s\", (email, user_id))", "is_vulnerable": false}
    ]
  },
  "remediation": {
    "explanation": "Replace raw string formatting with parameterized query placeholders (e.g., %s or ?).",
    "suggested_diff": "--- backend/app/db.py\n+++ backend/app/db.py\n-    cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n+    cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"
  }
}
```

### 6.2 CWE & OWASP Top 10 (2021) Mapping Matrix
The mapper module converts scanner findings, raw rule IDs, categories, and CWE numbers to authoritative OWASP Top 10 (2021) categories:

| OWASP Top 10 (2021) Category | Primary CWE IDs | Trigger Categories & Scanner Rules |
|------------------------------|-----------------|-----------------------------------|
| **`A01:2021-Broken Access Control`** | CWE-22 (Path Traversal), CWE-23, CWE-284, CWE-285, CWE-639 (IDOR), CWE-862, CWE-863 | Traversal rules, missing auth checks, IDOR |
| **`A02:2021-Cryptographic Failures`** | CWE-259, CWE-321, CWE-326, CWE-327 (Broken Crypto), CWE-330, CWE-338 (Weak PRNG), CWE-798 | Category: `SECRET`, Gitleaks rules, hardcoded API keys, JWT secret leaks, weak hashes (MD5, SHA1) |
| **`A03:2021-Injection`** | CWE-77, CWE-78 (Command Injection), CWE-79 (XSS), CWE-89 (SQLi), CWE-94 (Code Injection), CWE-95 | SQL string formatting, `child_process.exec`, `eval()`, template injection |
| **`A04:2021-Insecure Design`** | CWE-209 (Error Message Info Leak), CWE-256, CWE-501, CWE-522 | Missing rate limits, plaintext transmission, design flaws |
| **`A05:2021-Security Misconfiguration`** | CWE-16, CWE-260, CWE-311, CWE-489 | Category: `IAC`, Checkov findings, open S3 buckets, exposed ports, Docker root user |
| **`A06:2021-Vulnerable and Outdated Components`** | CWE-937, CWE-1035, CWE-1104 | Category: `SCA`, Trivy & OSV-Scanner CVEs, outdated package manifests |
| **`A07:2021-Identification and Authentication Failures`** | CWE-287, CWE-306, CWE-384, CWE-521, CWE-613 | Weak password requirements, missing session timeouts, insecure cookie flags |
| **`A08:2021-Software and Data Integrity Failures`** | CWE-494, CWE-502 (Insecure Deserialization), CWE-829 | Category: `SUPPLY_CHAIN`, Python `pickle.load`, `yaml.unsafe_load`, dependency confusion, typosquatting |
| **`A09:2021-Security Logging and Monitoring Failures`** | CWE-117 (Log Injection), CWE-778 | Unlogged security events, log forging |
| **`A10:2021-Server-Side Request Forgery (SSRF)`** | CWE-918 (SSRF) | Unvalidated HTTP request fetches, webhook triggers |

### 6.3 Reachability Verdict Normalization
The backend normalizes reachability from SecureShip's Gate 2 engine into four distinct UI-friendly verdicts:
- **`REACHABLE`**: Symbol is explicitly referenced and proven reachable via AST call graph analysis (`REACHABLE_CALL_PATH` or `REACHABLE_IMPORT`).
- **`UNREACHABLE`**: Function or package is evaluated and proven dead code / uninvoked in production paths (`GATE2_UNREACHABLE` or `UNREACHABLE`).
- **`POTENTIALLY_REACHABLE`**: Dynamic reflection, dynamic import, or dynamic property access prevents deterministic proof of non-reachability.
- **`UNKNOWN`**: Analysis inconclusive, missing symbol database, or unsupported language grammar.

---

## 7. Code Snippet Extraction Specification

The snippet extractor inspects the extracted codebase on disk and slices a context window of **±5 lines** around the reported vulnerable lines:

```python
from pathlib import Path
from typing import TypedDict

class SnippetLine(TypedDict):
    line_number: int
    content: str
    is_vulnerable: bool

class SnippetResult(TypedDict):
    start_line: int
    end_line: int
    vulnerable_start: int
    vulnerable_end: int
    lines: list[SnippetLine]
    error: str | None

def extract_snippet(
    base_dir: str | Path,
    file_path: str,
    start_line: int,
    end_line: int,
    context_lines: int = 5
) -> SnippetResult:
    """
    Extracts +/- context_lines around start_line:end_line from base_dir/file_path.
    Safely handles UTF-8, binary files, missing files, and boundary conditions.
    """
    base = Path(base_dir).resolve()
    target = (base / file_path).resolve()

    # Boundary check: ensure target does not escape base directory
    if not target.is_relative_to(base) or not target.is_file():
        return {
            "start_line": start_line,
            "end_line": end_line,
            "vulnerable_start": start_line,
            "vulnerable_end": end_line,
            "lines": [],
            "error": f"File not accessible: {file_path}"
        }

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as e:
        return {
            "start_line": start_line,
            "end_line": end_line,
            "vulnerable_start": start_line,
            "vulnerable_end": end_line,
            "lines": [],
            "error": f"Read error: {e}"
        }

    total_lines = len(all_lines)
    if total_lines == 0:
        return {
            "start_line": 0,
            "end_line": 0,
            "vulnerable_start": 0,
            "vulnerable_end": 0,
            "lines": [],
            "error": None
        }

    # Normalize line indices (1-based)
    v_start = max(1, start_line)
    v_end = max(v_start, end_line if end_line > 0 else v_start)

    slice_start = max(1, v_start - context_lines)
    slice_end = min(total_lines, v_end + context_lines)

    lines: list[SnippetLine] = []
    for num in range(slice_start, slice_end + 1):
        content = all_lines[num - 1].rstrip("\r\n")
        lines.append({
            "line_number": num,
            "content": content,
            "is_vulnerable": (v_start <= num <= v_end)
        })

    return {
        "start_line": slice_start,
        "end_line": slice_end,
        "vulnerable_start": v_start,
        "vulnerable_end": v_end,
        "lines": lines,
        "error": None
    }
```

---

## 8. Multi-Format Exporter Specifications

### 8.1 JSON Exporter
- Directly returns the full ScanReport structure with all summary statistics, scanner details, and enriched findings.
- Content-Type: `application/json; charset=utf-8`
- Header: `Content-Disposition: attachment; filename="secureship-report-{job_id}.json"`

### 8.2 SARIF 2.1.0 Exporter
- Follows the official OASIS SARIF standard and validates against `schemas/sarif-schema-2.1.0.json`.
- Root structure:
  ```json
  {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "SecureShip Security Suite",
            "fullName": "SecureShip Security Suite - Complete AppSec & Supply Chain Engine",
            "version": "1.0.0",
            "informationUri": "https://secureship.dev",
            "rules": [
              {
                "id": "secureship/sast/secureship-py-sql-format",
                "name": "SQL Injection in Query Execution",
                "shortDescription": {"text": "SQL Injection in Query Execution"},
                "fullDescription": {"text": "SQL query constructed via string formatting or f-strings before execution."},
                "help": {"text": "Replace raw string formatting with parameterized queries."},
                "properties": {
                  "tags": ["external/cwe/cwe-89", "owasp/a03-2021-injection"],
                  "security-severity": "8.9",
                  "precision": "high"
                }
              }
            ]
          }
        },
        "results": [
          {
            "ruleId": "secureship/sast/secureship-py-sql-format",
            "level": "error",
            "message": {"text": "SQL query constructed via string formatting before execution."},
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {"uri": "backend/app/db.py"},
                  "region": {
                    "startLine": 42,
                    "endLine": 42,
                    "snippet": {"text": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")"}
                  }
                }
              }
            ],
            "partialFingerprints": {
              "secureship/v1": "a3b2c1d0e4f5..."
            },
            "properties": {
              "severity": "HIGH",
              "confidence": "HIGH",
              "category": "SAST",
              "owaspCategory": "A03:2021-Injection",
              "reachability": "REACHABLE"
            }
          }
        ]
      }
    ]
  }
  ```
- Severity Level Mapping:
  - `CRITICAL`, `HIGH` $\rightarrow$ `"error"`
  - `MEDIUM` $\rightarrow$ `"warning"`
  - `LOW` $\rightarrow$ `"note"`
  - `INFO` $\rightarrow$ `"none"`

### 8.3 Standalone HTML Exporter
- Generates a **completely self-contained, single-file HTML document**.
- Zero external HTTP requests (all CSS and fonts embedded inline) to guarantee 100% offline viewing and air-gapped security compliance.
- Visual Features:
  - Dark-mode aesthetic aligned with modern security dashboards (slate/zinc palette).
  - Executive KPI metrics ribbon: Total Findings, Critical, High, Medium, Low, Info.
  - Scanner Performance & Status breakdown table.
  - OWASP Top 10 breakdown table.
  - Findings Cards featuring:
    - Color-coded severity badge (Critical: Red, High: Orange, Medium: Amber, Low: Blue, Info: Slate).
    - Rule ID, Scanner badge, CWE badge, OWASP category badge, Reachability badge.
    - Code Snippet Box with gutter line numbers, highlighting the exact vulnerable lines.
    - Remediation advice and suggested fix box.

### 8.4 Binary PDF Exporter (ReportLab)
- **Library Selection:** `reportlab` (Pure Python + prebuilt wheels, no headless browser, Cairo, or Pango runtime dependencies).
- Produces a formal, paginated, publication-grade binary PDF report (`application/pdf`).
- Layout & Elements:
  - **Header/Footer:** SecureScan branding, report timestamp, page numbering (`Page X of Y`).
  - **Executive Summary:** Scan metadata table (Job ID, Target Name, Scan Duration, Scanners Executed).
  - **Metrics Matrix:** Severity distribution table with color-coded cells.
  - **OWASP Category Summary:** Table mapping findings to OWASP Top 10 categories.
  - **Detailed Findings:**
    - Title banner colored by severity (Critical: `#DC2626`, High: `#EA580C`, Medium: `#D97706`, Low: `#2563EB`, Info: `#64748B`).
    - Metadata table: Location (File + Line), CWE IDs, OWASP Category, Reachability Verdict.
    - Code Block: Courier monospace formatted code box with line numbers.
    - Remediation Box: Recommendations and fix details.

---

## 9. Verification & Test Strategy

To verify compliance with all R1 and R2 requirements, the test suite must execute against synthetic archives and live endpoints:

### 9.1 Synthetic Test Archives Suite
The team will generate synthetic test archives in `backend/tests/fixtures/`:
1. `valid_clean.zip`: Clean codebase with no vulnerabilities. (Expect: Exit 0, 0 findings).
2. `valid_vulnerable.zip`: Contains `secureship-py-sql-format.positive.py` and hardcoded secret. (Expect: Exit 1, 2 findings, snippets extracted).
3. `zip_slip.zip`: Archive containing an entry with path traversal `../../evil.sh`. (Expect: `ValueError`, HTTP 422).
4. `symlink_0xA1ED.zip`: Archive containing an entry with Unix symlink external attribute `0xA1ED0000`. (Expect: `ValueError`, HTTP 422).
5. `zip_bomb.zip`: 100 MB of zeros deflated to < 100 KB (ratio > 1000x). (Expect: `ValueError`, HTTP 422).
6. `file_exceeds_10mb.zip`: Single 11 MB uncompressed file. (Expect: `ValueError`, HTTP 422).
7. `total_exceeds_50mb.zip`: Multiple files totaling 55 MB uncompressed. (Expect: `ValueError`, HTTP 422).

### 9.2 Verification Commands Runbook
```powershell
# 1. Run backend unit and safety tests
pytest backend/tests/test_safe_extract.py -v
pytest backend/tests/test_queue.py -v
pytest backend/tests/test_runner.py -v
pytest backend/tests/test_mapper.py -v
pytest backend/tests/test_snippet.py -v
pytest backend/tests/test_exporters.py -v

# 2. Run API integration tests
pytest backend/tests/test_api.py -v

# 3. Test SARIF export validation against official schema
python -c "import json, jsonschema; schema=json.load(open('schemas/sarif-schema-2.1.0.json')); report=json.load(open('test-out.sarif')); jsonschema.validate(report, schema); print('SARIF 2.1.0 Valid!')"
```

---

## 10. Summary of Architectural Recommendations for Implementers

1. **Keep `safe_extract()` Fail-Closed:** Never fallback to permissive extraction if an anomaly is detected. All temporary files must be cleaned immediately in `finally` blocks.
2. **Treat Exit Code 0 and 1 as Success:** Security scanners exit with code 1 when findings are present; the runner must treat 0 and 1 as normal successful completion.
3. **Use ReportLab for Robust PDF Generation:** Avoid WeasyPrint or Puppeteer to prevent heavyweight browser/C-library container bloat.
4. **Isolate Scan Workspaces:** Each scan must execute in its own `tempfile.mkdtemp(prefix="securescan_")` and be completely wiped after report generation.
