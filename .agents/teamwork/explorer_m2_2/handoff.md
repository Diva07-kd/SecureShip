# Explorer M2-2 Handoff Report: API Endpoints & Job Queue Investigation

**Author**: Explorer M2-2 (API Endpoints & Queue Explorer)  
**Date**: 2026-11-07T07:20:00Z  
**Scope**: FastAPI endpoints (`POST /api/scan`, `GET /api/jobs/{id}`, `GET /api/reports/{id}`, `GET /api/health`), Job Queue integration, Execution Lifecycle, and In-Memory / Persistent Store for Milestone 2.

---

## 1. Observation

### 1.1 Existing Milestone 1 Core Modules
Direct inspection of existing code in `backend/app/` revealed the following components:
- **`backend/app/core/queue.py`**:
  - `ScanJobQueue` implements an in-memory queue backed by `asyncio.Queue(maxsize=100)` and a state store `_jobs: dict[str, JobRecord]`.
  - Concurrency is strictly bounded to 1 via single-worker loop `_worker_loop()` (lines 92-108).
  - Background worker is started via `await queue.start()` and stopped via `await queue.stop()`.
  - Job execution stages transition through: `QUEUED` (0%) -> `EXTRACTING` (10%) -> `SCANNING` (30%..80%) -> `ENRICHING` (90%) -> `COMPLETED` (100%) or `FAILED` (100%).
  - Cleanup logic in lines 185-196:
    ```python
    finally:
        if scratch_dir and scratch_dir.exists():
            shutil.rmtree(scratch_dir, onerror=_handle_remove_readonly)
        job.temp_dir = None
        if job.zip_path and Path(job.zip_path).exists():
            try:
                Path(job.zip_path).unlink(missing_ok=True)
            except Exception:
                pass
    ```
- **`backend/app/core/runner.py`**:
  - `run_secureship_cli()` executes Node.js CLI with argument list `[node_bin, cli_script, "scan", str(target), "--json"]` and hard timeout 300s (lines 110-136).
  - Lines 162-180 treat both exit codes `0` (clean) and `1` (findings detected) as successful runs and parse stdout JSON.
  - Line 120 currently specifies:
    ```python
    work_dir = Path(cwd).resolve() if cwd else target
    ```
  - Crucial observation: In `queue.py` line 133:
    ```python
    raw_report = await run_secureship_cli(
        scan_target_dir=scratch_dir,
        timeout_seconds=300,
    )
    ```
    `cwd` is NOT passed to `run_secureship_cli()`. As a result, `work_dir` defaults to `target` (`scratch_dir`), which directly violates the requirement:
    *"SecureShip cwd MUST be `/secureship` (or configured CLI dir), not extracted_dir! (WASM resolution)"*.
- **`backend/app/core/safe_extract.py`**:
  - Enforces 5 strict defenses: Zip-slip path traversal rejection, symlink attribute `0xA1ED`/`S_IFLNK` rejection, zip-bomb ratio (>100x) rejection, single file quota (10MB), and total archive quota (50MB).
  - Returns `ExtractionResult(extracted_path, file_count, total_bytes)` or raises `ValueError`.
- **`backend/app/core/context_extractor.py`**:
  - `enrich_report_with_snippets()` reads vulnerable files safely from `scratch_dir` and injects ±5 lines of context (`CodeSnippet`), canonicalizes CWE IDs (`extract_cwe_ids`), classifies OWASP Top 10 (`map_cwe_to_owasp`), and normalizes reachability verdicts (`normalize_reachability_verdict`).
- **`backend/app/models/job.py` and `backend/app/models/report.py`**:
  - `JobRecord` inherits from `BaseSchema` with `to_camel` aliasing and `populate_by_name=True`.
  - `JobStatus`: `"queued"`, `"running"`, `"done"`, `"failed"`.
  - `JobStage`: `"queued"`, `"extracting"`, `"scanning"`, `"enriching"`, `"completed"`, `"failed"`.
  - `ScanReport` strongly types `id`, `target_name`, `status`, `scanners`, `findings` (`NormalizedFinding`), `summary` (`ScanSummary`), and `warnings`.
- **`backend/app/config.py`**:
  - Currently defines `MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024` (50MB), `SCAN_TIMEOUT_SECONDS = 300`, `MAX_CONCURRENCY = 1`.
  - Lacks `SECURESHIP_CWD` setting.
- **Missing FastAPI Application Files**:
  - Neither `backend/app/main.py`, `backend/app/routers/`, nor `backend/app/api/endpoints.py` exist yet in the codebase.
- **Environment Dependencies Verified**:
  - `slowapi` is installed and verified working with FastAPI.
  - `python-multipart`, `pydantic`, `fastapi`, `uvicorn`, `httpx`, and `pytest` are available.
  - Current baseline tests: 89 passed, 2 xfailed in 2.91s (`pytest backend/tests`).

---

## 2. Logic Chain

### 2.1 API Endpoint Specification & Contracts

#### A. Upload Endpoint: `POST /api/scan`
1. **Rate Limiting**:
   - `slowapi` limiter set to `10/hour` per client IP (`get_remote_address`). If exceeded, returns HTTP 429 (`RateLimitExceeded`).
2. **File Validation**:
   - Filename check: Must end with `.zip` (case-insensitive `file.filename.lower().endswith(".zip")`). Non-zip extensions return HTTP 400 (`Uploaded file must be a .zip archive`).
   - Content-Type check: Allowed MIME types: `application/zip`, `application/x-zip-compressed`, `application/octet-stream`, `multipart/x-zip`. Other MIME types (e.g. `application/json`, `image/png`, `text/plain`) return HTTP 400 (`Invalid Content-Type; expected application/zip`).
   - Magic bytes validation (Defense in Depth): The first chunk of uploaded bytes must begin with zip magic signature: `b"PK\x03\x04"` (standard), `b"PK\x05\x06"` (empty archive), or `b"PK\x07\x08"` (spanned archive). Rejecting mismatched headers with HTTP 400 prevents extension-spoofing attacks (e.g., renaming `malware.exe` to `malware.zip`).
   - Size limit: 50MB (52,428,800 bytes). Enforced via chunked streaming (64KB chunks) into a temporary disk file. If accumulated bytes exceed 50MB, writing immediately aborts, the temporary file is unlinked, and HTTP 400 is raised (`File size exceeds maximum allowed limit of 50 MB`).
   - Empty file: If total bytes uploaded == 0, reject with HTTP 400 (`Uploaded file is empty`).
3. **Execution & Queue Enqueue**:
   - Generate unique scan UUID: `job_id = str(uuid.uuid4())`.
   - Call `await queue.enqueue(job_id=job_id, zip_path=str(temp_zip_path))`.
   - Record `job.target_name = file.filename`.
4. **Response Contract (HTTP 200)**:
   ```json
   {
     "job_id": "b3e94a8e-...",
     "jobId": "b3e94a8e-...",
     "status": "queued",
     "poll_url": "/api/jobs/b3e94a8e-...",
     "pollUrl": "/api/jobs/b3e94a8e-..."
   }
   ```
   *Note*: Providing both snake_case and camelCase keys (or using `BaseSchema` with `populate_by_name=True`) ensures total compatibility with both the React frontend and all backend test suites.

#### B. Status Polling Endpoint: `GET /api/jobs/{id}`
1. Query `job_queue.get_job(id)`.
2. If `job is None`: Return HTTP 404 (`Scan job '{id}' not found`).
3. Return state object:
   ```json
   {
     "job_id": "b3e94a8e-...",
     "jobId": "b3e94a8e-...",
     "status": "queued|running|done|failed",
     "stage": "queued|extracting|scanning|enriching|completed|failed",
     "progress": 0..100,
     "created_at": "2026-11-07T07:00:00Z",
     "started_at": "2026-11-07T07:00:01Z",
     "completed_at": "2026-11-07T07:00:15Z",
     "finished_at": "2026-11-07T07:00:15Z",
     "finishedAt": "2026-11-07T07:00:15Z",
     "error": null,
     "poll_url": "/api/jobs/b3e94a8e-...",
     "report_url": "/api/reports/b3e94a8e-...",
     "target_name": "repo.zip"
   }
   ```
   *Note*: `finished_at` and `finishedAt` are aliased to `completed_at` to fulfill both prompt naming conventions and Pydantic models.

#### C. Report Retrieval Endpoint: `GET /api/reports/{id}`
1. Query `job_queue.get_job(id)`.
2. If `job is None`: Return HTTP 404 (`Scan job '{id}' not found`).
3. If `job.status in (JobStatus.QUEUED, JobStatus.RUNNING)`: Return HTTP 409 Conflict (`Scan job '{id}' is still in progress (progress: {job.progress}%)`).
4. If `job.status == JobStatus.FAILED`: Return HTTP 400 Bad Request (`Scan job '{id}' failed: {job.error}`).
5. If `job.status == JobStatus.DONE`: Return `job.report` (full unified `ScanReport` JSON object).

#### D. Health Check Endpoint: `GET /api/health`
1. Query `job_queue.get_stats()`.
2. Return HTTP 200:
   ```json
   {
     "status": "healthy",
     "service": "securescan-api",
     "version": "1.0.0",
     "queue_depth": 0,
     "is_processing": false,
     "active_job_id": null
   }
   ```

---

### 2.2 Execution Lifecycle & Resource Cleanliness

```
[Client POST /api/scan]
       │
       ▼
1. Validate .zip, MIME, magic bytes, 50MB limit
2. Stream to temp file: `securescan_upload_{uuid}.zip`
       │
       ▼
3. Enqueue to ScanJobQueue (`_queue.put(job_id)`)
       │
       ▼
[Worker Dequeues (Concurrency = 1)]
       │
       ▼
4. Create scratch_dir: `securescan_job_{uuid}_...`
5. safe_extract(zip_path, scratch_dir)
   ├── Pass: progress = 30
   └── Fail (ValueError): status = FAILED, error = msg, jump to Finally
       │
       ▼
6. run_secureship_cli(scan_target_dir=scratch_dir, cwd=SECURESHIP_CWD, timeout=300)
   ├── Pass (exit 0 or 1): parse stdout JSON, progress = 80
   ├── Timeout: status = FAILED, error = "Timed out", jump to Finally
   └── Exit > 1: status = FAILED, error = stderr, jump to Finally
       │
       ▼
7. enrich_report_with_snippets(raw_report, scratch_dir)
   ├── Extract ±5 line context
   ├── Normalize CWE IDs & map OWASP Top 10
   └── Normalize reachability verdict
       │
       ▼
8. job.status = DONE, job.progress = 100, job.completed_at = now()
       │
       ▼
[Finally Block — ALWAYS EXECUTED]
9. shutil.rmtree(scratch_dir)  -> Clean all extracted files
10. zip_path.unlink()           -> Clean uploaded zip archive
```

---

### 2.3 The `cwd` Bug & Tree-sitter WASM Grammar Resolution

In `backend/app/core/runner.py:120`:
`work_dir = Path(cwd).resolve() if cwd else target`
Because `cwd` is `None` in `queue.py:133`, `work_dir` currently resolves to `scratch_dir`.
In the production Docker container:
- The Tree-sitter WASM grammars (`tree-sitter-javascript.wasm`, `tree-sitter-python.wasm`, etc.) and scanner plugins reside under `/secureship` (or `/opt/secureship`).
- When the Node.js CLI runs with `process.cwd() == scratch_dir`, WASM grammar resolution fails because it looks for `./wasm/...` or `node_modules` relative to `process.cwd()`.
- **Required Fix**:
  1. Add `SECURESHIP_CWD: str = os.environ.get("SECURESHIP_CWD", "/secureship")` to `backend/app/config.py`.
  2. In `runner.py`:
     ```python
     def get_default_cwd(cli_script: Path) -> Path:
         env_cwd = os.environ.get("SECURESHIP_CWD")
         if env_cwd and Path(env_cwd).is_dir():
             return Path(env_cwd).resolve()
         if Path("/secureship").is_dir():
             return Path("/secureship").resolve()
         # Fallback to CLI package directory or parent
         return cli_script.parent.resolve()
     ```
  3. Pass `cwd` explicitly from `queue.py`:
     ```python
     cli_cwd = os.environ.get("SECURESHIP_CWD", "/secureship")
     raw_report = await run_secureship_cli(
         scan_target_dir=scratch_dir,
         timeout_seconds=300,
         cwd=cli_cwd if Path(cli_cwd).is_dir() else None,
     )
     ```

---

### 2.4 In-Memory vs. Persistent Store Architecture

- **In-Memory Store (`_jobs: dict[str, JobRecord]`)**:
  - Thread-safe in asyncio event loop.
  - Zero latency for rapid status polling (every 2 seconds by React UI).
  - Maintains complete `JobRecord` models and enriched `ScanReport` payloads.
- **FastAPI Lifespan Management**:
  - A singleton `ScanJobQueue` must be instantiated and controlled by FastAPI's `lifespan` handler in `backend/app/main.py`:
    ```python
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        queue = get_job_queue()
        await queue.start()
        app.state.queue = queue
        yield
        await queue.stop()
    ```
  - Defining `get_job_queue()` as a module-level helper in `app/core/queue.py` allows dependency injection in routers (`Depends(get_queue)`) and straightforward mocking in `pytest` fixtures.

---

## 3. Caveats

1. **Memory Ceiling under Heavy Job History**:
   - `ScanJobQueue` holds finished `JobRecord` objects (including reports) in RAM. For 50+ large reports, memory usage could increase. For this placement assessment and single-container deployment, this is well within the 3GB container RAM ceiling. An optional LRU eviction or file-backed storage can be added later if hundreds of reports are retained.
2. **Rate Limiting in Unit Tests**:
   - `slowapi` rate limits IP addresses. Test suites executing rapid scan uploads will trigger HTTP 429 if rate limiting is enabled during testing. The configuration must include `RATE_LIMITING_ENABLED: bool = True` (or disable in `conftest.py` / when `os.environ.get("TESTING") == "1"`).
3. **MIME Type Variations across Clients**:
   - Different operating systems and browser versions send varying MIME types for `.zip` files (e.g., Windows Explorer sends `application/x-zip-compressed`, curl sends `application/octet-stream`). The MIME validator must accept the set `{"application/zip", "application/x-zip-compressed", "application/octet-stream", "multipart/x-zip"}` in addition to verifying the `PK` magic header.

---

## 4. Conclusion & Implementation Blueprint

### 4.1 Recommended File Layout for Milestone 2
```
backend/app/
├── __init__.py
├── main.py                     # FastAPI app, lifespan, CORS, rate limiter, /api/health
├── config.py                   # Extended with SECURESHIP_CWD, RATE_LIMIT_ENABLED
├── core/
│   ├── queue.py                # Add get_job_queue() singleton and pass cwd
│   ├── runner.py               # Update cwd default resolution
│   ├── safe_extract.py         # (Unchanged from M1)
│   └── context_extractor.py    # (Unchanged from M1)
├── models/
│   ├── job.py                  # JobRecord, JobStatus, JobStage
│   └── report.py               # ScanReport, NormalizedFinding
├── routers/
│   ├── __init__.py
│   ├── upload.py               # POST /api/scan
│   ├── jobs.py                 # GET /api/jobs/{id}, GET /api/reports/{id}
│   └── reports.py              # GET /api/reports/{id}/export (Explorer M2-1)
└── api/
    ├── __init__.py
    └── endpoints.py            # Re-exports / mounts upload & jobs routers (PROJECT.md compatibility)
```

### 4.2 Blueprint: `backend/app/routers/upload.py`
```python
import os
import tempfile
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from app.core.queue import ScanJobQueue, get_job_queue
from app.config import settings

router = APIRouter(prefix="/api", tags=["Upload & Scan"])

ALLOWED_ZIP_MIMES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
    "multipart/x-zip",
}
ZIP_MAGIC_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 65536                   # 64 KB

@router.post("/scan", status_code=status.HTTP_200_OK)
async def upload_scan(
    request: Request,
    file: UploadFile = File(...),
    queue: ScanJobQueue = Depends(get_job_queue),
):
    # 1. Filename validation
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must be a .zip archive (filename must end with .zip)",
        )

    # 2. Content-Type validation
    if file.content_type and file.content_type.lower() not in ALLOWED_ZIP_MIMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Content-Type '{file.content_type}'. Must be application/zip",
        )

    # 3. Secure disk streaming and magic bytes validation
    job_id = str(uuid.uuid4())
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip", prefix=f"securescan_upload_{job_id}_")
    temp_path = Path(temp_zip.name)
    uploaded_bytes = 0
    first_chunk = True

    try:
        while chunk := await file.read(CHUNK_SIZE):
            if first_chunk:
                first_chunk = False
                if not any(chunk.startswith(magic) for magic in ZIP_MAGIC_HEADERS):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="File is not a valid zip archive (missing PK magic header)",
                    )
            uploaded_bytes += len(chunk)
            if uploaded_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File exceeds maximum allowed size of 50 MB ({uploaded_bytes} bytes)",
                )
            temp_zip.write(chunk)
        temp_zip.flush()
        temp_zip.close()

        if uploaded_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes)",
            )
    except Exception:
        temp_zip.close()
        temp_path.unlink(missing_ok=True)
        raise

    # 4. Enqueue into JobQueue
    job = await queue.enqueue(job_id=job_id, zip_path=str(temp_path))
    job.target_name = file.filename

    return {
        "job_id": job_id,
        "jobId": job_id,
        "status": "queued",
        "poll_url": f"/api/jobs/{job_id}",
        "pollUrl": f"/api/jobs/{job_id}",
    }
```

### 4.3 Blueprint: `backend/app/routers/jobs.py`
```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.queue import ScanJobQueue, get_job_queue
from app.models.job import JobStatus

router = APIRouter(prefix="/api", tags=["Jobs & Reports"])

@router.get("/jobs/{id}")
async def get_job_status(id: str, queue: ScanJobQueue = Depends(get_job_queue)):
    job = queue.get_job(id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{id}' not found",
        )

    return {
        "job_id": job.job_id,
        "jobId": job.job_id,
        "status": job.status.value,
        "stage": job.stage.value,
        "progress": job.progress,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "finished_at": job.completed_at,
        "finishedAt": job.completed_at,
        "error": job.error,
        "poll_url": job.poll_url or f"/api/jobs/{job.job_id}",
        "report_url": f"/api/reports/{job.job_id}" if job.status == JobStatus.DONE else None,
        "target_name": job.target_name,
    }

@router.get("/reports/{id}")
async def get_scan_report(id: str, queue: ScanJobQueue = Depends(get_job_queue)):
    job = queue.get_job(id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{id}' not found",
        )

    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan job '{id}' is still in progress (status: {job.status.value}, progress: {job.progress}%)",
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan job '{id}' failed: {job.error or 'Internal scanner failure'}",
        )

    if not job.report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No report available for job '{id}'",
        )

    return job.report
```

### 4.4 Blueprint: `backend/app/main.py`
```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.queue import get_job_queue
from app.routers import upload, jobs

limiter = Limiter(
    key_func=get_remote_address,
    enabled=settings.RATE_LIMIT_ENABLED,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    queue = get_job_queue()
    await queue.start()
    app.state.queue = queue
    yield
    await queue.stop()

app = FastAPI(
    title="SecureScan API",
    version="1.0.0",
    description="Multi-engine SAST/SCA/Secret/IaC scanning platform API",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(jobs.router)

@app.get("/api/health", tags=["Health"])
async def health_check():
    queue = get_job_queue()
    stats = queue.get_stats()
    return {
        "status": "healthy",
        "service": "securescan-api",
        "version": "1.0.0",
        "queue_depth": stats["queued_jobs"],
        "is_processing": stats["is_processing"],
        "active_job_id": stats["active_job_id"],
    }
```

---

## 5. Verification Method

To verify these designs independently once implemented by Worker M2:

1. **Unit & Integration Test Suite (`backend/tests/test_api.py`)**:
   Run the following test command:
   ```powershell
   pytest backend/tests/test_api.py -v
   ```
   Must test:
   - `test_upload_valid_zip_returns_200_and_poll_url`: Upload dummy zip file; assert status 200, keys `job_id` and `poll_url`.
   - `test_upload_non_zip_extension_returns_400`: Upload `sample.txt` or `sample.tar.gz`; assert status 400.
   - `test_upload_invalid_mime_type_returns_400`: Upload with `Content-Type: image/png`; assert status 400.
   - `test_upload_fake_zip_magic_returns_400`: Upload text starting with `MZ...` named `sample.zip`; assert status 400.
   - `test_upload_exceeds_50mb_returns_400`: Upload 51MB payload; assert status 400.
   - `test_job_status_transitions_and_404`: Query unknown UUID -> 404; query active job -> `queued`/`running` with progress; query done -> `done`.
   - `test_report_status_in_progress_returns_409`: Query `/api/reports/{id}` while running -> 409 Conflict.
   - `test_report_status_failed_returns_400`: Query `/api/reports/{id}` on failed job -> 400 Bad Request.
   - `test_report_status_done_returns_scan_report`: Query completed job -> valid JSON report with findings, snippets, CWE, and OWASP.
   - `test_health_endpoint`: Query `/api/health` -> 200, `healthy`, `queue_depth`.

2. **Full Regression Test Suite**:
   ```powershell
   pytest backend/tests
   ```
   Must pass all 89 existing baseline tests plus all new `test_api.py` tests.

3. **Invalidation Conditions**:
   - If `/api/scan` returns 200 for a non-zip file or file > 50MB.
   - If `/api/reports/{id}` returns 200 while a job is still in `running` state.
   - If temporary files or folders remain on disk after a job finishes or fails.
   - If `run_secureship_cli` executes with `cwd` set to `scratch_dir` instead of `/secureship` (or configured directory).
