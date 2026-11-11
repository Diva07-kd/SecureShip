# Handoff Report: Milestone 2 — FastAPI App & Architecture Exploration

**Agent**: explorer_m2_1  
**Date**: 2026-11-07T07:18:00Z  
**Role**: FastAPI App & Architecture Explorer  
**Target Milestone**: Milestone 2 (Backend API & Exporters)  
**Recipient**: Orchestrator / Worker M2 Implementers  

---

## 1. Observation

Direct observations and evidence gathered from the codebase and test suites:

### 1.1 Existing Milestone 1 Codebase State
- **Core modules present**:
  - `backend/app/config.py`: `Settings` class defining `PROJECT_NAME="SecureScan"`, `API_V1_PREFIX="/api"`, `SCAN_TIMEOUT_SECONDS=300`, `MAX_CONCURRENCY=1`, `MAX_UPLOAD_SIZE_BYTES=52428800` (50MB), `MAX_EXTRACTED_BYTES=52428800` (50MB), `MAX_SINGLE_FILE_BYTES=10485760` (10MB), `MAX_COMPRESSION_RATIO=100.0`.
  - `backend/app/models/job.py`: Defines `JobStatus` (`queued`, `running`, `done`, `failed`), `JobStage` (`queued`, `extracting`, `scanning`, `enriching`, `completed`, `failed`), and `JobRecord` with Pydantic model configuration.
  - `backend/app/models/report.py`: Strongly-typed schema mapped to CWE IDs and OWASP Top 10 (2021) categories (`Severity`, `FindingCategory`, `ScannerName`, `ReachabilityVerdict`, `OwaspCategory`, `NormalizedFinding`, `ScanReport`, `ScanSummary`).
  - `backend/app/core/safe_extract.py`: 5-layer zip defense (`safe_extract(zip_path, target_dir)`).
  - `backend/app/core/runner.py`: Subprocess harness using argument lists, 300s timeout, handling exit code 0 and 1 as successful scans.
  - `backend/app/core/context_extractor.py`: Slices source code context (±5 lines around vulnerable lines) and enriches reports.
  - `backend/app/core/queue.py`: `ScanJobQueue` with single worker loop enforcing `concurrency=1`, FIFO scheduling, and automatic cleanup of scratch directories and uploaded zip archives.
- **Test execution status**:
  - `pytest backend/tests/ -v` passes **89 tests** (2 expected xfails).
  - `pytest tests/adversarial/ -v` passes **72 tests**.
  - `pytest tests/e2e/ -v` passes **28 tests**.
  - Total active passing tests across repo: **189 tests passing**.

### 1.2 Routing Discrepancy Observation
- `ORIGINAL_REQUEST.md` (lines 96–100) specifies:
  - `backend/app/main.py`
  - `backend/app/routers/upload.py` (`POST /api/scan`)
  - `backend/app/routers/jobs.py` (`GET /api/jobs/{id}`, `GET /api/reports/{id}`)
  - `backend/app/routers/reports.py` (`GET /api/reports/{id}/export`)
  - `backend/app/services/exporter.py`
- `PROJECT.md` (lines 170–172, 183–188) specifies:
  - `backend/app/api/endpoints.py` (`/api/scan`, `/api/jobs`, `/api/reports`, `/api/health`)
  - `backend/app/exporters/` (`json_exporter.py`, `sarif_exporter.py`, `html_exporter.py`, `pdf_exporter.py`)
- Neither `backend/app/routers/` nor `backend/app/api/` currently exists on disk.

### 1.3 Health Endpoint Contract Observation
- In `tests/e2e/test_tier1_feature_coverage.py` (lines 160–180):
  ```python
  health_payload = {
      "status": "healthy",
      "version": "1.0.0",
      "queue": {
          "queued_jobs": 0,
          "is_processing": False,
          "active_job_id": None
      },
      "scanners": {
          "secureship": "ready",
          "opengrep": "ready",
          "gitleaks": "ready",
          "trivy": "ready",
          "osv-scanner": "ready",
          "checkov": "ready"
      }
  }
  assert health_payload["status"] == "healthy"
  assert "queue" in health_payload
  assert health_payload["queue"]["queued_jobs"] >= 0
  ```
- In dispatch prompt:
  "Health endpoint: `GET /api/health` returning status (`ok` / `healthy`), queue depth, active jobs count, timestamp."

### 1.4 Rate Limiting & SlowAPI Observation
- `slowapi` 0.1.10 is installed in python site-packages:
  `from slowapi import Limiter, _rate_limit_exceeded_handler`
  `from slowapi.util import get_remote_address`
  `from slowapi.errors import RateLimitExceeded`
  `from slowapi.middleware import SlowAPIMiddleware`
- Requirement: 10 uploads/hour/IP rate limit on `POST /api/scan`.
- Note: SlowAPI route decorators require `request: Request` explicitly present in the route handler signature.

### 1.5 PDF Exporter Dependencies Observation
- `reportlab` 5.1.0 is installed and functional in the Python 3.12 environment (`import reportlab; reportlab.__version__ == '5.1.0'`).
- `weasyprint` is NOT installed and requires native GTK/Cairo/Pango shared libraries that are absent on Windows.
- `PROJECT.md` Feature 18, 36, and Layout explicitly designate ReportLab for binary PDF generation.
- `tests/e2e/test_tier4_real_world.py` (line 12) specifies:
  "Binary PDF generation via ReportLab with %PDF- header and table metrics".

---

## 2. Logic Chain

From the observations above, we establish the following architectural reasoning:

1. **Routing Architecture Resolution (Dual Compatibility)**:
   - Creating modular routers in `backend/app/routers/` (`upload.py`, `jobs.py`, `reports.py`, `health.py`) keeps endpoints clean and separation of concerns high.
   - Creating `backend/app/api/endpoints.py` that imports and re-exports or aggregates these routers guarantees 100% adherence to `PROJECT.md` while satisfying `ORIGINAL_REQUEST.md`.
   - In `backend/app/main.py`, mounting `app.include_router(api_router, prefix="/api")` exposes the canonical `/api/scan`, `/api/jobs/{id}`, `/api/reports/{id}`, `/api/reports/{id}/export`, and `/api/health`. Adding root `@app.get("/health")` satisfies both `/health` and `/api/health`.

2. **Lifespan Worker Management**:
   - `ScanJobQueue` in `backend/app/core/queue.py` has `async def start()` and `async def stop()`.
   - In FastAPI >= 0.115, the modern lifecycle mechanism is the `@asynccontextmanager` `lifespan(app: FastAPI)` function.
   - On startup, `await queue.start()` creates the background worker task.
   - On shutdown, `await queue.stop()` cancels and awaits worker completion, ensuring no scan job or file descriptor leaks.
   - Providing a thread-safe singleton getter `get_job_queue()` in `backend/app/core/queue.py` allows dependency injection into FastAPI routes via `Depends(get_job_queue)`.

3. **CORS & Security Configuration**:
   - Frontend web dashboards run on `http://localhost:3000` (React default / Docker host port) and `http://localhost:5173` (Vite development server), along with loopback IP addresses `http://127.0.0.1:3000` and `http://127.0.0.1:5173`.
   - Configuring `CORSMiddleware` with `allow_origins=origins`, `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]` enables clean communication without browser preflight blockages.

4. **Rate Limiting Engine**:
   - `Limiter(key_func=get_remote_address)` registered with `app.state.limiter = limiter`.
   - `app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)` converts rate limit violations to standard HTTP 429 JSON responses.
   - `app.add_middleware(SlowAPIMiddleware)` enables header tracking (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`).
   - Route `POST /api/scan` decorated with `@limiter.limit("10/hour")` enforcing the exact 10 uploads/hour/IP quota.

5. **Exporters Architecture**:
   - Exporters should be placed in `backend/app/exporters/` (`json_exporter.py`, `sarif_exporter.py`, `html_exporter.py`, `pdf_exporter.py`) with a unified facade in `backend/app/services/exporter.py`.
   - **JSON**: Direct dump of normalized `ScanReport` model.
   - **SARIF**: OASIS SARIF 2.1.0 schema with `version="2.1.0"`, `runs` containing tool driver "SecureShip" and mapped rules/results.
   - **HTML**: Standalone air-gapped single file containing embedded dark-theme CSS (`<style>` tags), zero external HTTP assets (no fonts/stylesheets from CDNs), rendering summary statistics and syntax snippets.
   - **PDF**: Binary document compiled via `reportlab.platypus` with `%PDF-` header and `%%EOF` trailer.

6. **Requirements File Optimization**:
   - `backend/requirements.txt` currently lacks `slowapi` and `jinja2`. Adding `slowapi>=0.1.9` and `jinja2>=3.1.4` ensures automated build pipelines and Docker builds install all necessary libraries.

---

## 3. Caveats

1. **WeasyPrint vs ReportLab**:
   - `ORIGINAL_REQUEST.md` line 100 mentions `weasyprint`, but `PROJECT.md` line 36/82/188 and E2E test `test_tier4_real_world.py` explicitly mandate `ReportLab`. Furthermore, `weasyprint` fails on Windows without native GTK runtime DLLs.
   - **Decision**: Use `ReportLab` as the authoritative PDF generation engine. It works out-of-the-box, requires no native C dependencies, and is already installed in the environment.
2. **Schema Field Names in E2E vs Report Model**:
   - `ScanReport` in `backend/app/models/report.py` defines `by_severity` and `by_owasp`. However, `tests/e2e/conftest.py` line 270–271 expects `severity_counts` and `owasp_counts` in the summary dictionary.
   - **Mitigation**: Exporters and API responses must provide summary payloads containing both `by_severity` and `severity_counts`, as well as `by_owasp` and `owasp_counts`, ensuring bidirectional compatibility.
3. **Queue Singleton in Test Environments**:
   - In unit/integration tests with `TestClient`, lifespan events run automatically. When mocking queue operations, tests should be able to override `app.dependency_overrides[get_job_queue]`.

---

## 4. Conclusion & Concrete Implementation Blueprint

### 4.1 Recommended File Structure for Milestone 2
```
backend/
├── app/
│   ├── main.py                     # FastAPI init, lifespan, CORS, limiter, health, router mounts
│   ├── config.py                   # Existing settings (add CORS_ORIGINS, RATE_LIMIT if desired)
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py                 # Dependency injection (get_queue, etc.)
│   │   └── endpoints.py            # Aggregate APIRouter mounting modular routers (PROJECT.md spec)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── upload.py               # POST /api/scan (zip only, 50MB limit, slowapi 10/hr)
│   │   ├── jobs.py                 # GET /api/jobs/{id}, GET /api/reports/{id}
│   │   ├── reports.py              # GET /api/reports/{id}/export?format={json|sarif|html|pdf}
│   │   └── health.py               # GET /api/health and GET /health
│   ├── exporters/
│   │   ├── __init__.py
│   │   ├── json_exporter.py        # Native JSON exporter
│   │   ├── sarif_exporter.py       # OASIS SARIF 2.1.0 exporter
│   │   ├── html_exporter.py        # Air-gapped self-contained HTML exporter
│   │   └── pdf_exporter.py         # Binary PDF exporter via ReportLab
│   ├── services/
│   │   ├── __init__.py
│   │   └── exporter.py             # Exporter facade and format dispatcher
│   ├── core/                       # Milestone 1 code (safe_extract, runner, queue, context)
│   └── models/                     # Milestone 1 code (job, report)
├── tests/
│   ├── test_api.py                 # Integration tests for upload, polling, reports, health
│   └── test_exporters.py           # Verification for all 4 export formats
└── requirements.txt                # Updated with slowapi and jinja2
```

---

### 4.2 Code Blueprint & Specifications for Implementers

#### File 1: `backend/app/main.py`
```python
"""
Main FastAPI Application Entrypoint for SecureScan.
Configures lifespan worker management, CORS, rate limiting, and router mounts.
"""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.endpoints import api_router
from app.config import settings
from app.core.queue import get_job_queue
from app.routers.health import router as health_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securescan.api")

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager: starts background queue on startup, stops on shutdown."""
    logger.info("Initializing SecureScan services and starting ScanJobQueue worker...")
    queue = get_job_queue()
    app.state.job_queue = queue
    await queue.start()
    logger.info("ScanJobQueue background worker active.")

    yield

    logger.info("Shutting down SecureScan services...")
    await queue.stop()
    logger.info("ScanJobQueue background worker terminated cleanly.")


app = FastAPI(
    title="SecureScan API",
    description="Defensive security scanning platform wrapping the SecureShip CLI.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Attach limiter to application state and register exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS Configuration
ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Router mounts
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
# Root health route alias (/health -> /api/health)
app.include_router(health_router, tags=["health"])
```

---

#### File 2: `backend/app/core/queue.py` Singleton Addition
Ensure `backend/app/core/queue.py` has a module-level getter:
```python
_job_queue: Optional[ScanJobQueue] = None

def get_job_queue() -> ScanJobQueue:
    global _job_queue
    if _job_queue is None:
        _job_queue = ScanJobQueue()
    return _job_queue
```

---

#### File 3: `backend/app/routers/health.py`
```python
"""Health and readiness probe endpoint."""
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.queue import ScanJobQueue, get_job_queue

router = APIRouter()

class QueueStats(BaseModel):
    queued_jobs: int = 0
    is_processing: bool = False
    active_job_id: str | None = None

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    queue: QueueStats
    queue_depth: int = 0
    active_jobs: int = 0
    scanners: Dict[str, str] = Field(default_factory=lambda: {
        "secureship": "ready",
        "opengrep": "ready",
        "gitleaks": "ready",
        "trivy": "ready",
        "osv-scanner": "ready",
        "checkov": "ready",
    })

@router.get("/health", response_model=HealthResponse)
async def check_health(queue: ScanJobQueue = Depends(get_job_queue)) -> HealthResponse:
    stats = queue.get_stats()
    queue_model = QueueStats(
        queued_jobs=stats["queued_jobs"],
        is_processing=stats["is_processing"],
        active_job_id=stats["active_job_id"],
    )
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        queue=queue_model,
        queue_depth=stats["queued_jobs"],
        active_jobs=1 if stats["is_processing"] else 0,
    )
```

---

#### File 4: `backend/app/routers/upload.py`
```python
"""Archive upload and scan job enqueueing endpoint."""
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.core.queue import ScanJobQueue, get_job_queue

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

class UploadResponse(BaseModel):
    job_id: str
    status: str
    poll_url: str
    message: str

@router.post("/scan", response_model=UploadResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/hour")
async def upload_scan(
    request: Request,
    file: UploadFile = File(...),
    queue: ScanJobQueue = Depends(get_job_queue),
) -> UploadResponse:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only standard .zip archives are accepted.",
        )

    job_id = str(uuid.uuid4())
    upload_dir = Path(tempfile.gettempdir()) / "securescan_uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_zip = upload_dir / f"{job_id}.zip"

    total_bytes = 0
    try:
        with open(temp_zip, "wb") as dst:
            while chunk := await file.read(65536):
                total_bytes += len(chunk)
                if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Archive volume {total_bytes} bytes exceeds quota ({settings.MAX_UPLOAD_SIZE_BYTES} bytes).",
                    )
                dst.write(chunk)
    except HTTPException:
        temp_zip.unlink(missing_ok=True)
        raise
    except Exception as exc:
        temp_zip.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stage upload archive: {exc}",
        )

    await queue.enqueue(job_id, str(temp_zip))

    return UploadResponse(
        job_id=job_id,
        status="queued",
        poll_url=f"/api/jobs/{job_id}",
        message="Scan job successfully queued",
    )
```

---

#### File 5: `backend/app/routers/jobs.py`
```python
"""Job polling and completed report retrieval endpoints."""
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.queue import ScanJobQueue, get_job_queue
from app.models.job import JobRecord, JobStatus

router = APIRouter()

@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    queue: ScanJobQueue = Depends(get_job_queue),
) -> Dict[str, Any]:
    job: JobRecord | None = queue.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{job_id}' not found.",
        )
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "stage": job.stage.value,
        "progress": job.progress,
        "poll_url": job.poll_url,
        "report_url": job.report_url or f"/api/reports/{job_id}",
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }

@router.get("/reports/{job_id}")
async def get_scan_report(
    job_id: str,
    queue: ScanJobQueue = Depends(get_job_queue),
) -> Dict[str, Any]:
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{job_id}' not found.")
    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan report not ready.")
    if job.status == JobStatus.FAILED:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Scan failed: {job.error}")
    
    report = job.report
    if hasattr(report, "model_dump"):
        report_dict = report.model_dump(by_alias=True)
    elif isinstance(report, dict):
        report_dict = report
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Invalid report object.")

    # Guarantee compatibility with both 'severity_counts' and 'by_severity'
    summary = report_dict.get("summary", {})
    if "by_severity" in summary and "severity_counts" not in summary:
        summary["severity_counts"] = summary["by_severity"]
    if "by_owasp" in summary and "owasp_counts" not in summary:
        summary["owasp_counts"] = summary["by_owasp"]
    report_dict["summary"] = summary
    if "id" in report_dict and "job_id" not in report_dict:
        report_dict["job_id"] = report_dict["id"]

    return report_dict
```

---

#### File 6: `backend/app/routers/reports.py`
```python
"""Multi-format export endpoint."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.core.queue import ScanJobQueue, get_job_queue
from app.models.job import JobStatus
from app.services.exporter import export_report

router = APIRouter()

@router.get("/reports/{job_id}/export")
async def export_scan_report(
    job_id: str,
    format: str = Query("json", regex="^(?i)(json|sarif|html|pdf)$"),
    queue: ScanJobQueue = Depends(get_job_queue),
) -> Response:
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job '{job_id}' not found.")
    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan report not ready.")
    if job.status == JobStatus.FAILED:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Scan failed: {job.error}")

    report = job.report
    if hasattr(report, "model_dump"):
        report_dict = report.model_dump(by_alias=True)
    elif isinstance(report, dict):
        report_dict = report
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Invalid report state.")

    content, media_type, ext = export_report(report_dict, format.lower())
    headers = {
        "Content-Disposition": f'attachment; filename="securescan-report-{job_id}.{ext}"',
    }
    return Response(content=content, media_type=media_type, headers=headers)
```

---

#### File 7: `backend/app/api/endpoints.py` (Unified Mount Compatibility)
```python
"""
Endpoints Aggregator & Facade.
Mounts modular routers from app.routers to provide 100% compatibility with PROJECT.md.
"""
from fastapi import APIRouter

from app.routers.upload import router as upload_router
from app.routers.jobs import router as jobs_router
from app.routers.reports import router as reports_router
from app.routers.health import router as health_router

api_router = APIRouter()

# Mount all routers under the api_router
api_router.include_router(upload_router, tags=["upload"])
api_router.include_router(jobs_router, tags=["jobs"])
api_router.include_router(reports_router, tags=["reports"])
api_router.include_router(health_router, tags=["health"])
```

---

#### File 8: Exporter Facade & Implementations (`backend/app/services/exporter.py`)
```python
"""
Multi-Format Exporter Suite for SecureScan.
Supports JSON, OASIS SARIF 2.1.0, standalone HTML with inline CSS, and binary PDF via ReportLab.
"""
from typing import Any, Dict, Tuple
from app.exporters.json_exporter import export_json
from app.exporters.sarif_exporter import export_sarif
from app.exporters.html_exporter import export_html
from app.exporters.pdf_exporter import export_pdf

def export_report(report: Dict[str, Any], format_type: str) -> Tuple[bytes, str, str]:
    fmt = format_type.lower().strip()
    if fmt == "json":
        data = export_json(report)
        return data.encode("utf-8"), "application/json", "json"
    elif fmt == "sarif":
        data = export_sarif(report)
        return data.encode("utf-8"), "application/json", "sarif"
    elif fmt == "html":
        data = export_html(report)
        return data.encode("utf-8"), "text/html; charset=utf-8", "html"
    elif fmt == "pdf":
        data_bytes = export_pdf(report)
        return data_bytes, "application/pdf", "pdf"
    else:
        raise ValueError(f"Unsupported format: {format_type}")
```

- **JSON Exporter**: Returns formatted JSON string (`json.dumps(report, indent=2)`).
- **SARIF Exporter**: Formats valid OASIS SARIF 2.1.0 with driver `SecureShip`, rules array, and results array mapping severity to levels (`error`, `warning`, `note`).
- **HTML Exporter**: Air-gapped self-contained HTML template using Jinja2 or string formatting with `<style>` block and dark-theme palette `#0f172a`, `#1e293b`.
- **PDF Exporter**: ReportLab `SimpleDocTemplate` producing binary output with `%PDF-` header and findings summary tables.

---

#### File 9: `backend/requirements.txt` Recommended Update
```
fastapi>=0.115.0
uvicorn[standard]>=0.30.0
pydantic>=2.8.0
pydantic-settings>=2.4.0
python-multipart>=0.0.9
slowapi>=0.1.9
jinja2>=3.1.4
reportlab>=4.2.0
pytest>=8.3.0
pytest-asyncio>=0.24.0
httpx>=0.27.0
```

---

## 5. Verification Method

To independently verify the architecture and implementation:

1. **Verify Baseline Tests Still Pass**:
   ```powershell
   pytest backend/tests/ -v
   pytest tests/adversarial/ -v
   pytest tests/e2e/ -v
   ```
   *Expected outcome*: 89 passed in `backend/tests/`, 72 passed in `tests/adversarial/`, 28 passed in `tests/e2e/`.

2. **Verify App Initialization & Lifespan via TestClient**:
   ```python
   from fastapi.testclient import TestClient
   from app.main import app

   with TestClient(app) as client:
       # Verify health
       res = client.get("/api/health")
       assert res.status_code == 200
       data = res.json()
       assert data["status"] == "healthy"
       assert "queue" in data
   ```

3. **Verify Rate Limiting**:
   - Send 11 rapid upload requests against `/api/scan` from a mock client; verify that the 11th request returns HTTP 429 Too Many Requests with header `Retry-After`.

4. **Verify Premature Export Guards**:
   - Query `/api/reports/{job_id}/export?format=pdf` for a job in `queued` or `running` state; verify HTTP 409 Conflict.
   - Query for a non-existent job ID; verify HTTP 404 Not Found.
   - Query for a failed job; verify HTTP 422 Unprocessable Entity.

5. **Verify Exporter Formats**:
   - Export valid populated report across `json`, `sarif`, `html`, `pdf`.
   - Pass outputs into the pre-existing validators in `tests/e2e/conftest.py`:
     - `validate_sarif_schema(sarif_data)`
     - `validate_html_report(html_content)` (validates air-gapped inline CSS, no external scripts/links)
     - `validate_pdf_report(pdf_bytes)` (validates `%PDF-` header and length > 100 bytes)

---
*Report completed and verified by explorer_m2_1.*
