# Project: SecureScan — SecureShip Web Platform

## Architecture
SecureScan is a defensive security scanning web platform wrapping the SecureShip multi-engine SAST/SCA/Secret/IaC CLI inside a FastAPI backend and a dark-themed React dashboard, orchestrated via Docker Compose and deployable via Cloudflare Quick Tunnel.

```
                    ┌──────────────────────────────────────────────┐
                    │               Web Browser / UI               │
                    │         React 18 + Vite + Tailwind CSS       │
                    │           Recharts + Syntax Highlighting     │
                    └──────────────────────┬───────────────────────┘
                                           │
                         HTTP / JSON / Multipart (Port 80/3000)
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │          Nginx Reverse Proxy (Frontend)      │
                    │   Static SPA serving + /api/ proxy passing   │
                    └──────────────────────┬───────────────────────┘
                                           │
                               HTTP (Port 8000 internal)
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │         FastAPI Backend Application          │
                    │  ├── /api/scan (Upload & Safe Extract)       │
                    │  ├── /api/jobs/{id} (Status Polling)         │
                    │  ├── /api/reports/{id} (Unified Report)      │
                    │  ├── /api/reports/{id}/export (Multi-Format) │
                    │  └── /api/health (Readiness / Liveness)      │
                    └───────┬──────────────────────────────┬───────┘
                            │                              │
              ┌─────────────▼──────────────┐ ┌─────────────▼──────────────┐
              │ Safe Extraction Pipeline   │ │   Report Exporters         │
              │ • Zip-slip traversal block │ │   • JSON                   │
              │ • Symlink 0xA1ED reject    │ │   • SARIF 2.1.0            │
              │ • Zip bomb >100x reject    │ │   • Single-File HTML       │
              │ • 10MB file / 50MB total   │ │   • Binary PDF (ReportLab) │
              │ • Context manager cleanup  │ └────────────────────────────┘
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │ Job Queue (asyncio.Queue)  │
              │ Concurrency = 1 worker     │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼─────────────────────────────────────────────┐
              │ Subprocess Execution Runner (300s Hard Timeout)           │
              │ Argument list form (no shell=True)                        │
              │ Exit codes 0 and 1 handled as success                     │
              │ Executes: node /opt/secureship/dist/index.js scan         │
              └─────────────┬─────────────────────────────────────────────┘
                            │
              ┌─────────────▼─────────────────────────────────────────────┐
              │ SecureShip CLI Engine & Pre-baked Scanners                │
              │ • opengrep (1.31.0)  • gitleaks (8.24.0)                  │
              │ • trivy (0.76.0)     • osv-scanner (1.9.2)                │
              │ • checkov (3.3.29)   • Tree-sitter WASM grammars          │
              └───────────────────────────────────────────────────────────┘
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Safe Extract: Zip-Slip Defense | Reject archives containing `../`, absolute paths, or traversal sequences | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 2 | Safe Extract: Symlink Defense | Reject zip entries with external attribute `0xA1ED` or POSIX `S_IFLNK` | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 3 | Safe Extract: Zip-Bomb Defense | Enforce uncompressed-to-compressed ratio <= 100x before and during decompression | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 4 | Safe Extract: Size Quotas | Reject individual uncompressed file > 10 MB or total extracted archive > 50 MB | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 5 | Safe Extract: Lifecycle Cleanup | Clean up temporary scan directories upon scan completion or error using context manager | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 6 | Subprocess Runner | Execute SecureShip CLI via argument list (no shell=True) with 300s timeout | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 7 | Exit Code Semantics | Handle both exit code 0 (clean) and exit code 1 (findings present) as successful scans | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 8 | Asynchronous Job Queue | Manage `asyncio.Queue` processing at most 1 scan concurrently | M1 | ORIGINAL_REQUEST §Acceptance Criteria |
| 9 | Unified Finding Model | Standardize findings with CWE IDs, OWASP Top 10:2021 mapping, and reachability verdict | M1 | ORIGINAL_REQUEST §R1 |
| 10 | Code Context Extractor | Slices source code context (±5 lines around vulnerable lines) safely from extracted files | M1 | ORIGINAL_REQUEST §R2 |
| 11 | Upload Endpoint `POST /api/scan` | Accepts `.zip` uploads up to 50MB, returns HTTP 200 with `job_id` and `poll_url` | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 12 | Job Status Endpoint `GET /api/jobs/{id}` | Returns status (`queued`, `running`, `done`, `failed`) and progress percentage | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 13 | Report Endpoint `GET /api/reports/{id}` | Returns complete ScanReport JSON with findings, snippets, CWE, OWASP, reachability | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 14 | Health Endpoint `GET /api/health` | Returns service health status and queue depth | M2 | ORIGINAL_REQUEST §R1 |
| 15 | JSON Exporter `GET /api/reports/{id}/export?format=json` | Direct download of unified scan report in JSON format | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 16 | SARIF 2.1.0 Exporter `GET /api/reports/{id}/export?format=sarif` | Standard OASIS SARIF 2.1.0 conforming schema output | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 17 | Standalone HTML Exporter `GET /api/reports/{id}/export?format=html` | Self-contained single-file HTML report with embedded inline styling | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 18 | Binary PDF Exporter `GET /api/reports/{id}/export?format=pdf` | Standalone binary PDF report generated via ReportLab | M2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 19 | Dark-Themed React Frontend Setup | Vite + React + TypeScript + Tailwind CSS project in `frontend/` | M3 | ORIGINAL_REQUEST §R3 |
| 20 | Drag-and-Drop Upload Zone | File upload zone enforcing 50 MB limit with client-side guard and instant feedback | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 21 | Status Polling Loop | Automated 2-second status polling against `/api/jobs/{id}` during scan execution | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 22 | Summary Dashboard: Severity Donut | Interactive Recharts donut chart for CRITICAL, HIGH, MEDIUM, LOW, INFO counts | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 23 | Summary Dashboard: Scanner Breakdown | Recharts bar chart showing findings count per security engine | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 24 | Summary Dashboard: OWASP Breakdown | Visualization of findings grouped by OWASP Top 10 (2021) categories | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 25 | Filterable & Sortable Findings Table | Dynamic table with sorting by severity and filtering by category, scanner, CWE, path | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 26 | Slide-in Code Viewer Drawer | Code viewer panel with syntax highlighting and vulnerable line pinned with ±5 context | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 27 | Export Download Buttons | Direct triggers for downloading JSON, SARIF, HTML, and PDF reports | M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 28 | Backend Dockerfile | Multi-stage Dockerfile pre-baking all scanner binaries, Node.js CLI, Python venv, non-root user | M4 | ORIGINAL_REQUEST §R4 |
| 29 | Frontend Dockerfile | Multi-stage Vite build and Nginx Alpine reverse proxy | M4 | ORIGINAL_REQUEST §R4 |
| 30 | Docker Compose Orchestration | `docker-compose.yml` with backend and frontend services, 3G RAM / 1.5 CPU limits, healthchecks | M4 | ORIGINAL_REQUEST §Acceptance Criteria |
| 31 | Cloudflare Quick Tunnel Setup | Cloudflare tunnel configuration and documentation (`--profile tunnel`) | M4 | ORIGINAL_REQUEST §R4 |
| 32 | Project Documentation Suite | Complete `ARCHITECTURE.md`, `REFERENCES.md`, `THIRD-PARTY.md`, and `README.md` without stubs | M4 | ORIGINAL_REQUEST §R5 |
| 33 | E2E Testing Suite (Tiers 1-4) | Comprehensive opaque-box test suite published via `TEST_READY.md` | M5 / Track 2 | ORIGINAL_REQUEST §Acceptance Criteria |
| 34 | Adversarial Hardening (Tier 5) | White-box stress testing and adversarial edge-case verification | M5 | Prompt Project Pattern |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Backend Core: Extraction, Runner & Queue | Features 1-10: `safe_extract`, argument list subprocess runner with 300s timeout & exit 0/1 handling, `asyncio.Queue` concurrency=1, unified finding schema, CWE/OWASP mapping, snippet extractor | none | DONE |
| M2 | Backend API & Exporters | Features 11-18: FastAPI router, `/api/scan`, `/api/jobs/{id}`, `/api/reports/{id}`, `/api/health`, and exporters for JSON, SARIF 2.1.0, standalone HTML, and binary PDF | M1 | IN_PROGRESS |
| M3 | SecureScan React Dashboard | Features 19-27: Dark-themed React SPA, 50MB drag-and-drop zone, 2s polling, Recharts donut & bar charts, filterable table, slide-in code viewer with pinned vulnerable line, export buttons | M2 | PLANNED |
| M4 | Docker Compose, Pre-baking, Tunnel & Docs | Features 28-32: `Dockerfile.backend`, `frontend/Dockerfile`, `docker-compose.yml` (3G/1.5 CPU limits), Cloudflare tunnel profile, complete `ARCHITECTURE.md`, `REFERENCES.md`, `THIRD-PARTY.md`, `README.md` | M1, M2, M3 | PLANNED |
| M5 | Final Milestone: E2E Verification & Adversarial Hardening | Features 33-34: 100% pass on E2E test suite (Tiers 1-4 from E2E Track) followed by Tier 5 adversarial coverage hardening | M1, M2, M3, M4, Track 2 | PLANNED |

### Parallel Track: E2E Testing Track (Track 2)
| Track | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| T2 | E2E Testing Suite Track | Design and publish `TEST_INFRA.md`, generate synthetic test archives, implement test runners for Tiers 1-4, publish `TEST_READY.md` | none | DONE |

---

## Interface Contracts

### 1. `safe_extract` Contract
```python
def safe_extract(zip_path: Path, target_dir: Path) -> ExtractionResult:
    """
    Extracts a zip archive enforcing strict security invariants:
    - Path traversal rejection: any member containing '..' or resolving outside target_dir raises ValueError.
    - Symlink rejection: any member with external_attr >> 16 == 0xA1ED or S_IFLNK raises ValueError.
    - Zip-bomb defense: compression ratio (uncompressed / compressed) > 100 raises ValueError.
    - Size limits: single uncompressed file > 10MB (10,485,760 bytes) or total archive > 50MB (52,428,800 bytes) raises ValueError.
    - Returns ExtractionResult(extracted_path=target_dir, file_count=N, total_bytes=M).
    """
```

### 2. Scanner Runner Contract
```python
async def run_secureship_cli(scan_target_dir: Path, timeout_seconds: int = 300) -> ScanReport:
    """
    Executes SecureShip CLI using argument list:
    args = [node_bin, cli_dist_path, "scan", str(scan_target_dir), "--json"]
    - Hard timeout: 300 seconds.
    - Exit code handling:
        code == 0: successful scan, parse stdout JSON
        code == 1: successful scan with findings, parse stdout JSON
        code > 1: scan failure, raise ScannerExecutionError
    - Returns parsed and normalized ScanReport object.
    """
```

### 3. API Contract (`POST /api/scan` -> `GET /api/jobs/{id}` -> `GET /api/reports/{id}`)
- `POST /api/scan`:
  - Request: `multipart/form-data` with `file: UploadFile` (must end with `.zip`, max 50MB).
  - Response: `{"job_id": "<uuid4>", "status": "queued", "poll_url": "/api/jobs/<uuid4>"}` (HTTP 200).
- `GET /api/jobs/{job_id}`:
  - Response: `{"job_id": "<uuid4>", "status": "queued"|"running"|"done"|"failed", "progress": 0..100, "error": str|null}`
- `GET /api/reports/{job_id}`:
  - Response: Full `ScanReport` JSON object matching unified finding schema.
- `GET /api/reports/{job_id}/export?format={json|sarif|html|pdf}`:
  - Response: Streaming binary or text download with appropriate MIME type and Content-Disposition.

---

## Code Layout
```
c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI entrypoint, middleware, CORS, routers
│   │   ├── config.py                   # Environment config (limits, timeouts, paths)
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── endpoints.py            # /api/scan, /api/jobs, /api/reports, /api/health
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── safe_extract.py         # safe_extract() implementation with 5 defenses
│   │   │   ├── runner.py               # SecureShip CLI subprocess runner (args, 300s timeout)
│   │   │   ├── queue.py                # asyncio.Queue job queue (concurrency = 1)
│   │   │   └── context_extractor.py    # ±5 lines snippet extraction around findings
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── job.py                  # JobStatus, JobRecord Pydantic models
│   │   │   ├── report.py               # ScanReport, NormalizedFinding, OWASP & CWE mappings
│   │   └── exporters/
│   │       ├── __init__.py
│   │       ├── json_exporter.py        # Native JSON export
│   │       ├── sarif_exporter.py       # OASIS SARIF 2.1.0 compliant exporter
│   │       ├── html_exporter.py        # Self-contained single-file HTML exporter
│   │       └── pdf_exporter.py         # Binary PDF exporter via ReportLab
│   ├── tests/
│   │   ├── test_extraction.py          # Unit tests for safe_extract (zip-slip, symlink, bombs)
│   │   ├── test_runner.py              # Unit tests for CLI runner & exit code handling
│   │   ├── test_queue.py               # Unit tests for job queue
│   │   ├── test_api.py                 # Integration tests for FastAPI endpoints
│   │   └── test_exporters.py           # Tests for JSON, SARIF, HTML, and PDF exports
│   └── requirements.txt                # FastAPI, uvicorn, reportlab, pydantic, pytest
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── UploadZone.tsx          # Drag-and-drop upload zone with 50MB client-side guard
│   │   │   ├── SummaryDashboard.tsx    # Severity donut, scanner breakdown, OWASP breakdown
│   │   │   ├── FindingsTable.tsx       # Filterable and sortable findings table
│   │   │   ├── CodeViewerDrawer.tsx    # Slide-in drawer with pinned line highlighting (±5 context)
│   │   │   └── ExportButtons.tsx       # Download triggers for JSON, SARIF, HTML, PDF
│   │   ├── types/
│   │   │   └── report.ts               # TypeScript interfaces matching backend models
│   │   ├── App.tsx                     # Main layout and state machine
│   │   └── main.tsx
│   ├── package.json                    # React 18, Vite, Tailwind CSS, Recharts, Lucide icons
│   └── vite.config.ts
│
├── tests/
│   └── e2e/                            # Opaque-box E2E test suite (Tiers 1-4)
│
├── docs/
│   ├── ARCHITECTURE.md                 # System architecture, diagrams, defense mechanisms
│   ├── REFERENCES.md                   # Standards, OWASP/CWE mappings, academic citations
│   └── THIRD-PARTY.md                  # Comprehensive SBOM, licenses, verification hashes
│
├── Dockerfile.backend                  # Production multi-stage backend container
├── docker-compose.yml                  # Compose stack with resource ceilings (3G RAM, 1.5 CPU)
├── README.md                           # Main user documentation and deployment guide
└── TEST_READY.md                       # Published by E2E Testing Track when test suite is ready
```
