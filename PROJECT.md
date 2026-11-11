# Project: SecureScan — Placement Assessment Completion

## Architecture
- **Backend**: FastAPI 0.115+ application with async job queue, sandboxed safe ZIP extraction, multi-scanner runner CLI, and multi-format exporters (JSON, SARIF 2.1.0, single-file HTML, PDF).
- **Frontend**: React 18 + Vite + TypeScript + Tailwind CSS + Recharts + React Router DOM with dark theme (`bg-gray-950`), Inter typography, and modular page architecture (`ScanPage`, `ReportPage`, `Navbar`, `Footer`).
- **Container Infrastructure**: Docker Compose V2 with resource limits (`deploy.resources.limits`), multi-stage Dockerfiles (`Dockerfile.backend`, `frontend/Dockerfile`), Nginx reverse proxy with 50MB body limit and 300s timeouts, and Cloudflare tunnel profile.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | UploadZone & Zip Validation | Drag-and-drop, .zip only, 50MB limit, animated progress bar | M1 | ORIGINAL_REQUEST §1 |
| 2 | Pages & Routing Architecture | `ScanPage.tsx`, `ReportPage.tsx`, `Navbar.tsx`, `Footer.tsx`, React Router `/scan`, `/report/:job_id` | M1 | ORIGINAL_REQUEST §1, §3 |
| 3 | SummaryDashboard & OWASP Filter | Donut chart (red-600, orange-500, yellow-500, blue-400, gray-500), 4 stat cards (Total Findings, Files Affected, Scanners Run, Scan Duration), scanner bar chart, OWASP bar chart with click-to-filter | M1 | ORIGINAL_REQUEST §1 |
| 4 | FindingsTable & Reachability Badges | Filterable by severity/category/scanner/CWE/path/OWASP, sortable CRITICAL first, reachability (green=REACHABLE, gray=UNREACHABLE, yellow=UNKNOWN) | M1 | ORIGINAL_REQUEST §1, §5 |
| 5 | CodeViewerDrawer & Breadcrumbs | Slide-in drawer, breadcrumb path, Prism-highlighted snippet, red vulnerable line highlight, ±5 context lines, fix advice | M1 | ORIGINAL_REQUEST §1 |
| 6 | ExportButtons Multi-Format | JSON, SARIF, HTML, PDF blob downloads from `/api/reports/{id}/export?format=X` | M1 | ORIGINAL_REQUEST §1 |
| 7 | Design System & Inter Font | Dark theme `bg-gray-950`, `text-gray-100`, `indigo-500` accent, Google Fonts Inter loaded in index.html & tailwind | M1 | ORIGINAL_REQUEST §5 |
| 8 | API Type Contracts Bidirectional Aliases | CamelCase & snake_case support in `normalize_report_dict`, `jobs.py`, `health.py` | M2 | ORIGINAL_REQUEST §4 |
| 9 | Docker Compose & Container Viability | Port mappings, 3GB RAM/1.5 CPU backend limits, 512MB/1.0 CPU frontend limits, healthchecks, Cloudflare tunnel profile | M2 | ORIGINAL_REQUEST §2 |
| 10 | Comprehensive Test Verification | 399/399 pytest tests passing, `npm run build` clean with 0 TS errors, clean forensic audit | M3 | ORIGINAL_REQUEST §6 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Frontend Pages, Components & Design System | Install `react-router-dom`, create `ScanPage`, `ReportPage`, `Navbar`, `Footer`, update `SummaryDashboard`, `FindingsTable`, `CodeViewerDrawer`, `index.html`, `tailwind.config.js` | none | DONE |
| M2 | Backend API Contracts & Schema Normalization | Update `json_exporter.py`, `jobs.py`, `health.py` for bidirectional camelCase/snake_case serialization | none | DONE |
| M3 | Comprehensive Verification & Audits | Reviewer verification (2 APPROVE), Challenger stress testing (2 APPROVE), Forensic Auditor (CLEAN), 399 pytest tests, clean npm build | M1, M2 | DONE |

## Interface Contracts
### Frontend ↔ Backend API
- `POST /api/scan`: `multipart/form-data` with field `file`. Returns `{"job_id": string, "jobId": string, "status": "queued", "poll_url": string, "pollUrl": string}`.
- `GET /api/jobs/{id}`: Returns `jobId`/`job_id`, `status` ("queued"|"running"|"done"|"failed"), `progress` (0..100), `stage`, `error`.
- `GET /api/reports/{id}`: Returns normalized `ScanReport` containing both camelCase (`totalFindings`, `bySeverity`, `byOwasp`, `durationMs`, `filePath`, `startLine`, `isTarget`, `lineNumber`) and snake_case equivalents.
- `GET /api/reports/{id}/export?format=json|sarif|html|pdf`: Returns binary attachment with `Content-Disposition`.
- `GET /api/health`: Returns system health, scanner readiness, and queue metrics (`queuedJobs`, `isProcessing`).

## Code Layout
- `backend/app/exporters/json_exporter.py` — Serializer normalization with bidirectional aliases
- `backend/app/routers/jobs.py` — Job status endpoint with dual aliases
- `backend/app/routers/health.py` — Health endpoint with queue telemetry
- `frontend/package.json` — Frontend dependencies (`react-router-dom@^6.28.0`)
- `frontend/index.html` — HTML entry point & Inter font links
- `frontend/tailwind.config.js` — Tailwind CSS config with Inter and severity color tokens
- `frontend/src/App.tsx` — Modular React Router entry point (`/scan`, `/report/:job_id`, etc.)
- `frontend/src/pages/ScanPage.tsx` — Upload & scanning page with 2s polling
- `frontend/src/pages/ReportPage.tsx` — Report analysis dashboard page with resilient polling
- `frontend/src/components/Navbar.tsx` — Navigation header with brand link & live health badge
- `frontend/src/components/Footer.tsx` — Clean dark footer
- `frontend/src/components/SummaryDashboard.tsx` — Metric cards & charts with OWASP click-to-filter
- `frontend/src/components/FindingsTable.tsx` — Filterable findings table with severity ordering
- `frontend/src/components/CodeViewerDrawer.tsx` — Vulnerability drawer with breadcrumbs & red line highlight
