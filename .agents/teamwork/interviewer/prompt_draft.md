Build SecureScan, a file and folder upload security scanner web platform wrapping the SecureShip CLI with a Python FastAPI backend and a React dashboard, deployable via Docker Compose and Cloudflare Quick Tunnel for the Heyram Infrastructure placement assessment.

Working directory: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE
Integrity mode: development

## Requirements

### R1. SecureScan Backend API & Scanner Pipeline
FastAPI backend service accepting .zip uploads up to 50 MB, enforcing zip-slip, zip-bomb, and symlink defenses during extraction into temporary directories. It manages an asynchronous job queue with concurrency of 1, executes SecureShip CLI inside the container, parses results into a unified finding model mapped to CWE and OWASP Top 10 categories, and exposes upload, polling, report retrieval, and health endpoints.

### R2. Code Context & Multi-Format Exporter
Service that extracts snippet context (±5 lines around vulnerable lines) and exports scan reports to JSON, standard SARIF 2.1.0, standalone HTML with embedded styling, and PDF format.

### R3. SecureScan React Dashboard
Dark-themed React frontend with TypeScript, Vite, Tailwind CSS, recharts, and syntax highlighting. It provides an upload zone with drag-and-drop and progress polling, a summary dashboard (severity donut, scanner breakdown, OWASP categories), a filterable and sortable findings list, a slide-in code viewer with vulnerable line highlighting, and export download triggers.

### R4. Docker Compose & Deployment Setup
Docker Compose configuration (`docker compose up`) orchestrating the backend (pre-baking scanner binaries: gitleaks, trivy, osv-scanner, checkov, and SecureShip CLI) and frontend services with memory (3G) and CPU (1.5) limits, healthchecks, and Cloudflare Quick Tunnel deployment documentation and configuration.

### R5. Project Documentation
Comprehensive documentation suite comprising ARCHITECTURE.md, REFERENCES.md (security standards and academic citations), THIRD-PARTY.md (attributions and licenses), and README.md.

## Verification Resources
Synthetic test zip archives created by the team covering valid scans, zip-slip path traversal payloads, zip bombs (>100x compression ratio), symlinks, and sample vulnerable files; and the existing SecureShip test artifacts and CLI doctor command.

## Acceptance Criteria

### Security & Safe Extraction
- [ ] `safe_extract()` raises ValueError and rejects zip archives containing path traversal (`../`), symlinks (external attribute `0xA1ED`), compression ratios > 100x, single files > 10 MB, or total extracted size > 50 MB.
- [ ] Subprocess execution uses argument list form (no shell string interpolation) with a 300-second hard timeout.
- [ ] Temporary scan directories are deleted upon scan completion or failure.

### Job Queue & Scanner Execution
- [ ] `POST /api/scan` accepts valid `.zip` archives up to 50 MB and returns HTTP 200 with `job_id` and `poll_url`.
- [ ] Scan queue processes at most 1 scan concurrently using asyncio.Queue.
- [ ] SecureShip CLI runner handles exit code 0 (no findings) and exit code 1 (findings present) as successful runs.
- [ ] `GET /api/jobs/{id}` returns job status (`queued`, `running`, `done`, `failed`) and progress.
- [ ] `GET /api/reports/{id}` returns complete ScanReport JSON with CWE ID, OWASP Top 10 category, snippet context, and reachability verdict.

### Exporter Formats
- [ ] `GET /api/reports/{id}/export?format=json` returns full unified report JSON.
- [ ] `GET /api/reports/{id}/export?format=sarif` returns valid SARIF 2.1.0 schema conforming output.
- [ ] `GET /api/reports/{id}/export?format=html` returns a self-contained single-file HTML report with inline CSS.
- [ ] `GET /api/reports/{id}/export?format=pdf` returns a valid binary PDF document.

### Frontend Dashboard
- [ ] React UI builds cleanly (`npm run build`) without TypeScript or lint errors.
- [ ] Drag-and-drop upload zone accepts `.zip` files, enforces 50 MB limit, and initiates 2-second status polling upon upload.
- [ ] Summary dashboard renders severity donut chart, scanner breakdown bar chart, and OWASP category breakdown.
- [ ] Findings table supports sorting by severity and filtering by severity, category, scanner, CWE, and file path.
- [ ] Code viewer panel displays syntax-highlighted code and pins the exact reported line with ±5 lines of context.
- [ ] Export buttons trigger direct downloads for JSON, SARIF, HTML, and PDF formats.

### Container & Integration Verification
- [ ] Full end-to-end container integration test executes SecureShip CLI inside the Docker Compose stack on a synthetic test archive and generates a populated report.
- [ ] Backend Dockerfile pre-bakes scanner binaries (gitleaks, trivy, osv-scanner) and SecureShip without runtime downloads.
- [ ] Docker Compose starts both backend and frontend services cleanly within specified resource limits (3G RAM, 1.5 CPUs).
- [ ] Documentation files (`docs/ARCHITECTURE.md`, `docs/REFERENCES.md`, `docs/THIRD-PARTY.md`, `README.md`) contain complete explanations, diagrams, and citations with no placeholder stubs or TODOs.