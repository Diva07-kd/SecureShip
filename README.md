# SecureScan 🛡️ — Defensive Security Scanner Web Platform
### Powered by SecureShip Multi-Scanner Engine
**Placement Assessment Submission for Heyram Infrastructure**

---

## 📌 Executive Summary

**SecureScan** is an enterprise-grade, defensive security scanning web platform wrapping the **SecureShip** multi-engine vulnerability intelligence pipeline. It pairs a **Python FastAPI backend** and a **dark-themed React 18 + Vite + Tailwind CSS dashboard**, orchestrating asynchronous security audits across Static Application Security Testing (SAST), Software Composition Analysis (SCA), Secret Detection, and Infrastructure-as-Code (IaC) analysis.

The platform is fully containerized via **Docker Compose**, features zero-configuration public exposure through **Cloudflare Quick Tunnels (Option A)**, enforces strict memory (3 GB) and CPU (1.5 cores) resource ceilings, and guarantees multi-layered archive defenses against malicious inputs.

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
              │ • Zip-slip traversal block │ │   • Native JSON            │
              │ • Symlink 0xA1ED reject    │ │   • OASIS SARIF 2.1.0      │
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
              │ Executes: node /secureship/dist/index.js scan             │
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

## ⚡ Key Features Checklist

- [x] **Safe Archive Extraction**: Rejects Zip-Slip traversals (`../`), Symlinks (`0xA1ED`), Zip-Bombs (> 100x ratio), single files > 10 MB, and archives > 50 MB with deterministic temp directory cleanup.
- [x] **Subprocess Runner Contract**: Structured argument-list subprocess execution (zero `shell=True`), 300-second hard timeout, dual exit-code success handling (exit 0 = clean, exit 1 = findings).
- [x] **Asynchronous Job Queue**: `asyncio.Queue` with single worker (concurrency = 1) preventing CPU/memory exhaustion.
- [x] **Unified Finding Model & Taxonomies**: Normalized Pydantic v2 schema mapping all scanner outputs into MITRE CWE and OWASP Top 10 (2021) categories with reachability verdicts.
- [x] **Code Context Extractor**: Safely slices &plusmn;5 lines of source code context around reported vulnerable lines with boundary clamping, encoding fallback, and binary rejection.
- [x] **Multi-Format Exporters**: Instant downloads for Native JSON, OASIS SARIF 2.1.0, Standalone Air-Gapped HTML, and Executive Binary PDF.
- [x] **Dark-Themed React Dashboard**: React 18, Vite, Tailwind CSS, Recharts severity donut and scanner breakdown charts, sortable/filterable findings table, and slide-in code viewer drawer.
- [x] **Hardened Container Stack**: Production `docker-compose.yml` with memory limits (3 GB) and CPU limits (1.5 cores), healthchecks, and non-root user (UID 10001).
- [x] **Cloudflare Quick Tunnel (Option A)**: Ephemeral, zero-setup public HTTPS ingress via `docker compose --profile tunnel up`.
- [x] **100% Comprehensive Documentation**: Complete architectural specifications, academic references, third-party SBOM, and API documentation with zero stubs or TODOs.

---

## 🚀 Quick Start Guide

### Option 1: Run with Docker Compose (Recommended)

1. **Launch the Stack:**
   ```bash
   docker compose up --build -d
   ```
2. **Access the Application:**
   - **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
   - **Backend REST API:** [http://localhost:8000/api/health](http://localhost:8000/api/health)
   - **Swagger Interactive API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option 2: Deploy Publicly via Cloudflare Quick Tunnel (Option A)

Expose the entire application to the internet via Cloudflare Quick Tunnel with zero accounts or configuration required:

#### 1-Click Launch Scripts:
- **Windows (PowerShell):** `.\run-securescan.ps1`
- **Linux / macOS / Git Bash:** `./run-securescan.sh`

#### Or Manual Docker Compose Command:
```bash
# 1. Start full stack with tunnel profile
docker compose --profile tunnel up --build -d

# 2. View generated public HTTPS URL
docker compose logs tunnel | grep -o 'https://[a-zA-Z0-9-]\+\.trycloudflare\.com'
```

*Example Output:*
```
https://quick-sample-tunnel-name.trycloudflare.com
```

---

### Option 3: Local Development (Without Docker)

#### 1. Backend Service
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Service
```bash
cd frontend
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

---

## 🧪 Comprehensive Test Suite & Verification Results

The platform includes **396 automated tests** covering unit, integration, adversarial, and end-to-end tiers:

| Test Suite | Location | Tests Passed | Focus Area |
|---|---|---|---|
| **Backend Core & API** | `backend/tests/` | **217 Passed** | Safe extraction, runner contracts, queue lifecycle, API endpoints, and exporters |
| **End-to-End Synthetics** | `tests/e2e/` | **28 Passed** | Tiers 1-4: Safe extract happy paths, boundaries, cross-features, real-world fixtures |
| **Adversarial Hardening** | `tests/adversarial/` | **151 Passed** | Zip-slip payloads, zip bombs, symlinks, race conditions, memory limits, hostile payloads |
| **Total Automated Tests** | Repository Root | **396 Passed** | **100% Pass Rate Across All Suites** |

To execute all test suites:
```bash
# Run all test suites across the entire repository
python -m pytest backend/tests tests/e2e tests/adversarial -v

# Run individual suites
python -m pytest backend/tests -v
python -m pytest tests/e2e -v
python -m pytest tests/adversarial -v
```

---

## 🎬 Placement Assessment: Demo Video Script & Evaluation Walkthrough

Follow this step-by-step evaluation guide to verify all deliverables:

### Step 1: Healthcheck & Platform Readiness
1. Navigate to `http://localhost:3000` (or your Cloudflare Tunnel URL).
2. Observe the top right navigation badge: **"Scanners Ready (5 engines baked)"**.
3. Verify `GET /api/health` returns `200 OK` with queue depth `0` and all five scanners ready.

### Step 2: Malicious Archive Defenses (Safe Extraction Verification)
1. In the upload zone, attempt uploading a non-zip file (e.g. `.tar` or `.sh`). Observe immediate rejection: *"Only .zip archives are supported"*.
2. Run automated tests against adversarial archives:
   `python -m pytest tests/adversarial/test_m1_adversarial.py`
   Notice how `zip_slip.zip` (path traversal), `symlink_0xa1ed.zip` (symlink attack), and `zip_bomb.zip` (> 100x ratio) are rejected with clear errors while protecting the host.

### Step 3: Archive Upload & Real-Time Polling
1. Drag and drop `tests/fixtures/valid_vulnerable.zip` into the upload zone.
2. Observe the 2-second polling loop animating through stages:
   - `1. Safe Extract` -> `2. Engine Scan` -> `3. Snippets & OWASP`
3. Notice how exit code 1 from SecureShip is treated as a successful scan with findings.

### Step 4: Executive Dashboard & Analytics
1. The dashboard automatically displays:
   - **4 Stat Cards:** Total Findings, Critical & High, Monitored Engines (5), Scan Duration.
   - **Severity Donut Chart:** Visual breakdown of Critical, High, Medium, Low, and Info findings.
   - **Scanner Engine Bar Chart:** Distribution of findings across opengrep, gitleaks, trivy, osv-scanner, checkov.
   - **OWASP Top 10:2021 Bar Chart:** Categorization according to OWASP Top 10 standards.

### Step 5: Filterable Findings Table & Code Viewer Drawer
1. Type `SQL` into the search bar — table immediately filters to SQL injection findings.
2. Select severity dropdown `HIGH` or sort by severity / location.
3. Click **"Inspect"** on any finding:
   - Slide-in Code Viewer Drawer opens from the right.
   - Exact vulnerable line is highlighted in bold red with a `>>` indicator.
   - Pinned context window displays &plusmn;5 lines of code.
   - Authoritative MITRE CWE reference link is provided.

### Step 6: Multi-Format Report Downloads
Click each download button in the export bar and inspect the downloaded files:
1. **JSON:** Standardized unified JSON schema.
2. **SARIF 2.1.0:** Valid OASIS SARIF v2.1.0 schema conforming to GitHub Code Scanning standards.
3. **Single-File HTML:** Self-contained report with inline CSS and zero external network dependencies.
4. **Executive PDF:** Binary PDF document with summary tables, severity color indicators, and code snippets generated via ReportLab.

---

## 📚 Architectural & Technical Documentation

For in-depth architectural and standard citations, consult the documentation suite in `docs/`:

- [**System Architecture & Technical Specification**](docs/ARCHITECTURE.md): Component diagrams, data flow Mermaid sequence charts, and defense in depth.
- [**Academic References & Security Standards**](docs/REFERENCES.md): MITRE CWE, OWASP Top 10, OASIS SARIF 2.1.0, Snyk Zip Slip research, Shannon entropy.
- [**Third-Party Attributions & SBOM**](docs/THIRD-PARTY.md): SecureShip authorship declaration, licenses, and cryptographic tool hashes.
- [**Comprehensive API & User Manual**](docs/DOCUMENTATION.md): Detailed REST endpoints, request/response payloads, and configuration options.
- [**Cloudflare Quick Tunnel Setup Runbook**](.cloudflare/tunnel-setup.md): Deployment guide for Option A public ingress.

---

## ⚖️ License & Intellectual Property

- **SecureShip & SecureScan:** Authored by the candidate for the Heyram Infrastructure placement assessment under the **Apache-2.0 License**.
- Third-party scanners and tools are governed by their respective open-source licenses detailed in [THIRD-PARTY.md](docs/THIRD-PARTY.md).
