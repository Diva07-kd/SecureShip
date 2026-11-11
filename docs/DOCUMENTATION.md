# SecureScan Comprehensive Technical Documentation & API Manual

This document provides complete operational, architectural, and developer documentation for **SecureScan**, the enterprise security scanning web platform wrapping **SecureShip**.

---

## 1. System Requirements & Prerequisites

- **Docker:** Docker Engine version 24.0+ and Docker Compose v2.20+
- **Host Resources:**
  - Minimum 4 GB RAM (3 GB allocated to backend container)
  - Minimum 2 CPU cores (1.5 cores allocated to backend container)
  - 10 GB available disk space for scanner binaries and temporary extraction scratchpads
- **Optional Local Development Prerequisites:**
  - Node.js 22.x LTS and pnpm 12.14+
  - Python 3.12+

---

## 2. Quickstart & Deployment Instructions

### 2.1 Standard Docker Compose Stack
To start both the FastAPI backend (port 8000) and the React/Nginx frontend (port 3000):
```bash
# Clone and enter directory
cd /path/to/SecureShip-IDE

# Launch containers in background
docker compose up --build -d

# Verify containers are running and healthy
docker compose ps
```

### 2.2 Public Ingress via Cloudflare Quick Tunnel (Option A)
To expose the stack with a publicly accessible HTTPS endpoint (no account required):

**Using 1-Click Launchers:**
- On Windows: Run `.\run-securescan.ps1`
- On Linux / macOS / WSL: Run `./run-securescan.sh`

**Using Docker Compose directly:**
```bash
docker compose --profile tunnel up --build -d

# Display the public URL
docker compose logs tunnel | grep -o 'https://[a-zA-Z0-9-]\+\.trycloudflare\.com'
```

---

## 3. REST API Specification & Reference

All endpoints are hosted under the `/api` prefix.

### 3.1 Health & Readiness Probe
- **Endpoint:** `GET /api/health`
- **Description:** Returns real-time health metrics, background queue depth, and pre-baked scanner readiness.
- **Example cURL:**
  ```bash
  curl -s http://localhost:8000/api/health | jq
  ```
- **Response `200 OK`:**
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
    }
  }
  ```

---

### 3.2 Submit Scan Archive
- **Endpoint:** `POST /api/scan`
- **Content-Type:** `multipart/form-data`
- **Request Parameter:** `file`: `.zip` binary archive (maximum 50 MB)
- **Defenses Enforced:**
  - Archive type validation (rejects non-zip files)
  - 50 MB hard upload ceiling (returns `413 Request Entity Too Large`)
  - Zip-Slip path traversal defense
  - Zip-Bomb ratio ceiling (&le; 100x)
  - Symlink `0xA1ED` rejection
- **Example cURL:**
  ```bash
  curl -X POST http://localhost:8000/api/scan \
    -F "file=@/path/to/project.zip"
  ```
- **Response `200 OK`:**
  ```json
  {
    "job_id": "3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "status": "queued",
    "poll_url": "/api/jobs/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "message": "Scan job successfully queued"
  }
  ```

---

### 3.3 Poll Job Execution Status
- **Endpoint:** `GET /api/jobs/{job_id}`
- **Description:** Returns the real-time execution stage (`extracting`, `scanning`, `enriching`, `completed`, `failed`) and progress percentage (0-100%).
- **Example cURL:**
  ```bash
  curl -s http://localhost:8000/api/jobs/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9 | jq
  ```
- **Response `200 OK`:**
  ```json
  {
    "job_id": "3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "status": "running",
    "stage": "scanning",
    "progress": 45,
    "poll_url": "/api/jobs/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "report_url": "/api/reports/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "error": null,
    "target_name": "project.zip",
    "created_at": "2026-11-07T12:00:00Z",
    "started_at": "2026-11-07T12:00:01Z",
    "completed_at": null
  }
  ```

---

### 3.4 Retrieve Scan Report
- **Endpoint:** `GET /api/reports/{job_id}`
- **Description:** Retrieves the unified, enriched scan report containing findings, MITRE CWE IDs, OWASP Top 10 classifications, reachability verdicts, and &plusmn;5 lines code snippets.
- **Example cURL:**
  ```bash
  curl -s http://localhost:8000/api/reports/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9 | jq
  ```
- **Response Structure:**
  ```json
  {
    "job_id": "3a74b9e2-411a-4f51-b88a-9d8a5531bcf9",
    "status": "done",
    "target_name": "project.zip",
    "summary": {
      "total_findings": 1,
      "severity_counts": {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
      },
      "owasp_counts": {
        "A03:2021-Injection": 1
      }
    },
    "scanners": [
      {
        "name": "opengrep",
        "status": "SUCCESS"
      }
    ],
    "findings": [
      {
        "id": "f-1",
        "rule_id": "secureship-py-sql-injection",
        "scanner_name": "opengrep",
        "category": "SAST",
        "severity": "HIGH",
        "title": "SQL Injection in app.py",
        "description": "User input directly concatenated into query",
        "location": {
          "file_path": "backend/app.py",
          "start_line": 24,
          "end_line": 24
        },
        "cwe_ids": ["CWE-89"],
        "owasp_category": "A03:2021-Injection",
        "reachability": "REACHABLE",
        "snippet": {
          "file_path": "backend/app.py",
          "start_line": 19,
          "end_line": 29,
          "lines": [
            {
              "line_number": 24,
              "content": "cursor.execute(query)",
              "is_target": true
            }
          ]
        }
      }
    ]
  }
  ```

---

### 3.5 Multi-Format Report Export
- **Endpoint:** `GET /api/reports/{job_id}/export?format={json|sarif|html|pdf}`
- **Parameters:**
  - `format=json`: Application/json unified report.
  - `format=sarif`: Application/sarif+json OASIS SARIF 2.1.0 report.
  - `format=html`: Air-gapped self-contained HTML report with inline CSS.
  - `format=pdf`: Binary PDF report generated via ReportLab.
- **Example cURL Commands:**
  ```bash
  # Export OASIS SARIF
  curl -O -J "http://localhost:8000/api/reports/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9/export?format=sarif"

  # Export Standalone HTML
  curl -O -J "http://localhost:8000/api/reports/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9/export?format=html"

  # Export Executive PDF
  curl -O -J "http://localhost:8000/api/reports/3a74b9e2-411a-4f51-b88a-9d8a5531bcf9/export?format=pdf"
  ```

---

## 4. Verification & Automated Test Suites

SecureScan features comprehensive automated test coverage across unit, adversarial, and end-to-end tiers (396 total tests, 100% pass rate):

### 4.1 Run Backend Unit & Integration Tests (217 Tests)
```bash
python -m pytest backend/tests -v
```
*Covers: Safe extraction invariants, runner subprocess contracts, queue lifecycle, CWE/OWASP models, context extraction, API endpoints, rate limiting, and exporters.*

### 4.2 Run End-to-End Synthetic Archive Verification (28 Tests)
```bash
python -m pytest tests/e2e -v
```
*Covers: Clean archives, vulnerable archives, zip-slip attacks, zip-bombs, symlink attacks, oversized archives, and schema validations.*

### 4.3 Run White-Box Adversarial Hardening Suite (151 Tests)
```bash
python -m pytest tests/adversarial -v
```
*Covers: Path traversal escapes, unicode normalization, nested archives, concurrent race conditions, process signal handling, and memory threshold boundary testing.*

### 4.4 Run All Test Suites (396 Tests)
```bash
python -m pytest backend/tests tests/e2e tests/adversarial -v
```

---

## 5. Security Architecture Invariants

| Defense Layer | Implementation | Verification Status |
|---|---|---|
| **Zip-Slip Defense** | Canonical boundary check `path.resolve().is_relative_to(target)` | 100% verified across 32 unit & e2e tests |
| **Zip-Bomb Defense** | Pre-check + real-time stream ratio guard (`> 100.0x`) | 100% verified against overlapping entries |
| **Symlink Defense** | External attribute mode `0xA1ED` & `S_IFLNK` rejection | 100% verified against symlink fixtures |
| **Quota Enforcement** | 10 MB per file, 50 MB total archive | 100% verified during streaming chunk writes |
| **Queue Concurrency** | Single worker `asyncio.Queue(maxsize=100)` | 100% verified under parallel load |
| **Subprocess Safety** | Structured argument list (no `shell=True`), 300s timeout | 100% verified with subprocess inspection |
| **PID 1 Signal Handling** | `tini` process supervisor propagates `SIGTERM` cleanly | Verified in Docker container lifecycle |
| **Air-Gap Self-Containment**| HTML exporter contains zero external scripts/stylesheets | Verified by automated HTML parser test |
