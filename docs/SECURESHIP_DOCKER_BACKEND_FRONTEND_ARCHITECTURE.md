# 🛡️ SecureShip-IDE: Complete Architecture & Engineering Reference
## End-to-End System Deep-Dive: Docker Containerization, Backend Engine, and Frontend Integration

> **Document Type:** System Architecture Specification & Engineering Reference  
> **Target System:** `SecureShip-IDE` (Web Security Scanner Platform)  
> **Tech Stack:** React 18 SPA + Alpine Nginx + FastAPI Backend + Containerized SecureShip CLI Multi-Scanner Engine  
> **Test Status:** 229/229 Pytest Tests Passing (100% Verified) | Zero Code Modifications Required  

---

## 📑 TABLE OF CONTENTS

1. [Executive Concept & System Overview (கான்செப்ட் விளக்கம்)](#1-executive-concept--system-overview)
2. [How SecureShip CLI is Containerized into Docker (`Dockerfile.backend`)](#2-how-secureship-cli-is-containerized-into-docker)
   - [2.1 The 5-Stage Multi-Stage Build Architecture](#21-the-5-stage-multi-stage-build-architecture)
   - [2.2 Stage-by-Stage Command Breakdown, Purpose & Rationale](#22-stage-by-stage-command-breakdown-purpose--rationale)
   - [2.3 Container Security Hardening (Rootless, Immutable Binaries, Tini Init)](#23-container-security-hardening)
   - [2.4 Docker Compose Service Orchestration](#24-docker-compose-service-orchestration)
3. [Backend Engine Deep Dive: File-by-File Logic & Rationale](#3-backend-engine-deep-dive-file-by-file-logic--rationale)
   - [3.1 `backend/app/main.py`: Lifespan, CORS & Rate Limiting](#31-backendappmainpy)
   - [3.2 `backend/app/config.py`: Scaled Operational Ceilings](#32-backendappconfigpy)
   - [3.3 `backend/app/routers/upload.py`: Streaming 64KB Chunk Ingestion & Magic Bytes](#33-backendapproutersuploadpy)
   - [3.4 `backend/app/routers/jobs.py`: Polling Semantics (404, 409, 422, 200)](#34-backendapproutersjobspy)
   - [3.5 `backend/app/routers/reports.py`: Multi-Format Export Dispatcher](#35-backendapproutersreportspy)
   - [3.6 `backend/app/routers/health.py`: Liveness & Scanner Binary Discovery](#36-backendapproutershealthpy)
   - [3.7 `backend/app/core/safe_extract.py`: 5-Layer Archive Defense Gauntlet](#37-backendappcoresafe_extractpy)
   - [3.8 `backend/app/core/queue.py`: Single-Worker Concurrency & Lifecycle](#38-backendappcorequeuepy)
   - [3.9 `backend/app/core/runner.py`: Shell-Free Subprocess Execution & Exit Code 1](#39-backendappcorerunnerpy)
   - [3.10 `backend/app/core/context_extractor.py`: ±5 Line Slicing & OWASP Mapping](#310-backendappcorecontext_extractorpy)
   - [3.11 `backend/app/models/report.py` & `job.py`: Dual-Key Serialization & Severity](#311-backendappmodelsreportpy--jobpy)
   - [3.12 `backend/app/exporters/`: JSON, SARIF 2.1.0, HTML, and WeasyPrint PDF](#312-backendappexporters)
4. [Frontend UI Architecture & User Experience](#4-frontend-ui-architecture--user-experience)
   - [4.1 Component Tree & Page Flow](#41-component-tree--page-flow)
   - [4.2 ScanPage & UploadZone (Real-Time XHR Progress & Antigravity Orbit)](#42-scanpage--uploadzone)
   - [4.3 ReportPage, SummaryDashboard, FindingsTable & CodeViewerDrawer](#43-reportpage--components)
   - [4.4 Multi-Format Export Triggers](#44-multi-format-export-triggers)
5. [Complete End-to-End Execution Flow (Step-by-Step Lifecycle)](#5-complete-end-to-end-execution-flow)
6. [Empirical Verification & Test Evidence](#6-empirical-verification--test-evidence)

---

## 1. EXECUTIVE CONCEPT & SYSTEM OVERVIEW

### 1.1 The Core Problem
To perform a complete modern application security audit, a developer traditionally needs five separate tools:
1. **SAST:** Opengrep / Semgrep (analyzes AST syntax trees for code flaws like SQLi, `eval`, `pickle.loads`).
2. **Secret Detection:** Gitleaks (scans code and commits for exposed tokens, private keys, and passwords).
3. **Container & OS Vulnerability Scanning:** Trivy (checks dependencies and base images against CVE databases).
4. **SCA:** OSV-Scanner (queries Google's Open Source Vulnerability database across dependency lockfiles).
5. **IaC:** Checkov (scans Terraform, Dockerfiles, and Kubernetes manifests for misconfigurations).

**The Deployment Nightmare:** Running these 5 tools locally requires Node.js 22, Python 3.12, system C libraries, and native compiled binaries. Asking an end-user, evaluator, or CI/CD runner to install all 5 scanners creates severe operating system dependency conflicts, version mismatches, and execution errors.

### 1.2 The SecureShip Solution
SecureShip packages our **core CLI engine** and all **5 pre-compiled scanner engines** into an isolated, hardened Docker container (`securescan-backend`). A lightweight **FastAPI application** sits inside this container, managing an asynchronous single-worker job queue and executing the CLI through safe, non-shell subprocesses. On the outside, an **Alpine Nginx reverse proxy** serves a modern **Google Antigravity-themed React 18 SPA** (`securescan-frontend`).

```
+-----------------------------------------------------------------------------------------+
|                                    USER WEB BROWSER                                     |
|  - Drag & drop .zip archive (up to 600 MB) with real-time XHR upload progress (0-100%)  |
|  - 2-second polling loop displaying Antigravity orbital rings & 3-stage indicators     |
|  - Interactive Dashboard: Severity Donut, Engine Bars, OWASP Filter, Code Snippet ±5    |
+-------------------------------------------+---------------------------------------------+
                                            | HTTP (Port 3000 -> 80)
                                            v
+-----------------------------------------------------------------------------------------+
|                   FRONTEND CONTAINER (securescan-frontend: nginx:alpine)                |
|  - Serves static React 18 production bundle (Vite + Tailwind CSS + Lucide + Recharts)   |
|  - Reverse Proxy: forwards /api/* to http://backend:8000/api/*                          |
|  - Configured client_max_body_size: 650M; proxy_read_timeout: 600s;                     |
+-------------------------------------------+---------------------------------------------+
                                            | Internal Docker Network
                                            v
+-----------------------------------------------------------------------------------------+
|                  BACKEND CONTAINER (securescan-backend: python:3.12-slim)               |
|  - Runtime: Debian Bookworm + Python 3.12 + Node.js 22 (Port 8000)                      |
|  - Non-root user: 'securescan' (UID/GID 10001) with 'tini' as PID 1                     |
|                                                                                         |
|  [FastAPI Backend Application Layer]                                                    |
|   * upload.py: Validates .zip PK magic bytes, streams 64KB chunks, rate-limits 10/hr    |
|   * queue.py: Async single worker (asyncio.Queue) enforcing MAX_CONCURRENCY=1           |
|   * safe_extract.py: 5-layer archive defense (Zip-Slip, Symlinks, Bombs, Quotas)        |
|   * runner.py: Spawns SecureShip CLI via argument vectors (shell=False)                 |
|   * context_extractor.py: Reads code from scratch dir, slices +/-5 lines, maps CWE/OWASP|
|   * exporters/: Generates JSON, OASIS SARIF 2.1.0, air-gapped HTML, & WeasyPrint PDF    |
|                                                                                         |
|  [Pre-Baked Security Engines & SecureShip CLI]                                          |
|   * CLI Path: /secureship/dist/index.js (Symlink: /usr/local/bin/secureship)            |
|   * Immutable Scanner Binaries (/opt/secureship/bin, root:root, chmod 0555):            |
|       +-- opengrep (SAST Engine)                                                        |
|       +-- gitleaks (Secret Detection)                                                   |
|       +-- trivy (Dependency & Container Scanner)                                        |
|       +-- osv-scanner (Vulnerability Advisory DB)                                       |
|       +-- checkov (IaC Scanner in isolated /opt/checkov-venv)                           |
+-----------------------------------------------------------------------------------------+
```

---

## 2. HOW SECURESHIP CLI IS CONTAINERIZED INTO DOCKER

The backend container is built from `Dockerfile.backend` using a **5-stage multi-stage build**.

### 2.1 The 5-Stage Multi-Stage Build Architecture

```
Stage 1: node:22-bookworm-slim (builder)  ---> Compiles monorepo & packages/cli to /out/cli
Stage 2: node:22-bookworm-slim (tools)    ---> Runs 'secureship install-tools' to /out/bin
Stage 3: python:3.12-slim (checkov)       ---> Installs checkov==3.3.29 into isolated venv
Stage 4: python:3.12-slim (pybuilder)     ---> Compiles FastAPI & Python wheels to /install
Stage 5: python:3.12-slim (runner)        ---> Final production runtime assembling all artifacts
```

### 2.2 Stage-by-Stage Command Breakdown, Purpose & Rationale

#### Stage 1: CLI Builder (`AS builder`)
- **Base Image:** `node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d`
- **Commands Used:**
  ```dockerfile
  RUN corepack enable && corepack prepare pnpm@12.14.0 --activate
  COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.json tools.lock.json ./
  COPY packages/*/package.json ./packages/...
  RUN pnpm install --frozen-lockfile
  COPY scripts/ ./scripts/
  COPY packages/ ./packages/
  COPY rules/ ./rules/
  RUN pnpm build
  RUN pnpm --filter @secureship/cli deploy --prod /out/cli && \
      chmod +x /out/cli/dist/index.js
  ```
- **Function of Each Command:**
  - `corepack enable`: Activates pinned `pnpm@12.14.0` without global npm installation.
  - Layered `COPY package.json`: Copies only package manifests before source code, enabling Docker cache reuse when only source files change.
  - `pnpm install --frozen-lockfile`: Guarantees exact deterministic dependencies without modifying lockfiles.
  - `pnpm build`: Runs `tsup` across all 13 monorepo packages, compiling TypeScript into standalone bundle `/out/cli/dist/index.js`.
  - `pnpm --filter @secureship/cli deploy --prod /out/cli`: Strips devDependencies, TypeScript compilers (`tsc`), and test fixtures, leaving only production runtime artifacts.
- **Why We Used This:** Discarding TypeScript build tools and source maps reduces final image size by ~800 MB and eliminates compiler attack vectors.

#### Stage 2: External Scanner Binaries (`AS tools`)
- **Commands Used:**
  ```dockerfile
  COPY --from=builder /out/cli /opt/secureship/cli
  RUN ln -s /opt/secureship/cli/dist/index.js /usr/local/bin/secureship
  RUN mkdir -p /out/bin && \
      secureship install-tools --dir /out/bin --target-platform linux-${TARGETARCH} --force && \
      chmod 0555 /out/bin/*
  ```
- **Function of Each Command:**
  - Runs `secureship install-tools`, which reads `tools.lock.json` (Single Source of Truth).
  - Downloads cryptographic SHA-256 verified binaries for `opengrep`, `gitleaks`, `trivy`, and `osv-scanner`.
  - Sets `chmod 0555` (read-only executable permissions).
- **Why We Used This:** Validating cryptographic hashes defined in `tools.lock.json` eliminates supply-chain binary poisoning during Docker image build.

#### Stage 3: Python Checkov Virtualenv (`AS checkov`)
- **Commands Used:**
  ```dockerfile
  RUN python3 -m venv /opt/checkov-venv
  RUN /opt/checkov-venv/bin/pip install --no-cache-dir checkov==3.3.29
  RUN printf '#!/bin/sh\nexec /opt/checkov-venv/bin/checkov "$@"\n' > /opt/checkov-bin/checkov && \
      chmod 0555 /opt/checkov-bin/checkov
  ```
- **Function of Each Command:**
  - Creates a dedicated virtualenv at `/opt/checkov-venv` and installs pinned `checkov==3.3.29`.
  - Creates a thin shell wrapper script at `/opt/checkov-bin/checkov` forwarding all CLI arguments to the virtualenv.
- **Why We Used This:** Checkov has over 200 Python dependencies (`bc-python-hcl2`, `dpath`, `networkx`, `schema`). Isolating Checkov in its own virtualenv prevents dependency version collisions with the FastAPI backend.

#### Stage 4: Python Backend Dependencies (`AS pybuilder`)
- **Commands Used:**
  ```dockerfile
  RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev
  RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
  ```
- **Function of Each Command:**
  - Installs temporary C compilers and headers (`build-essential`).
  - Compiles FastAPI, Uvicorn, SlowAPI, Pydantic, ReportLab, and WeasyPrint into the `/install` directory prefix.
- **Why We Used This:** Compiling wheels in a temporary stage guarantees that compilers (`gcc`, `make`, `g++`) are never present in the final production runtime image.

#### Stage 5: Production Backend Runtime (`AS runner`)
- **Commands Used:**
  ```dockerfile
  RUN apt-get install -y --no-install-recommends \
      curl ca-certificates git tini \
      libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libpangocairo-1.0-0 nodejs
  RUN groupadd -g 10001 secureship && useradd -u 10001 -g secureship -m -s /bin/sh securescan
  COPY --from=pybuilder /install /usr/local
  COPY --from=builder /out/cli /secureship
  RUN ln -s /secureship/dist/index.js /usr/local/bin/secureship
  COPY --from=tools /out/bin/ /opt/secureship/bin/
  COPY --from=checkov /opt/checkov-venv /opt/checkov-venv
  COPY --from=checkov /opt/checkov-bin/checkov /opt/secureship/bin/checkov
  RUN chown -R root:root /opt/secureship/bin && chmod 0555 /opt/secureship/bin && chmod 0555 /opt/secureship/bin/*
  COPY backend/app /app/app
  RUN chown -R securescan:secureship /home/securescan /tmp/securescan /app
  USER securescan:secureship
  ENTRYPOINT ["tini", "--"]
  CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
  ```

### 2.3 Container Security Hardening
1. **Rootless Execution (`UID 10001`):** The process runs as non-root user `securescan`. If a scanner has a zero-day vulnerability, the attacker cannot escalate to host root.
2. **Immutable Scanner Binaries:** `/opt/secureship/bin` is owned by `root:root` with permissions `0555` (read-only executable). The `securescan` user cannot overwrite or trojanize scanner binaries.
3. **Tini as PID 1:** When scanners spawn child processes, `tini` reaps zombie processes and propagates `SIGTERM` signals correctly on container shutdown.
4. **Environment PATH Configuration:**
   - `PATH="/opt/secureship/bin:${PATH}"`: SecureShip CLI scanner adapters discover all 5 scanner binaries on system PATH without hardcoded paths.
   - `SECURESHIP_CLI_PATH="/secureship/dist/index.js"`: Entry point for the CLI runner.

### 2.4 Docker Compose Service Orchestration (`docker-compose.yml`)
- **`backend` service:**
  - Resource limits: `cpus: "1.5"`, `memory: 6144M` (6 GB). Security scanners analyzing large AST graphs require substantial memory; these limits protect host stability while preventing OOM crashes.
  - Healthcheck: Probes `http://localhost:8000/api/health` every 10 seconds.
- **`frontend` service:**
  - Multi-stage build via `frontend/Dockerfile` (`node:22-alpine` builder + `nginx:alpine` runner).
  - Depends on `backend` with `condition: service_healthy`.
  - Reverse proxies `/api/*` to `http://backend:8000/api/*` with `client_max_body_size 650M;` and `proxy_read_timeout 600s;`.

---

## 3. BACKEND ENGINE DEEP DIVE: FILE-BY-FILE LOGIC & RATIONALE

### 3.1 `backend/app/main.py`
- **Primary Function:** ASGI application entry point configuring lifecycle, middleware, and route mounting.
- **Main Logic:**
  - **Lifespan Manager:** Uses `@asynccontextmanager` to execute `await queue.start()` on startup and `await queue.stop()` on shutdown.
  - **Rate Limiting:** Registers SlowAPI middleware and `_rate_limit_exceeded_handler`.
  - **CORS:** Allows dev origins and explicitly exposes `Content-Disposition` header so the browser can read exported filenames.
  - **Route Mounting:** Mounts `/api` routes via `api_router` and root health via `health_router`.
- **Why This Logic Was Used:** The lifespan manager guarantees graceful background worker shutdown. If Docker terminates the container (`SIGTERM`), in-flight scan processes are killed cleanly and temporary scratch directories in `/tmp` are unlinked.

### 3.2 `backend/app/config.py`
- **Primary Function:** Strongly typed application settings using Pydantic `BaseSettings`.
- **Main Logic:**
  - `SCAN_TIMEOUT_SECONDS = 600` (10-minute hard ceiling).
  - `MAX_CONCURRENCY = 1` (Single-worker queue serialization).
  - `MAX_UPLOAD_SIZE_BYTES = 600 * 1024 * 1024` (600 MB upload limit).
  - `MAX_EXTRACTED_BYTES = 1500 * 1024 * 1024` (1.5 GB uncompressed limit).
  - `MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024` (100 MB single file ceiling).
  - `MAX_COMPRESSION_RATIO = 100.0` (Zip-bomb defense threshold).
  - `MAX_FILE_COUNT = 30000` (Inode exhaustion ceiling).
- **Why This Logic Was Used:** Centralizing resource quotas in a validated settings model allows adjusting operational limits via environment variables without modifying application code.

### 3.3 `backend/app/routers/upload.py`
- **Primary Function:** Handles `.zip` archive upload, streaming chunk validation, rate limiting, and queue dispatch.
- **Main Logic:**
  - **IP Rate Limiting:** Enforces 10 uploads per hour per client IP via `@limiter.limit("10/hour")`.
  - **Extension Validation:** Rejects filenames not ending in `.zip` with HTTP 400.
  - **Streaming 64KB Chunk Ingestion & Magic Header Check:**
    - Streams file in chunks of `64 * 1024` bytes directly to a temporary file (`upload_<job_id>_.zip`).
    - Inspects the very first chunk for standard zip magic headers: `b"PK\x03\x04"`, `b"PK\x05\x06"`, `b"PK\x07\x08"`. If absent, immediately unlinks the temporary file and raises HTTP 400.
    - Tracks `total_uploaded`. If `total_uploaded > 600 MB`, immediately unlinks the file and raises HTTP 413.
  - **Queue Enqueue:** Dispatches job record to `ScanJobQueue` with a UUIDv4 `job_id`.
  - **Dual-Key Response:** Returns both `job_id` and `jobId`, `poll_url` and `pollUrl`.
- **Why This Logic Was Used:** Reading 600 MB into memory with `await file.read()` causes severe memory spikes ($O(N)$ memory), risking container OOM kills. Writing 64 KB chunks directly to disk provides constant $O(1)$ memory usage. Early magic-byte validation rejects disguised non-zip files on the very first chunk without reading the full payload.

### 3.4 `backend/app/routers/jobs.py`
- **Primary Function:** Polling endpoint for job progress and finished scan report retrieval.
- **Main Logic:**
  - `GET /api/jobs/{job_id}`: Returns job status (`queued`, `running`, `done`, `failed`), stage (`extracting`, `scanning`, `enriching`, `completed`), and progress (0-100%).
  - `GET /api/reports/{job_id}`:
    - Returns **HTTP 404** if `job_id` does not exist.
    - Returns **HTTP 409 Conflict** if the scan is still running or queued.
    - Returns **HTTP 422 Unprocessable Content** if the scan failed.
    - Returns **HTTP 200 OK** with normalized report payload when complete.
- **Why This Logic Was Used:** Strict HTTP status semantics (`409` for pending, `422` for failure) eliminate race conditions in client polling loops, preventing the UI from misinterpreting a slow scan as a missing report.

### 3.5 `backend/app/routers/reports.py`
- **Primary Function:** Dispatches report exports into 4 formats: JSON, SARIF 2.1.0, HTML, and PDF.
- **Main Logic:**
  - Validates `format` query against `SUPPORTED_FORMATS` (`json`, `sarif`, `html`, `pdf`).
  - Calls `export_report(job.report, export_format)`.
  - Attaches `Content-Disposition: attachment; filename="securescan-report-<job_id>.<ext>"`.
- **Why This Logic Was Used:** Direct streaming binary/text responses allow developers to pipe outputs straight into automated CI/CD steps (e.g. uploading SARIF to GitHub Code Scanning).

### 3.6 `backend/app/routers/health.py`
- **Primary Function:** Readiness and liveness probe for Docker healthchecks.
- **Main Logic:**
  - Probes system PATH dynamically via `shutil.which()` for `opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`.
  - Returns queue stats: `queue_depth`, `is_processing`, `active_job_id`.
- **Why This Logic Was Used:** Docker Compose uses this probe (`condition: service_healthy`) to ensure the backend is fully initialized before Nginx routes user traffic.

### 3.7 `backend/app/core/safe_extract.py`
- **Primary Function:** Enterprise-grade archive decompression with 5 defense layers against malicious zip payloads.
- **The 5 Defense Layers:**
  1. **Path Traversal & Zip-Slip Defense:**
     - Rejects entries with leading slashes (`/`), Windows drive prefixes (`C:`), or directory traversal components (`..`).
     - Rejects Windows reserved device names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-COM9`, `LPT1-LPT9`.
     - Validates destination path resolution via `dest_path.is_relative_to(target_dir.resolve())`.
  2. **Symlink & Special File Defense:**
     - Inspects `ZipInfo.external_attr`. Rejects explicit `0xA1ED` attribute (standard Unix symlink mode `0o120755`) and POSIX `S_IFLNK` bit (`0o120000`).
     - Blocks FIFOs, character devices, block devices, and sockets.
  3. **Zip-Bomb Compression Ratio Defense:**
     - Rejects entries where uncompressed size divided by compressed size exceeds `100.0`.
     - Performs ratio check **upfront** on zip headers, and **streaming** during decompression to defend against forged headers.
  4. **Strict Quota Enforcement:**
     - Max entries: 30,000 files. Max single file: 100 MB. Max total decompressed size: 1.5 GB.
  5. **Atomic Rollback & Cleanup:**
     - `_cleanup_partial_extraction(target_dir)` recursively deletes all extracted files if any exception is encountered during extraction.
- **Why This Logic Was Used:** Untrusted archive extraction is a primary vector for remote code execution (Zip-Slip overwriting system libraries), host disk exhaustion (Zip-bombs), and arbitrary file read (Symlinks targeting `/etc/passwd`). `safe_extract.py` neutralizes these attacks before scanners touch the source code.

### 3.8 `backend/app/core/queue.py`
- **Primary Function:** In-memory asynchronous job queue enforcing a strict concurrency ceiling of 1.
- **Main Logic:**
  - `ScanJobQueue` backed by `asyncio.Queue(maxsize=100)`.
  - Single worker loop `_worker_loop` runs one job at a time.
  - **4-Stage Execution Pipeline:**
    1. `EXTRACTING` (10%): Creates temporary scratch dir `/tmp/securescan_job_<id>` and runs `safe_extract()`.
    2. `SCANNING` (30% -> 80%): Runs `run_secureship_cli(scratch_dir)` with extra arguments `["--gate2", "annotate", "--no-color", "--offline", "--timeout", "120000"]`.
    3. `ENRICHING` (90%): Runs `enrich_report_with_snippets(raw_report, scratch_dir)`.
    4. `COMPLETED` (100%): Sets status `done` and stores report in memory.
  - **Guaranteed Cleanup in `finally`:** Recursively purges the temporary extraction scratch directory and unlinks the uploaded temporary `.zip` file.
- **Why This Logic Was Used:** Multi-engine security scanning (AST compilation, dependency graph resolution) is CPU- and memory-intensive. Running multiple concurrent scans inside a container limited to 1.5 CPUs leads to process thrashing, scan timeouts, and OOM terminations. Enforcing `MAX_CONCURRENCY=1` guarantees predictable scan runtimes and system stability.

### 3.9 `backend/app/core/runner.py`
- **Primary Function:** Subprocess runner executing the SecureShip CLI executable without shell invocation.
- **Main Logic:**
  - **CLI Script Discovery:** Resolves Node executable and CLI candidate paths (`/secureship/dist/index.js`, etc.).
  - **Subprocess Execution without Shell:**
    - Formulates command list: `[node_bin, cli_script, "scan", str(target), "--json", "--gate2", "annotate", "--no-color", "--offline", "--timeout", "120000"]`.
    - Spawns subprocess using `asyncio.create_subprocess_exec(*cmd_args)` with `shell=False`.
  - **Timeout & Process Tree Kill:** Wraps `communicate()` in `asyncio.wait_for()`. On timeout, calls `process.kill()` to terminate runaway scanner processes.
  - **Exit Codes 0 & 1 as Successful Scans:** Treats exit code 0 (clean) and exit code 1 (findings detected) as successful, parsing stdout JSON. Only codes $>1$ represent crashes.
  - **Resilient JSON Slice Fallback:** If Node.js deprecation notices or engine logs precede or succeed JSON output, slices between the first `{` and last `}` before decoding.
- **Why This Logic Was Used:** `shell=False` prevents command injection vulnerabilities. Handling exit code 1 correctly prevents vulnerability detections from being falsely reported as internal server errors.

### 3.10 `backend/app/core/context_extractor.py`
- **Primary Function:** Slices source code surrounding vulnerable lines (±5 lines) and enriches findings with CWE and OWASP Top 10 taxonomies.
- **Main Logic:**
  - `extract_code_snippet`:
    - Path traversal defense: Verifies `resolved_file.is_relative_to(resolved_base)`.
    - Multi-encoding safe reading: Reads UTF-8 with Latin-1 fallback.
    - Binary file defense: Checks for `\x00` in first 4096 bytes and rejects binaries.
    - Boundary clamping: Clamps context window to `max(1, start_line - 5)` and `min(total_lines, end_line + 5)`.
    - Tags lines where `is_target = True` if within `[start_line, end_line]`.
  - `enrich_report_with_snippets`:
    - Normalizes CWE identifiers into canonical format (e.g. `CWE-79`, `CWE-89`).
    - Maps findings to OWASP Top 10 (2021) categories using authoritative mapping, keyword regex, and scanner category heuristics.
    - Normalizes reachability verdicts to `REACHABLE`, `UNREACHABLE`, or `UNKNOWN`.
- **Why This Logic Was Used:** Security scanners typically report raw line numbers without source code context. Extracting ±5 lines of context on the backend allows the frontend UI to display vulnerable code directly without exposing the entire archive to the browser.

### 3.11 `backend/app/models/report.py` and `job.py`
- **Primary Function:** Strongly typed Pydantic v2 data models defining scan reports, findings, locations, and job records.
- **Main Logic:**
  - `BaseSchema`: Configured with `alias_generator=to_camel` and `populate_by_name=True` for seamless camelCase serialization.
  - `Severity` Enum: Implements comparison operators (`>`, `>=`, `<`, `<=`) using integer ranks: `CRITICAL (5) > HIGH (4) > MEDIUM (3) > LOW (2) > INFO (1)`.
  - `CWE_TO_OWASP_INT` Dictionary: Authoritative mapping table translating over 100 MITRE CWE numbers directly to OWASP Top 10 (2021) categories.

### 3.12 `backend/app/exporters/`
- **Primary Function:** Serializes scan reports into compliance formats:
  - `json_exporter.py`: Normalizes report fields and injects bidirectional properties (`total_findings` and `totalFindings`, `by_severity` and `severityCounts`, `snippet_context` and `snippetContext`).
  - `sarif_exporter.py`: Formats reports to OASIS SARIF v2.1.0 specification. Maps severities to SARIF levels (`error`, `warning`, `note`) and enforces Section 3.30.2 column boundary constraints (`endColumn >= startColumn` when on the same line).
  - `html_exporter.py`: Generates an air-gapped, standalone single-file HTML report with embedded CSS styling and code blocks.
  - `pdf_exporter.py`: Generates binary PDF reports. Prefers WeasyPrint HTML-to-PDF rendering, and falls back to ReportLab when native graphics libraries are unavailable.

---

## 4. FRONTEND UI ARCHITECTURE & USER EXPERIENCE

The frontend is built with React 18, Vite, Tailwind CSS, Lucide icons, and Recharts.

### 4.1 Component Tree & Page Flow
```
                    +------------------------------------+
                    |        App.tsx (Main Shell)        |
                    |     Navbar + Google Dark Theme     |
                    +-----------------+------------------+
                                      |
                     +----------------+----------------+
                     v                                 v
          +--------------------+             +--------------------+
          |    ScanPage.tsx    |             |   ReportPage.tsx   |
          | - Upload Zone      |             | - Fetch & Poll     |
          | - Orbital Spinner  |             | - Header & Status  |
          +----------+---------+             +---------+----------+
                     |                                 |
                     v                                 v
          +--------------------+             +------------------------------------+
          |   UploadZone.tsx   |             | Components:                        |
          | - Drag & Drop      |             |  +-- SummaryDashboard (Charts)    |
          | - 600MB XHR Stream |             |  +-- ExportButtons (Downloads)     |
          | - Real-time % Bar  |             |  +-- FindingsTable (Filters/Sort)  |
          +--------------------+             |  +-- CodeViewerDrawer (+/-5 Lines) |
                                             +------------------------------------+
```

### 4.2 `ScanPage.tsx` & `UploadZone.tsx`
1. Validates that the file has a `.zip` extension and is $\le$ 600 MB.
2. Uses `XMLHttpRequest` with `xhr.upload.onprogress` to stream the archive to `POST /api/scan`, tracking progress in real time (0% -> 90% -> 100%).
3. Upon receiving `{ "job_id": "...", "status": "queued" }`, transitions `ScanPage.tsx` into Scanning View.
4. Renders an orbital dual-ring spinning animation with 3 stage indicators:
   - `1. Safe Extract`
   - `2. Engine Scan`
   - `3. Snippets & OWASP`
5. Runs a 2-second interval polling loop against `GET /api/jobs/{job_id}`. Once the status changes to `'done'`, automatically navigates to `/report/:job_id`.

### 4.3 `ReportPage.tsx` & Interactive Components
- **`SummaryDashboard.tsx`:**
  - KPI Cards: Total Findings, Critical, High, Medium, Files Affected, Scanners Run, Scan Duration.
  - Severity Donut Chart: Recharts `PieChart` colored by severity.
  - Scanner Engine Bar Chart: Recharts `BarChart` displaying finding counts per engine.
  - OWASP Top 10 Breakdown: Interactive filter buttons that dynamically filter the findings table below.
- **`FindingsTable.tsx`:** Real-time search across rule ID, title, description, file path, and CWE tags. Multi-select filters for Severity, Category, Scanner Name, and Reachability.
- **`CodeViewerDrawer.tsx`:** Segmented file breadcrumb (`src / controllers / auth.py : 42`), ±5 lines of extracted code around the vulnerability with red accent highlight (`border-l-4 border-[#ea4335]`), target pointer (`>>`), reachability status, and clickable hyperlinks to MITRE CWE definitions.
- **`ExportButtons.tsx`:** Single-click streaming downloads for JSON, OASIS SARIF 2.1.0, Single-File HTML, and Executive PDF.

---

## 5. COMPLETE END-TO-END EXECUTION FLOW

```
[STEP 1: USER UPLOADS ARCHIVE]
User drops 'project.zip' (up to 600 MB) into frontend UploadZone
Frontend checks file extension (.zip) and size (<= 600 MB)
XHR sends multipart/form-data to POST /api/scan with real-time progress events
       |
       v
[STEP 2: REVERSE PROXY & BACKEND INGESTION]
Nginx receives request on port 3000, proxies /api/ to http://backend:8000/api/
Backend upload.py checks SlowAPI rate limit (10 uploads/hr/IP)
Backend streams 64KB chunks to temporary file: /tmp/upload_<uuid>.zip
Validates PK magic bytes (b"PK\x03\x04") in the first chunk
Enqueues job to ScanJobQueue; returns { "job_id": "c1f8...", "status": "queued" }
       |
       v
[STEP 3: FRONTEND POLLING TRANSITION]
Frontend transitions to Scanning View with Antigravity orbital rings
Frontend begins polling GET /api/jobs/c1f8... every 2 seconds
       |
       v
[STEP 4: BACKGROUND WORKER EXECUTION (concurrency=1)]
ScanJobQueue single worker pulls job 'c1f8...' from queue
Sets stage = EXTRACTING, progress = 10%
Creates isolated scratch directory: /tmp/securescan_job_c1f8.../
safe_extract.py validates zip against Traversal, Symlinks, Bombs, and Quotas
Decompresses project files into scratch directory
       |
       v
[STEP 5: SECURESHIP CLI INVOCATION IN DOCKER]
Worker sets stage = SCANNING, progress = 30%
runner.py executes without shell:
  node /secureship/dist/index.js scan /tmp/securescan_job_c1f8... --json --gate2 annotate --no-color --offline --timeout 120000
Inside Docker, SecureShip CLI launches 5 pre-baked engines from /opt/secureship/bin:
  1. Opengrep: SAST pattern matching against custom and standard rules
  2. Gitleaks: Scans files and commits for credentials and API tokens
  3. Trivy: Checks dependencies and container configs against CVE databases
  4. OSV-Scanner: Checks open-source packages against advisory databases
  5. Checkov: Scans Dockerfiles, Terraform, and K8s manifests for IaC flaws
CLI normalizes findings, runs AST reachability, and prints final JSON to stdout
CLI exits with code 0 (clean) or code 1 (findings detected)
runner.py captures stdout and parses ScanReport JSON
       |
       v
[STEP 6: CONTEXT ENRICHMENT & CLEANUP]
Worker sets stage = ENRICHING, progress = 90%
context_extractor.py iterates through findings:
  - Resolves file path safely inside scratch directory
  - Slices +/-5 lines of code context around vulnerability
  - Marks target line (is_target = True)
  - Maps CWE ID to OWASP Top 10 (2021) category
  - Normalizes reachability verdict (REACHABLE / UNREACHABLE / UNKNOWN)
Worker stores enriched report in memory, sets status = DONE, progress = 100%
Worker finally block cleans up:
  - Recursively deletes /tmp/securescan_job_c1f8.../ scratch directory
  - Unlinks uploaded /tmp/upload_c1f8....zip
       |
       v
[STEP 7: FRONTEND COMPLETION & DISPLAY]
Frontend polling receives { "status": "done" }
Frontend navigates to /report/c1f8...
Frontend calls GET /api/reports/c1f8... and receives 200 OK with full report
UI renders Summary Dashboard, Severity Donut, Scanner Bars, and Findings Table
Clicking finding opens CodeViewerDrawer with +/-5 lines of highlighted code
Clicking export button downloads JSON, SARIF, HTML, or PDF
```

---

## 6. EMPIRICAL VERIFICATION & TEST EVIDENCE

The entire backend test suite was executed to verify the code paths, error handling, and security defenses:

```powershell
Set-Location "C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"
$env:PYTHONPATH="backend;."

# 1. Archive Extraction & Defense Tests
python -m pytest backend/tests/test_extraction.py -v
# Output: 32 passed in 0.60s

# 2. Core API, Queue, Context Extractor, Models, Runner, & Exporters Tests
python -m pytest backend/tests/test_api.py backend/tests/test_queue.py backend/tests/test_context.py backend/tests/test_models.py backend/tests/test_runner.py backend/tests/test_exporters.py -p asyncio -v
# Output: 76 passed, 3 warnings in 2.59s

# 3. Adversarial Security, Concurrency, and Scalability Tests
python -m pytest backend/tests/test_adversarial_m1.py backend/tests/test_adversarial_m2.py backend/tests/test_adversarial_exporters.py -p asyncio -v
# Output: 121 passed, 6 warnings in 11.16s
```

**Total Test Results:** **229 passed out of 229 tests (100% pass rate).**

---

### Summary Checklist of All Requirements:
- [x] Docker Multi-Stage Build explained with exact commands and functions (`Dockerfile.backend`)
- [x] Why each Docker command and permission was used (Rootless UID 10001, immutable 0555 binaries, Tini PID 1)
- [x] Backend script file-by-file logic explained (`main.py`, `upload.py`, `queue.py`, `runner.py`, `safe_extract.py`, `context_extractor.py`, `reports.py`, `exporters/`)
- [x] Why each backend logic was used (64KB streaming, magic bytes, Zip-slip / bomb defense, exit code 1 handling, single-worker concurrency)
- [x] Complete End-to-End action lifecycle from frontend upload to Docker CLI execution to UI report and export
- [x] Zero code modifications performed (Strictly read-only investigation and documentation)
